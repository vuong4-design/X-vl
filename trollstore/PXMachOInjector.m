// PXMachOInjector.m - minimal LC_LOAD_DYLIB insertion for prepared copies.

#import "PXMachOInjector.h"

#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stdarg.h>
#include <string.h>

NSString * const PXMachOInjectorErrorDomain = @"PXMachOInjectorErrorDomain";

static NSError *PXMIError(NSInteger code, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    return [NSError errorWithDomain:PXMachOInjectorErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"Mach-O injection error"}];
}

static uint32_t PXSwap32(uint32_t v, BOOL swap) {
    return swap ? OSSwapInt32(v) : v;
}

static BOOL PXRangeOK(NSUInteger length, uint64_t offset, uint64_t size) {
    return offset <= length && size <= length && offset + size <= length;
}

static BOOL PXMIHasDylibCommand(uint8_t *base, NSUInteger fileLength, uint64_t sliceOffset, BOOL swap, NSString *dylibPath, NSError **error) {
    struct mach_header_64 *mh = (struct mach_header_64 *)(base + sliceOffset);
    uint32_t ncmds = PXSwap32(mh->ncmds, swap);
    uint32_t sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    uint64_t commandsOffset = sliceOffset + sizeof(struct mach_header_64);
    if (!PXRangeOK(fileLength, commandsOffset, sizeofcmds)) {
        if (error) *error = PXMIError(10, @"Malformed load command range");
        return NO;
    }
    uint64_t cursor = commandsOffset;
    NSData *wanted = [dylibPath dataUsingEncoding:NSUTF8StringEncoding];
    for (uint32_t i = 0; i < ncmds; i++) {
        if (!PXRangeOK(fileLength, cursor, sizeof(struct load_command))) break;
        struct load_command *lc = (struct load_command *)(base + cursor);
        uint32_t cmd = PXSwap32(lc->cmd, swap);
        uint32_t cmdsize = PXSwap32(lc->cmdsize, swap);
        if (cmdsize < sizeof(struct load_command) || !PXRangeOK(fileLength, cursor, cmdsize)) break;
        if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB || cmd == LC_REEXPORT_DYLIB) {
            struct dylib_command *dc = (struct dylib_command *)lc;
            uint32_t nameOffset = PXSwap32(dc->dylib.name.offset, swap);
            if (nameOffset < cmdsize) {
                char *name = (char *)lc + nameOffset;
                NSUInteger maxLen = cmdsize - nameOffset;
                NSString *existing = [[NSString alloc] initWithBytes:name length:strnlen(name, maxLen) encoding:NSUTF8StringEncoding];
                if ([existing isEqualToString:dylibPath]) return YES;
            }
        }
        cursor += cmdsize;
    }
    (void)wanted;
    return NO;
}

static BOOL PXMIInsertIntoThin64(NSMutableData *data, uint64_t sliceOffset, uint64_t sliceSize, BOOL swap, NSString *dylibPath, NSError **error) {
    uint8_t *base = data.mutableBytes;
    NSUInteger fileLength = data.length;
    if (!PXRangeOK(fileLength, sliceOffset, sizeof(struct mach_header_64))) {
        if (error) *error = PXMIError(20, @"Thin slice header out of range");
        return NO;
    }
    if (PXMIHasDylibCommand(base, fileLength, sliceOffset, swap, dylibPath, NULL)) {
        return YES;
    }

    struct mach_header_64 *mh = (struct mach_header_64 *)(base + sliceOffset);
    uint32_t ncmds = PXSwap32(mh->ncmds, swap);
    uint32_t sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    uint64_t commandsOffset = sliceOffset + sizeof(struct mach_header_64);
    uint64_t commandsEnd = commandsOffset + sizeofcmds;
    if (!PXRangeOK(fileLength, commandsOffset, sizeofcmds)) {
        if (error) *error = PXMIError(21, @"Load commands out of range");
        return NO;
    }

    NSData *pathData = [dylibPath dataUsingEncoding:NSUTF8StringEncoding];
    uint32_t nameOffset = sizeof(struct dylib_command);
    uint32_t rawSize = nameOffset + (uint32_t)pathData.length + 1;
    uint32_t cmdSize = (rawSize + 7) & ~7;

    uint64_t paddingEnd = sliceOffset + sliceSize;
    uint64_t scanLimit = MIN((uint64_t)fileLength, paddingEnd);
    uint64_t available = 0;
    for (uint64_t p = commandsEnd; p < scanLimit; p++) {
        if (base[p] != 0) break;
        available++;
    }
    if (available < cmdSize) {
        if (error) *error = PXMIError(22, @"Not enough Mach-O header padding: need %u, available %llu", cmdSize, available);
        return NO;
    }

    struct dylib_command dc;
    memset(&dc, 0, sizeof(dc));
    dc.cmd = PXSwap32(LC_LOAD_DYLIB, swap);
    dc.cmdsize = PXSwap32(cmdSize, swap);
    dc.dylib.name.offset = PXSwap32(nameOffset, swap);
    dc.dylib.timestamp = 0;
    dc.dylib.current_version = 0;
    dc.dylib.compatibility_version = 0;

    memset(base + commandsEnd, 0, cmdSize);
    memcpy(base + commandsEnd, &dc, sizeof(dc));
    memcpy(base + commandsEnd + nameOffset, pathData.bytes, pathData.length);
    base[commandsEnd + nameOffset + pathData.length] = 0;

    mh->ncmds = PXSwap32(ncmds + 1, swap);
    mh->sizeofcmds = PXSwap32(sizeofcmds + cmdSize, swap);
    return YES;
}

static BOOL PXMIInsertIntoSlice(NSMutableData *data, uint64_t offset, uint64_t size, NSString *dylibPath, NSError **error) {
    if (!PXRangeOK(data.length, offset, sizeof(uint32_t))) {
        if (error) *error = PXMIError(30, @"Slice out of range");
        return NO;
    }
    uint32_t magic = *(uint32_t *)((uint8_t *)data.mutableBytes + offset);
    if (magic == MH_MAGIC_64) return PXMIInsertIntoThin64(data, offset, size, NO, dylibPath, error);
    if (magic == MH_CIGAM_64) return PXMIInsertIntoThin64(data, offset, size, YES, dylibPath, error);
    if (error) *error = PXMIError(31, @"Unsupported non-64-bit Mach-O slice magic=0x%x", magic);
    return NO;
}

static BOOL PXMIHasDylibCommandInSlice(NSData *data, uint64_t offset, NSString *dylibPath, BOOL *checked, NSError **error) {
    if (!PXRangeOK(data.length, offset, sizeof(uint32_t))) {
        if (error) *error = PXMIError(40, @"Slice out of range");
        return NO;
    }
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)(base + offset);
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        if (checked) *checked = YES;
        return PXMIHasDylibCommand(base, data.length, offset, magic == MH_CIGAM_64, dylibPath, error);
    }
    return NO;
}

static NSDictionary<NSString *, id> *PXMICodeSignatureSummaryForSlice(NSData *data, uint64_t offset, uint64_t sliceSize, NSError **error) {
    if (!PXRangeOK(data.length, offset, sizeof(uint32_t))) {
        if (error) *error = PXMIError(60, @"Slice out of range");
        return nil;
    }
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)(base + offset);
    BOOL is64 = NO;
    BOOL swap = NO;
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64 = YES;
        swap = (magic == MH_CIGAM_64);
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64 = NO;
        swap = (magic == MH_CIGAM);
    } else {
        return @{@"supported": @"NO", @"error": [NSString stringWithFormat:@"Unsupported Mach-O slice magic=0x%x", magic]};
    }

    uint64_t headerSize = is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    if (!PXRangeOK(data.length, offset, headerSize)) {
        if (error) *error = PXMIError(61, @"Mach-O header out of range");
        return nil;
    }

    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    if (is64) {
        struct mach_header_64 *mh = (struct mach_header_64 *)(base + offset);
        ncmds = PXSwap32(mh->ncmds, swap);
        sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    } else {
        struct mach_header *mh = (struct mach_header *)(base + offset);
        ncmds = PXSwap32(mh->ncmds, swap);
        sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    }

    uint64_t commandsOffset = offset + headerSize;
    if (!PXRangeOK(data.length, commandsOffset, sizeofcmds)) {
        if (error) *error = PXMIError(62, @"Load commands out of range");
        return nil;
    }

    NSMutableDictionary *summary = [@{
        @"supported": @"YES",
        @"is64": is64 ? @"YES" : @"NO",
        @"sliceOffset": @(offset),
        @"sliceSize": @(sliceSize),
        @"ncmds": @(ncmds),
        @"sizeofcmds": @(sizeofcmds),
        @"hasCodeSignature": @"NO",
    } mutableCopy];

    uint64_t cursor = commandsOffset;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (!PXRangeOK(data.length, cursor, sizeof(struct load_command))) break;
        struct load_command *lc = (struct load_command *)(base + cursor);
        uint32_t cmd = PXSwap32(lc->cmd, swap);
        uint32_t cmdsize = PXSwap32(lc->cmdsize, swap);
        if (cmdsize < sizeof(struct load_command) || !PXRangeOK(data.length, cursor, cmdsize)) break;
        if (cmd == LC_CODE_SIGNATURE) {
            if (cmdsize >= sizeof(struct linkedit_data_command)) {
                struct linkedit_data_command *cs = (struct linkedit_data_command *)lc;
                uint32_t dataoff = PXSwap32(cs->dataoff, swap);
                uint32_t datasize = PXSwap32(cs->datasize, swap);
                uint64_t end = (uint64_t)dataoff + datasize;
                summary[@"hasCodeSignature"] = @"YES";
                summary[@"codeSignatureDataOffset"] = @(dataoff);
                summary[@"codeSignatureDataSize"] = @(datasize);
                summary[@"codeSignatureEnd"] = @(end);
                summary[@"codeSignatureRangeOK"] = PXRangeOK(data.length, offset + dataoff, datasize) ? @"YES" : @"NO";
                summary[@"codeSignatureAtSliceEnd"] = (sliceSize > 0 && end == sliceSize) ? @"YES" : @"NO";
                summary[@"headerMutationInvalidatesSignature"] = @"LIKELY";
            }
            break;
        }
        cursor += cmdsize;
    }
    return summary;
}

static NSDictionary<NSString *, id> *PXMIEncryptionSummaryForSlice(NSData *data, uint64_t offset, uint64_t sliceSize, NSError **error) {
    if (!PXRangeOK(data.length, offset, sizeof(uint32_t))) {
        if (error) *error = PXMIError(80, @"Slice out of range");
        return nil;
    }
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)(base + offset);
    BOOL is64 = NO;
    BOOL swap = NO;
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64 = YES;
        swap = (magic == MH_CIGAM_64);
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64 = NO;
        swap = (magic == MH_CIGAM);
    } else {
        return @{@"supported": @"NO", @"error": [NSString stringWithFormat:@"Unsupported Mach-O slice magic=0x%x", magic]};
    }

    uint64_t headerSize = is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    if (!PXRangeOK(data.length, offset, headerSize)) {
        if (error) *error = PXMIError(81, @"Mach-O header out of range");
        return nil;
    }
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    if (is64) {
        struct mach_header_64 *mh = (struct mach_header_64 *)(base + offset);
        ncmds = PXSwap32(mh->ncmds, swap);
        sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    } else {
        struct mach_header *mh = (struct mach_header *)(base + offset);
        ncmds = PXSwap32(mh->ncmds, swap);
        sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    }
    uint64_t commandsOffset = offset + headerSize;
    if (!PXRangeOK(data.length, commandsOffset, sizeofcmds)) {
        if (error) *error = PXMIError(82, @"Load commands out of range");
        return nil;
    }

    NSMutableDictionary *summary = [@{
        @"supported": @"YES",
        @"is64": is64 ? @"YES" : @"NO",
        @"sliceOffset": @(offset),
        @"sliceSize": @(sliceSize),
        @"hasEncryptionInfo": @"NO",
        @"cryptid": @0,
        @"encrypted": @"NO",
    } mutableCopy];
    uint64_t cursor = commandsOffset;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (!PXRangeOK(data.length, cursor, sizeof(struct load_command))) break;
        struct load_command *lc = (struct load_command *)(base + cursor);
        uint32_t cmd = PXSwap32(lc->cmd, swap);
        uint32_t cmdsize = PXSwap32(lc->cmdsize, swap);
        if (cmdsize < sizeof(struct load_command) || !PXRangeOK(data.length, cursor, cmdsize)) break;
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            if (cmdsize >= sizeof(struct encryption_info_command)) {
                struct encryption_info_command *ec = (struct encryption_info_command *)lc;
                uint32_t cryptoff = PXSwap32(ec->cryptoff, swap);
                uint32_t cryptsize = PXSwap32(ec->cryptsize, swap);
                uint32_t cryptid = PXSwap32(ec->cryptid, swap);
                summary[@"hasEncryptionInfo"] = @"YES";
                summary[@"cryptoff"] = @(cryptoff);
                summary[@"cryptsize"] = @(cryptsize);
                summary[@"cryptid"] = @(cryptid);
                summary[@"encrypted"] = cryptid != 0 ? @"YES" : @"NO";
            }
            break;
        }
        cursor += cmdsize;
    }
    return summary;
}

static NSDictionary<NSString *, id> *PXMILoadCommandSummaryForSlice(NSData *data, uint64_t offset, uint64_t sliceSize, NSError **error) {
    if (!PXRangeOK(data.length, offset, sizeof(uint32_t))) {
        if (error) *error = PXMIError(100, @"Slice out of range");
        return nil;
    }
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)(base + offset);
    BOOL is64 = NO;
    BOOL swap = NO;
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64 = YES;
        swap = (magic == MH_CIGAM_64);
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64 = NO;
        swap = (magic == MH_CIGAM);
    } else {
        return @{@"supported": @"NO", @"error": [NSString stringWithFormat:@"Unsupported Mach-O slice magic=0x%x", magic]};
    }

    uint64_t headerSize = is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    if (!PXRangeOK(data.length, offset, headerSize)) {
        if (error) *error = PXMIError(101, @"Mach-O header out of range");
        return nil;
    }
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    if (is64) {
        struct mach_header_64 *mh = (struct mach_header_64 *)(base + offset);
        ncmds = PXSwap32(mh->ncmds, swap);
        sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    } else {
        struct mach_header *mh = (struct mach_header *)(base + offset);
        ncmds = PXSwap32(mh->ncmds, swap);
        sizeofcmds = PXSwap32(mh->sizeofcmds, swap);
    }

    uint64_t commandsOffset = offset + headerSize;
    if (!PXRangeOK(data.length, commandsOffset, sizeofcmds)) {
        if (error) *error = PXMIError(102, @"Load commands out of range");
        return nil;
    }

    NSMutableArray<NSString *> *dylibs = [NSMutableArray array];
    NSMutableArray<NSString *> *rpaths = [NSMutableArray array];
    NSMutableArray<NSDictionary<NSString *, id> *> *loadCommands = [NSMutableArray array];
    uint64_t cursor = commandsOffset;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (!PXRangeOK(data.length, cursor, sizeof(struct load_command))) break;
        struct load_command *lc = (struct load_command *)(base + cursor);
        uint32_t cmd = PXSwap32(lc->cmd, swap);
        uint32_t cmdsize = PXSwap32(lc->cmdsize, swap);
        if (cmdsize < sizeof(struct load_command) || !PXRangeOK(data.length, cursor, cmdsize)) break;
        if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB || cmd == LC_REEXPORT_DYLIB) {
            struct dylib_command *dc = (struct dylib_command *)lc;
            uint32_t nameOffset = PXSwap32(dc->dylib.name.offset, swap);
            if (nameOffset < cmdsize) {
                char *name = (char *)lc + nameOffset;
                NSUInteger maxLen = cmdsize - nameOffset;
                NSString *s = [[NSString alloc] initWithBytes:name length:strnlen(name, maxLen) encoding:NSUTF8StringEncoding];
                if (s.length) {
                    [dylibs addObject:s];
                    NSString *cmdName = @"LC_LOAD_DYLIB";
                    if (cmd == LC_LOAD_WEAK_DYLIB) cmdName = @"LC_LOAD_WEAK_DYLIB";
                    else if (cmd == LC_LOAD_UPWARD_DYLIB) cmdName = @"LC_LOAD_UPWARD_DYLIB";
                    else if (cmd == LC_REEXPORT_DYLIB) cmdName = @"LC_REEXPORT_DYLIB";
                    [loadCommands addObject:@{
                        @"name": s,
                        @"cmd": @(cmd),
                        @"cmdName": cmdName,
                        @"weak": (cmd == LC_LOAD_WEAK_DYLIB) ? @"YES" : @"NO",
                    }];
                }
            }
        } else if (cmd == LC_RPATH) {
            struct rpath_command *rc = (struct rpath_command *)lc;
            uint32_t pathOffset = PXSwap32(rc->path.offset, swap);
            if (pathOffset < cmdsize) {
                char *name = (char *)lc + pathOffset;
                NSUInteger maxLen = cmdsize - pathOffset;
                NSString *s = [[NSString alloc] initWithBytes:name length:strnlen(name, maxLen) encoding:NSUTF8StringEncoding];
                if (s.length) [rpaths addObject:s];
            }
        }
        cursor += cmdsize;
    }
    return @{
        @"supported": @"YES",
        @"is64": is64 ? @"YES" : @"NO",
        @"sliceOffset": @(offset),
        @"sliceSize": @(sliceSize),
        @"ncmds": @(ncmds),
        @"sizeofcmds": @(sizeofcmds),
        @"loadedDylibs": dylibs,
        @"loadCommands": loadCommands,
        @"rpaths": rpaths,
    };
}

@implementation PXMachOInjector

+ (BOOL)insertDylibLoadCommand:(NSString *)dylibLoadPath
               intoMachOAtPath:(NSString *)path
                          error:(NSError **)error {
    if (!dylibLoadPath.length || !path.length) {
        if (error) *error = PXMIError(1, @"Missing dylib path or Mach-O path");
        return NO;
    }
    NSMutableData *data = [NSMutableData dataWithContentsOfFile:path];
    if (!data.length) {
        if (error) *error = PXMIError(2, @"Failed to read Mach-O: %@", path);
        return NO;
    }
    uint8_t *base = data.mutableBytes;
    uint32_t magic = *(uint32_t *)base;
    BOOL ok = NO;
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        BOOL swap = (magic == FAT_CIGAM);
        struct fat_header *fh = (struct fat_header *)base;
        uint32_t nfat = PXSwap32(fh->nfat_arch, swap);
        if (!PXRangeOK(data.length, sizeof(struct fat_header), (uint64_t)nfat * sizeof(struct fat_arch))) {
            if (error) *error = PXMIError(3, @"Malformed fat header");
            return NO;
        }
        ok = YES;
        struct fat_arch *arch = (struct fat_arch *)(base + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint32_t off = PXSwap32(arch[i].offset, swap);
            uint32_t size = PXSwap32(arch[i].size, swap);
            NSError *sliceErr = nil;
            if (!PXMIInsertIntoSlice(data, off, size, dylibLoadPath, &sliceErr)) {
                ok = NO;
                if (error) *error = sliceErr;
                break;
            }
        }
    } else {
        ok = PXMIInsertIntoSlice(data, 0, data.length, dylibLoadPath, error);
    }
    if (!ok) return NO;
    if (![data writeToFile:path atomically:YES]) {
        if (error) *error = PXMIError(4, @"Failed to write patched Mach-O: %@", path);
        return NO;
    }
    return YES;
}

+ (BOOL)hasDylibLoadCommand:(NSString *)dylibLoadPath
              inMachOAtPath:(NSString *)path
                       error:(NSError **)error {
    if (!dylibLoadPath.length || !path.length) {
        if (error) *error = PXMIError(50, @"Missing dylib path or Mach-O path");
        return NO;
    }
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) {
        if (error) *error = PXMIError(51, @"Failed to read Mach-O: %@", path);
        return NO;
    }
    if (!PXRangeOK(data.length, 0, sizeof(uint32_t))) {
        if (error) *error = PXMIError(52, @"Mach-O too small: %@", path);
        return NO;
    }
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)base;
    BOOL checkedAny = NO;
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        BOOL swap = (magic == FAT_CIGAM);
        struct fat_header *fh = (struct fat_header *)base;
        uint32_t nfat = PXSwap32(fh->nfat_arch, swap);
        if (!PXRangeOK(data.length, sizeof(struct fat_header), (uint64_t)nfat * sizeof(struct fat_arch))) {
            if (error) *error = PXMIError(53, @"Malformed fat header");
            return NO;
        }
        struct fat_arch *arch = (struct fat_arch *)(base + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint32_t off = PXSwap32(arch[i].offset, swap);
            BOOL checked = NO;
            NSError *sliceErr = nil;
            if (PXMIHasDylibCommandInSlice(data, off, dylibLoadPath, &checked, &sliceErr)) return YES;
            if (sliceErr) {
                if (error) *error = sliceErr;
                return NO;
            }
            checkedAny = checkedAny || checked;
        }
    } else {
        NSError *sliceErr = nil;
        if (PXMIHasDylibCommandInSlice(data, 0, dylibLoadPath, &checkedAny, &sliceErr)) return YES;
        if (sliceErr) {
            if (error) *error = sliceErr;
            return NO;
        }
    }
    if (!checkedAny && error) *error = PXMIError(54, @"No supported 64-bit Mach-O slice found");
    return NO;
}

+ (nullable NSDictionary<NSString *, id> *)codeSignatureSummaryForMachOAtPath:(NSString *)path
                                                                         error:(NSError **)error {
    if (!path.length) {
        if (error) *error = PXMIError(70, @"Missing Mach-O path");
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) {
        if (error) *error = PXMIError(71, @"Failed to read Mach-O: %@", path);
        return nil;
    }
    if (!PXRangeOK(data.length, 0, sizeof(uint32_t))) {
        if (error) *error = PXMIError(72, @"Mach-O too small: %@", path);
        return nil;
    }

    NSMutableDictionary *summary = [@{
        @"path": path ?: @"",
        @"fileSize": @(data.length),
        @"isFat": @"NO",
    } mutableCopy];
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)base;
    NSMutableArray *slices = [NSMutableArray array];
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        BOOL swap = (magic == FAT_CIGAM);
        struct fat_header *fh = (struct fat_header *)base;
        uint32_t nfat = PXSwap32(fh->nfat_arch, swap);
        if (!PXRangeOK(data.length, sizeof(struct fat_header), (uint64_t)nfat * sizeof(struct fat_arch))) {
            if (error) *error = PXMIError(73, @"Malformed fat header");
            return nil;
        }
        summary[@"isFat"] = @"YES";
        summary[@"nfat"] = @(nfat);
        struct fat_arch *arch = (struct fat_arch *)(base + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint32_t off = PXSwap32(arch[i].offset, swap);
            uint32_t size = PXSwap32(arch[i].size, swap);
            NSError *sliceErr = nil;
            NSDictionary *slice = PXMICodeSignatureSummaryForSlice(data, off, size, &sliceErr);
            NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:slice ?: @{}];
            row[@"index"] = @(i);
            if (sliceErr) row[@"error"] = sliceErr.localizedDescription ?: @"";
            [slices addObject:row];
        }
    } else {
        NSError *sliceErr = nil;
        NSDictionary *slice = PXMICodeSignatureSummaryForSlice(data, 0, data.length, &sliceErr);
        NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:slice ?: @{}];
        row[@"index"] = @0;
        if (sliceErr) row[@"error"] = sliceErr.localizedDescription ?: @"";
        [slices addObject:row];
    }
    summary[@"slices"] = slices;
    return summary;
}

+ (nullable NSDictionary<NSString *, id> *)encryptionSummaryForMachOAtPath:(NSString *)path
                                                                      error:(NSError **)error {
    if (!path.length) {
        if (error) *error = PXMIError(90, @"Missing Mach-O path");
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) {
        if (error) *error = PXMIError(91, @"Failed to read Mach-O: %@", path);
        return nil;
    }
    if (!PXRangeOK(data.length, 0, sizeof(uint32_t))) {
        if (error) *error = PXMIError(92, @"Mach-O too small: %@", path);
        return nil;
    }

    NSMutableDictionary *summary = [@{
        @"path": path ?: @"",
        @"fileSize": @(data.length),
        @"isFat": @"NO",
        @"encrypted": @"NO",
    } mutableCopy];
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)base;
    NSMutableArray *slices = [NSMutableArray array];
    BOOL encryptedAny = NO;
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        BOOL swap = (magic == FAT_CIGAM);
        struct fat_header *fh = (struct fat_header *)base;
        uint32_t nfat = PXSwap32(fh->nfat_arch, swap);
        if (!PXRangeOK(data.length, sizeof(struct fat_header), (uint64_t)nfat * sizeof(struct fat_arch))) {
            if (error) *error = PXMIError(93, @"Malformed fat header");
            return nil;
        }
        summary[@"isFat"] = @"YES";
        summary[@"nfat"] = @(nfat);
        struct fat_arch *arch = (struct fat_arch *)(base + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint32_t off = PXSwap32(arch[i].offset, swap);
            uint32_t size = PXSwap32(arch[i].size, swap);
            NSError *sliceErr = nil;
            NSDictionary *slice = PXMIEncryptionSummaryForSlice(data, off, size, &sliceErr);
            NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:slice ?: @{}];
            row[@"index"] = @(i);
            if (sliceErr) row[@"error"] = sliceErr.localizedDescription ?: @"";
            if ([row[@"encrypted"] isEqual:@"YES"]) encryptedAny = YES;
            [slices addObject:row];
        }
    } else {
        NSError *sliceErr = nil;
        NSDictionary *slice = PXMIEncryptionSummaryForSlice(data, 0, data.length, &sliceErr);
        NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:slice ?: @{}];
        row[@"index"] = @0;
        if (sliceErr) row[@"error"] = sliceErr.localizedDescription ?: @"";
        if ([row[@"encrypted"] isEqual:@"YES"]) encryptedAny = YES;
        [slices addObject:row];
    }
    summary[@"slices"] = slices;
    summary[@"encrypted"] = encryptedAny ? @"YES" : @"NO";
    return summary;
}

+ (nullable NSDictionary<NSString *, id> *)loadCommandSummaryForMachOAtPath:(NSString *)path
                                                                       error:(NSError **)error {
    if (!path.length) {
        if (error) *error = PXMIError(110, @"Missing Mach-O path");
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) {
        if (error) *error = PXMIError(111, @"Failed to read Mach-O: %@", path);
        return nil;
    }
    if (!PXRangeOK(data.length, 0, sizeof(uint32_t))) {
        if (error) *error = PXMIError(112, @"Mach-O too small: %@", path);
        return nil;
    }
    NSMutableDictionary *summary = [@{
        @"path": path ?: @"",
        @"fileSize": @(data.length),
        @"isFat": @"NO",
    } mutableCopy];
    uint8_t *base = (uint8_t *)data.bytes;
    uint32_t magic = *(uint32_t *)base;
    NSMutableArray *slices = [NSMutableArray array];
    NSMutableOrderedSet<NSString *> *allDylibs = [NSMutableOrderedSet orderedSet];
    NSMutableOrderedSet<NSString *> *allRpaths = [NSMutableOrderedSet orderedSet];
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        BOOL swap = (magic == FAT_CIGAM);
        struct fat_header *fh = (struct fat_header *)base;
        uint32_t nfat = PXSwap32(fh->nfat_arch, swap);
        if (!PXRangeOK(data.length, sizeof(struct fat_header), (uint64_t)nfat * sizeof(struct fat_arch))) {
            if (error) *error = PXMIError(113, @"Malformed fat header");
            return nil;
        }
        summary[@"isFat"] = @"YES";
        summary[@"nfat"] = @(nfat);
        struct fat_arch *arch = (struct fat_arch *)(base + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint32_t off = PXSwap32(arch[i].offset, swap);
            uint32_t size = PXSwap32(arch[i].size, swap);
            NSError *sliceErr = nil;
            NSDictionary *slice = PXMILoadCommandSummaryForSlice(data, off, size, &sliceErr);
            NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:slice ?: @{}];
            row[@"index"] = @(i);
            if (sliceErr) row[@"error"] = sliceErr.localizedDescription ?: @"";
            for (NSString *s in row[@"loadedDylibs"] ?: @[]) [allDylibs addObject:s];
            for (NSString *s in row[@"rpaths"] ?: @[]) [allRpaths addObject:s];
            [slices addObject:row];
        }
    } else {
        NSError *sliceErr = nil;
        NSDictionary *slice = PXMILoadCommandSummaryForSlice(data, 0, data.length, &sliceErr);
        NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:slice ?: @{}];
        row[@"index"] = @0;
        if (sliceErr) row[@"error"] = sliceErr.localizedDescription ?: @"";
        for (NSString *s in row[@"loadedDylibs"] ?: @[]) [allDylibs addObject:s];
        for (NSString *s in row[@"rpaths"] ?: @[]) [allRpaths addObject:s];
        [slices addObject:row];
    }
    summary[@"slices"] = slices;
    summary[@"loadedDylibs"] = allDylibs.array;
    summary[@"rpaths"] = allRpaths.array;
    return summary;
}

@end
