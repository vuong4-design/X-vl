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

@end
