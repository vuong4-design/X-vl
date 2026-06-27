// PXEntitlements.m — In-process Mach-O entitlements reader.
// See PXEntitlements.h for the contract.
//
// Parses LC_CODE_SIGNATURE -> embedded SuperBlob -> CSMAGIC_EMBEDDED_ENTITLEMENTS.
// All multi-byte code-signature fields are big-endian on disk and are byte-
// swapped via ntohl. Mach-O header/load-command fields follow the binary's
// own endianness (detected from the magic).

#import "PXEntitlements.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/swap.h>

NSString *const PXEntitlementsErrorDomain = @"com.hydra.projectx.entitlements";

// Code Signing magic numbers (from cs_blobs.h; redeclared to avoid SDK dependency).
static const uint32_t kPXCSMAGIC_EMBEDDED_SIGNATURE   = 0xfade0cc0;
static const uint32_t kPXCSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;

typedef struct {
    uint32_t type;
    uint32_t offset;
} PXCSBlobIndex;

typedef struct {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
} PXCSSuperBlob;

typedef struct {
    uint32_t magic;
    uint32_t length;
} PXCSGenericBlob;

static NSError *PXEntError(PXEntitlementsError code, NSString *desc) {
    return [NSError errorWithDomain:PXEntitlementsErrorDomain
                              code:code
                          userInfo:@{NSLocalizedDescriptionKey: desc}];
}

// Safe bounds check: is [offset, offset+len) within data?
static BOOL PXRangeOK(NSData *data, uint64_t offset, uint64_t len) {
    uint64_t end;
    if (__builtin_add_overflow(offset, len, &end)) return NO;
    return end <= (uint64_t)data.length;
}

// Extract entitlements XML from a code-signature SuperBlob located at
// `csOffset` (offset into `data`) of size `csSize`.
static NSData *PXEntitlementsFromCodeSig(NSData *data,
                                         uint64_t csOffset,
                                         uint64_t csSize) {
    if (!PXRangeOK(data, csOffset, sizeof(PXCSSuperBlob))) return nil;

    const uint8_t *base = (const uint8_t *)data.bytes + csOffset;
    PXCSSuperBlob superBlob;
    memcpy(&superBlob, base, sizeof(superBlob));
    uint32_t magic = ntohl(superBlob.magic);
    uint32_t count = ntohl(superBlob.count);

    if (magic != kPXCSMAGIC_EMBEDDED_SIGNATURE) {
        return nil;
    }

    // Bound the index array.
    uint64_t indexBytes = (uint64_t)count * sizeof(PXCSBlobIndex);
    if (!PXRangeOK(data, csOffset + sizeof(PXCSSuperBlob), indexBytes)) {
        return nil;
    }

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *idxPtr =
            base + sizeof(PXCSSuperBlob) + (uint64_t)i * sizeof(PXCSBlobIndex);
        PXCSBlobIndex idx;
        memcpy(&idx, idxPtr, sizeof(idx));
        uint32_t blobOffset = ntohl(idx.offset);

        uint64_t absBlobOffset = csOffset + blobOffset;
        if (!PXRangeOK(data, absBlobOffset, sizeof(PXCSGenericBlob))) {
            continue;
        }

        PXCSGenericBlob blob;
        memcpy(&blob, (const uint8_t *)data.bytes + absBlobOffset, sizeof(blob));
        uint32_t blobMagic = ntohl(blob.magic);
        uint32_t blobLength = ntohl(blob.length);

        if (blobMagic == kPXCSMAGIC_EMBEDDED_ENTITLEMENTS) {
            if (blobLength < sizeof(PXCSGenericBlob)) continue;
            uint64_t payloadLen = blobLength - sizeof(PXCSGenericBlob);
            uint64_t payloadOff = absBlobOffset + sizeof(PXCSGenericBlob);
            if (!PXRangeOK(data, payloadOff, payloadLen)) continue;
            return [data subdataWithRange:NSMakeRange((NSUInteger)payloadOff,
                                                      (NSUInteger)payloadLen)];
        }
    }
    return nil;
}

// Scan a single (thin) Mach-O slice starting at sliceOffset for LC_CODE_SIGNATURE.
static NSData *PXEntitlementsFromThinMachO(NSData *data,
                                           uint64_t sliceOffset,
                                           NSError **error) {
    if (!PXRangeOK(data, sliceOffset, sizeof(uint32_t))) {
        if (error) *error = PXEntError(PXEntitlementsErrorMalformed, @"slice offset out of range");
        return nil;
    }

    uint32_t magic;
    memcpy(&magic, (const uint8_t *)data.bytes + sliceOffset, sizeof(magic));

    BOOL is64 = NO;
    BOOL swap = NO;
    switch (magic) {
        case MH_MAGIC:    is64 = NO; swap = NO;  break;
        case MH_CIGAM:    is64 = NO; swap = YES; break;
        case MH_MAGIC_64: is64 = YES; swap = NO;  break;
        case MH_CIGAM_64: is64 = YES; swap = YES; break;
        default:
            if (error) *error = PXEntError(PXEntitlementsErrorNotMachO, @"unrecognized Mach-O magic");
            return nil;
    }

    uint32_t ncmds;
    uint64_t loadCmdsOffset;
    if (is64) {
        if (!PXRangeOK(data, sliceOffset, sizeof(struct mach_header_64))) {
            if (error) *error = PXEntError(PXEntitlementsErrorMalformed, @"truncated mach_header_64");
            return nil;
        }
        struct mach_header_64 hdr;
        memcpy(&hdr, (const uint8_t *)data.bytes + sliceOffset, sizeof(hdr));
        ncmds = swap ? OSSwapInt32(hdr.ncmds) : hdr.ncmds;
        loadCmdsOffset = sliceOffset + sizeof(struct mach_header_64);
    } else {
        if (!PXRangeOK(data, sliceOffset, sizeof(struct mach_header))) {
            if (error) *error = PXEntError(PXEntitlementsErrorMalformed, @"truncated mach_header");
            return nil;
        }
        struct mach_header hdr;
        memcpy(&hdr, (const uint8_t *)data.bytes + sliceOffset, sizeof(hdr));
        ncmds = swap ? OSSwapInt32(hdr.ncmds) : hdr.ncmds;
        loadCmdsOffset = sliceOffset + sizeof(struct mach_header);
    }

    uint64_t cursor = loadCmdsOffset;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (!PXRangeOK(data, cursor, sizeof(struct load_command))) {
            if (error) *error = PXEntError(PXEntitlementsErrorMalformed, @"truncated load_command");
            return nil;
        }
        struct load_command lc;
        memcpy(&lc, (const uint8_t *)data.bytes + cursor, sizeof(lc));
        uint32_t cmd = swap ? OSSwapInt32(lc.cmd) : lc.cmd;
        uint32_t cmdsize = swap ? OSSwapInt32(lc.cmdsize) : lc.cmdsize;

        if (cmdsize < sizeof(struct load_command)) {
            if (error) *error = PXEntError(PXEntitlementsErrorMalformed, @"invalid cmdsize");
            return nil;
        }

        if (cmd == LC_CODE_SIGNATURE) {
            if (!PXRangeOK(data, cursor, sizeof(struct linkedit_data_command))) {
                if (error) *error = PXEntError(PXEntitlementsErrorMalformed, @"truncated LC_CODE_SIGNATURE");
                return nil;
            }
            struct linkedit_data_command sigCmd;
            memcpy(&sigCmd, (const uint8_t *)data.bytes + cursor, sizeof(sigCmd));
            uint32_t dataoff = swap ? OSSwapInt32(sigCmd.dataoff) : sigCmd.dataoff;
            uint32_t datasize = swap ? OSSwapInt32(sigCmd.datasize) : sigCmd.datasize;

            // Code signature offset is relative to the slice start.
            uint64_t csAbs = sliceOffset + dataoff;
            NSData *ents = PXEntitlementsFromCodeSig(data, csAbs, datasize);
            if (ents) {
                return ents;
            }
            // LC_CODE_SIGNATURE present but no entitlements blob inside.
            if (error) *error = PXEntError(PXEntitlementsErrorNoEntitlements, @"no entitlements blob in signature");
            return nil;
        }

        cursor += cmdsize;
    }

    if (error) *error = PXEntError(PXEntitlementsErrorNoCodeSignature, @"no LC_CODE_SIGNATURE load command");
    return nil;
}

@implementation PXEntitlements

+ (nullable NSData *)entitlementsDataForBinaryAtPath:(NSString *)binaryPath
                                               error:(NSError * _Nullable * _Nullable)error {
    if (binaryPath.length == 0) {
        if (error) *error = PXEntError(PXEntitlementsErrorInvalidArgs, @"nil/empty binary path");
        return nil;
    }

    NSError *readErr = nil;
    NSData *data = [NSData dataWithContentsOfFile:binaryPath
                                         options:NSDataReadingMappedIfSafe
                                           error:&readErr];
    if (!data) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:@"Failed to read '%@': %@",
                binaryPath, readErr.localizedDescription ?: @"unknown error"];
            *error = PXEntError(PXEntitlementsErrorReadFailed, desc);
        }
        return nil;
    }

    if (data.length < sizeof(uint32_t)) {
        if (error) *error = PXEntError(PXEntitlementsErrorNotMachO, @"file too small");
        return nil;
    }

    uint32_t magic;
    memcpy(&magic, data.bytes, sizeof(magic));

    // Fat (universal) binary: iterate slices.
    if (magic == FAT_MAGIC || magic == FAT_CIGAM ||
        magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        BOOL is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
        // fat_header fields are always big-endian.
        struct fat_header fh;
        memcpy(&fh, data.bytes, sizeof(fh));
        uint32_t nfat = ntohl(fh.nfat_arch);

        uint64_t archOffset = sizeof(struct fat_header);
        for (uint32_t i = 0; i < nfat; i++) {
            uint64_t sliceOff = 0;
            if (is64) {
                if (!PXRangeOK(data, archOffset, sizeof(struct fat_arch_64))) break;
                struct fat_arch_64 fa;
                memcpy(&fa, (const uint8_t *)data.bytes + archOffset, sizeof(fa));
                sliceOff = OSSwapBigToHostInt64(fa.offset);
                archOffset += sizeof(struct fat_arch_64);
            } else {
                if (!PXRangeOK(data, archOffset, sizeof(struct fat_arch))) break;
                struct fat_arch fa;
                memcpy(&fa, (const uint8_t *)data.bytes + archOffset, sizeof(fa));
                sliceOff = ntohl(fa.offset);
                archOffset += sizeof(struct fat_arch);
            }

            NSError *sliceErr = nil;
            NSData *ents = PXEntitlementsFromThinMachO(data, sliceOff, &sliceErr);
            if (ents) {
                return ents;
            }
            // Keep scanning other slices; remember last meaningful error.
            if (error) *error = sliceErr;
        }
        if (error && !*error) {
            *error = PXEntError(PXEntitlementsErrorNoEntitlements, @"no entitlements in any fat slice");
        }
        return nil;
    }

    // Thin Mach-O.
    return PXEntitlementsFromThinMachO(data, 0, error);
}

+ (nullable NSDictionary<NSString *, id> *)entitlementsForBinaryAtPath:(NSString *)binaryPath
                                                                error:(NSError * _Nullable * _Nullable)error {
    NSData *xml = [self entitlementsDataForBinaryAtPath:binaryPath error:error];
    if (!xml) {
        return nil;
    }

    NSError *plistErr = nil;
    id obj = [NSPropertyListSerialization propertyListWithData:xml
                                                      options:NSPropertyListImmutable
                                                       format:NULL
                                                        error:&plistErr];
    if (![obj isKindOfClass:[NSDictionary class]]) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:@"Entitlements plist parse failed: %@",
                plistErr.localizedDescription ?: @"not a dictionary"];
            *error = PXEntError(PXEntitlementsErrorMalformed, desc);
        }
        return nil;
    }
    return (NSDictionary *)obj;
}

@end
