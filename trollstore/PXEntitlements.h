// PXEntitlements.h — In-process Mach-O entitlements reader.
//
// Replaces the legacy `ldid -e <binary>` shell-out (AppEntitlementsReader.m:42)
// by parsing the embedded entitlements blob directly from the binary's
// LC_CODE_SIGNATURE -> CSMAGIC_EMBEDDED_ENTITLEMENTS slot.
//
// Advantages over ldid:
//  - No external binary dependency (works without /var/jb/usr/bin/ldid).
//  - No uid 0 required (reading a bundle binary is a plain file read).
//  - OS-version independent: works on iOS 17.6+ where spawnRoot is mitigated.
//
// Handles thin and fat (universal) Mach-O, both endiannesses, and 32/64-bit.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const PXEntitlementsErrorDomain;

typedef NS_ENUM(NSInteger, PXEntitlementsError) {
    PXEntitlementsErrorInvalidArgs    = 1, // nil/empty path
    PXEntitlementsErrorReadFailed     = 2, // could not read file
    PXEntitlementsErrorNotMachO       = 3, // not a recognizable Mach-O
    PXEntitlementsErrorNoCodeSignature = 4, // no LC_CODE_SIGNATURE present
    PXEntitlementsErrorNoEntitlements = 5, // no embedded entitlements blob
    PXEntitlementsErrorMalformed      = 6, // truncated/corrupt structures
};

@interface PXEntitlements : NSObject

// Returns the raw entitlements XML plist data embedded in the Mach-O at
// `binaryPath`, or nil with an error. For fat binaries, the first slice that
// contains an entitlements blob is returned.
+ (nullable NSData *)entitlementsDataForBinaryAtPath:(NSString *)binaryPath
                                               error:(NSError * _Nullable * _Nullable)error;

// Convenience: parses the entitlements XML into an NSDictionary.
+ (nullable NSDictionary<NSString *, id> *)entitlementsForBinaryAtPath:(NSString *)binaryPath
                                                                error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
