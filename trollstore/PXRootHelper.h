// PXRootHelper.h — Wrapper around TrollStore's spawnRoot: with availability
// detection.
//
// This is the ONLY path through which uid-0 operations should flow. Callers
// must treat a failure as a hard error and surface it (no silent fallback).
// On iOS 17.6+ the underlying persona-mgmt mechanism is mitigated, so
// -isRootSpawnAvailable will report NO and -runAsRoot:error: will fail with a
// descriptive error rather than silently doing nothing.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const PXRootHelperErrorDomain;

typedef NS_ENUM(NSInteger, PXRootHelperError) {
    PXRootHelperErrorUnavailable   = 1, // spawnRoot unsupported (e.g. iOS 17.6+)
    PXRootHelperErrorSpawnFailed   = 2, // spawn attempted but returned non-zero
    PXRootHelperErrorInvalidArgs   = 3, // empty argv / missing binary path
    PXRootHelperErrorHelperMissing = 4, // bundled helper binary not found
};

@interface PXRootHelper : NSObject

+ (instancetype)sharedHelper;

// Best-effort detection of whether root spawning is available on this device.
// Cached after first probe. Returns NO on iOS 17.6+ or when the bundled helper
// is missing.
- (BOOL)isRootSpawnAvailable;

// Absolute path to the bundled root helper binary (declared in TSRootBinaries),
// or nil if it cannot be located inside the app bundle.
- (nullable NSString *)helperBinaryPath;

// Runs the bundled helper as root with the given argv. Returns the child exit
// code via `exitCode` (if non-NULL). Returns YES on exit code 0, NO otherwise,
// populating `error` with a descriptive PXRootHelperError.
- (BOOL)runAsRoot:(NSArray<NSString *> *)argv
         exitCode:(nullable int *)exitCode
           stdOut:(NSString * _Nullable * _Nullable)stdOut
           stdErr:(NSString * _Nullable * _Nullable)stdErr
            error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
