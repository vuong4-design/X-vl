// PXRootHelper.m — Wrapper around TrollStore's spawnRoot: with availability
// detection. See PXRootHelper.h for contract.

#import "PXRootHelper.h"
#import "TSUtil.h"
#import "PXDiagnostics.h"
#import <sys/utsname.h>

NSString *const PXRootHelperErrorDomain = @"com.hydra.projectx.roothelper";

// Name of the bundled root helper binary declared in the app's TSRootBinaries.
static NSString *const kPXRootHelperBinaryName = @"weaponx_root_helper";

@implementation PXRootHelper {
    BOOL _availabilityProbed;
    BOOL _rootSpawnAvailable;
    NSString *_cachedHelperPath;
}

+ (instancetype)sharedHelper {
    static PXRootHelper *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[PXRootHelper alloc] init];
    });
    return shared;
}

- (nullable NSString *)helperBinaryPath {
    if (_cachedHelperPath) {
        return _cachedHelperPath;
    }

    // The helper is bundled at the app bundle root (declared in TSRootBinaries).
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSArray<NSString *> *candidates = @[
        [bundlePath stringByAppendingPathComponent:kPXRootHelperBinaryName],
        [[bundlePath stringByAppendingPathComponent:@"Helpers"]
            stringByAppendingPathComponent:kPXRootHelperBinaryName],
    ];

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *path in candidates) {
        if ([fm isExecutableFileAtPath:path]) {
            _cachedHelperPath = [path copy];
            return _cachedHelperPath;
        }
    }
    return nil;
}

// Parses the major.minor of the running OS version.
- (void)probeAvailability {
    if (_availabilityProbed) {
        return;
    }
    _availabilityProbed = YES;
    _rootSpawnAvailable = NO;

    // Must have a bundled helper to spawn at all.
    if (![self helperBinaryPath]) {
        return;
    }

    // persona-mgmt root spawning is mitigated from iOS 17.6 onward. Gate on
    // the OS version: allow < 17.6, refuse >= 17.6.
    NSOperatingSystemVersion v =
        [[NSProcessInfo processInfo] operatingSystemVersion];
    BOOL versionOK = NO;
    if (v.majorVersion < 17) {
        versionOK = YES;
    } else if (v.majorVersion == 17) {
        versionOK = (v.minorVersion < 6);
    } else {
        versionOK = NO;
    }

    _rootSpawnAvailable = versionOK;
}

- (BOOL)isRootSpawnAvailable {
    [self probeAvailability];
    return _rootSpawnAvailable;
}

- (BOOL)runAsRoot:(NSArray<NSString *> *)argv
         exitCode:(nullable int *)exitCode
           stdOut:(NSString * _Nullable * _Nullable)stdOut
           stdErr:(NSString * _Nullable * _Nullable)stdErr
            error:(NSError * _Nullable * _Nullable)error {
    if (argv.count == 0) {
        if (error) {
            *error = [NSError errorWithDomain:PXRootHelperErrorDomain
                                         code:PXRootHelperErrorInvalidArgs
                                     userInfo:@{NSLocalizedDescriptionKey:
                                         @"runAsRoot called with empty argv"}];
        }
        return NO;
    }

    NSString *helperPath = [self helperBinaryPath];
    if (!helperPath) {
        [PXDiagnostics log:@"[root] helper missing"];
        if (error) {
            *error = [NSError errorWithDomain:PXRootHelperErrorDomain
                                         code:PXRootHelperErrorHelperMissing
                                     userInfo:@{NSLocalizedDescriptionKey:
                                         @"Bundled root helper binary not found in app bundle"}];
        }
        return NO;
    }

    if (![self isRootSpawnAvailable]) {
        [PXDiagnostics log:@"[root] unavailable for argv=%@", argv];
        if (error) {
            *error = [NSError errorWithDomain:PXRootHelperErrorDomain
                                         code:PXRootHelperErrorUnavailable
                                     userInfo:@{NSLocalizedDescriptionKey:
                                         @"Root spawning unavailable on this OS (iOS 17.6+ mitigation)"}];
        }
        return NO;
    }

    NSString *outStr = nil;
    NSString *errStr = nil;
    [PXDiagnostics log:@"[root] run helper=%@ argv=%@", helperPath, argv];
    int code = spawnRoot(helperPath, argv, &outStr, &errStr);
    [PXDiagnostics log:@"[root] result code=%d stdout=%@ stderr=%@", code, outStr ?: @"", errStr ?: @""];

    if (stdOut) {
        *stdOut = outStr;
    }
    if (stdErr) {
        *stdErr = errStr;
    }
    if (exitCode) {
        *exitCode = code;
    }

    if (code != 0) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"Root helper exited with code %d: %@", code,
                errStr.length ? errStr : @"(no stderr)"];
            *error = [NSError errorWithDomain:PXRootHelperErrorDomain
                                         code:PXRootHelperErrorSpawnFailed
                                     userInfo:@{NSLocalizedDescriptionKey: desc}];
        }
        return NO;
    }

    return YES;
}

@end
