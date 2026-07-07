// PXDiagnostics.m — TrollStore debug logging and self-tests.

#import "PXDiagnostics.h"
#import "PXDYLDLauncher.h"
#import "PXEntitlements.h"
#import "PXInPlacePatcher.h"
#import "PXRootHelper.h"
#import "PXRuntimeSnapshot.h"
#import "PXShellRouter.h"

#import <UIKit/UIKit.h>
#import <sys/stat.h>

static NSString *PXDiagDirectory(void) {
    return @"/var/mobile/Library/ProjectXTroll";
}

static NSString *PXDiagString(id obj) {
    if (!obj) return @"(nil)";
    if ([obj isKindOfClass:[NSString class]]) return obj;
    return [obj description];
}

@implementation PXDiagnostics

+ (NSString *)logPath {
    return [PXDiagDirectory() stringByAppendingPathComponent:@"diagnostic.log"];
}

+ (void)ensureDirectory {
    NSError *err = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:PXDiagDirectory()
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:&err];
}

+ (void)clearLog {
    [self ensureDirectory];
    [[@"" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:[self logPath] atomically:YES];
}

+ (void)log:(NSString *)format, ... {
    if (!format.length) return;
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    [self ensureDirectory];
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [fmt stringFromDate:[NSDate date]], message ?: @""];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];

    NSString *path = [self logPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [data writeToFile:path atomically:YES];
        return;
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    [fh seekToEndOfFile];
    [fh writeData:data];
    [fh closeFile];
}

+ (NSString *)readLogTailWithMaxBytes:(NSUInteger)maxBytes {
    NSData *data = [NSData dataWithContentsOfFile:[self logPath]];
    if (!data.length) return @"(diagnostic log is empty)";
    if (maxBytes > 0 && data.length > maxBytes) {
        data = [data subdataWithRange:NSMakeRange(data.length - maxBytes, maxBytes)];
    }
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return s ?: @"(failed to decode diagnostic log)";
}

+ (NSDictionary<NSString *,id> *)environmentSnapshot {
    [self log:@"[env] starting environment snapshot"];
    NSBundle *bundle = [NSBundle mainBundle];
    NSProcessInfo *pi = [NSProcessInfo processInfo];
    NSString *tmpDir = @"/var/tmp/weaponx";
    NSString *tmpFile = [tmpDir stringByAppendingPathComponent:@"diagnostic_write_test.txt"];
    NSString *libFile = [PXDiagDirectory() stringByAppendingPathComponent:@"diagnostic_write_test.txt"];
    NSError *tmpErr = nil;
    NSError *libErr = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    [self ensureDirectory];
    BOOL tmpWrite = [@"ok" writeToFile:tmpFile atomically:YES encoding:NSUTF8StringEncoding error:&tmpErr];
    BOOL libWrite = [@"ok" writeToFile:libFile atomically:YES encoding:NSUTF8StringEncoding error:&libErr];
    NSDictionary *info = @{
        @"bundleIdentifier": bundle.bundleIdentifier ?: @"",
        @"bundlePath": bundle.bundlePath ?: @"",
        @"executable": bundle.infoDictionary[@"CFBundleExecutable"] ?: @"",
        @"home": NSHomeDirectory() ?: @"",
        @"osVersion": pi.operatingSystemVersionString ?: @"",
        @"logPath": [self logPath],
        @"writeVarTmp": tmpWrite ? @"YES" : PXDiagString(tmpErr.localizedDescription),
        @"writeProjectXTrollLibrary": libWrite ? @"YES" : PXDiagString(libErr.localizedDescription),
    };
    [self log:@"[env] %@", info];
    return info;
}

static NSArray<NSString *> *PXDiagMissingEntitlements(NSDictionary<NSString *, id> *entitlements, NSArray<NSString *> *requiredKeys) {
    NSMutableArray<NSString *> *missing = [NSMutableArray array];
    for (NSString *key in requiredKeys) {
        id value = entitlements[key];
        if (!value || ([value respondsToSelector:@selector(boolValue)] && ![value boolValue])) {
            [missing addObject:key];
        }
    }
    return missing;
}

+ (NSDictionary<NSString *,id> *)entitlementsSnapshot {
    [self log:@"[entitlements] starting entitlement snapshot"];

    NSBundle *bundle = [NSBundle mainBundle];
    NSString *executableName = bundle.infoDictionary[@"CFBundleExecutable"];
    NSString *mainPath = executableName.length ? [bundle.bundlePath stringByAppendingPathComponent:executableName] : @"";
    NSString *helperPath = [[PXRootHelper sharedHelper] helperBinaryPath] ?: @"";

    NSArray<NSString *> *requiredApp = @[
        @"platform-application",
        @"com.apple.private.persona-mgmt",
        @"com.apple.private.security.no-sandbox",
        @"com.apple.private.security.no-container",
        @"com.apple.private.MobileContainerManager.allowed",
        @"com.apple.private.security.container-manager"
    ];
    NSArray<NSString *> *requiredHelper = @[
        @"platform-application",
        @"com.apple.private.persona-mgmt",
        @"com.apple.private.security.no-sandbox",
        @"com.apple.private.security.no-container"
    ];

    NSError *mainErr = nil;
    NSError *helperErr = nil;
    NSDictionary *mainEnt = mainPath.length ? [PXEntitlements entitlementsForBinaryAtPath:mainPath error:&mainErr] : nil;
    NSDictionary *helperEnt = helperPath.length ? [PXEntitlements entitlementsForBinaryAtPath:helperPath error:&helperErr] : nil;
    NSArray *missingMain = mainEnt ? PXDiagMissingEntitlements(mainEnt, requiredApp) : requiredApp;
    NSArray *missingHelper = helperEnt ? PXDiagMissingEntitlements(helperEnt, requiredHelper) : requiredHelper;

    NSDictionary *info = @{
        @"mainPath": mainPath ?: @"",
        @"helperPath": helperPath ?: @"",
        @"mainReadOK": mainEnt ? @"YES" : @"NO",
        @"helperReadOK": helperEnt ? @"YES" : @"NO",
        @"mainError": mainErr.localizedDescription ?: @"",
        @"helperError": helperErr.localizedDescription ?: @"",
        @"missingMain": missingMain ?: @[],
        @"missingHelper": missingHelper ?: @[],
        @"mainEntitlements": mainEnt ?: @{},
        @"helperEntitlements": helperEnt ?: @{},
    };
    [self log:@"[entitlements] mainPath=%@ helperPath=%@ missingMain=%@ missingHelper=%@ mainError=%@ helperError=%@",
     mainPath ?: @"",
     helperPath ?: @"",
     missingMain ?: @[],
     missingHelper ?: @[],
     mainErr.localizedDescription ?: @"",
     helperErr.localizedDescription ?: @""];
    [self log:@"[entitlements] main=%@", mainEnt ?: @{}];
    [self log:@"[entitlements] helper=%@", helperEnt ?: @{}];
    return info;
}

+ (NSDictionary<NSString *,id> *)rootHelperSelfTest {
    [self log:@"[root] starting root helper self-test"];
    PXRootHelper *helper = [PXRootHelper sharedHelper];
    NSString *path = [helper helperBinaryPath];
    BOOL exists = path.length && [[NSFileManager defaultManager] fileExistsAtPath:path];
    BOOL executable = path.length && [[NSFileManager defaultManager] isExecutableFileAtPath:path];
    BOOL available = [helper isRootSpawnAvailable];
    int exitCode = -999;
    NSString *stdOut = nil;
    NSString *stdErr = nil;
    NSError *err = nil;
    BOOL ok = [helper runAsRoot:@[@"rm", @"/var/tmp/weaponx/roothelper_nonexistent"]
                          exitCode:&exitCode
                            stdOut:&stdOut
                            stdErr:&stdErr
                             error:&err];
    NSDictionary *info = @{
        @"helperPath": path ?: @"(nil)",
        @"exists": exists ? @"YES" : @"NO",
        @"executable": executable ? @"YES" : @"NO",
        @"available": available ? @"YES" : @"NO",
        @"runOK": ok ? @"YES" : @"NO",
        @"exitCode": @(exitCode),
        @"stdout": stdOut ?: @"",
        @"stderr": stdErr ?: @"",
        @"error": err.localizedDescription ?: @"",
    };
    [self log:@"[root] %@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)routerFixtureSelfTest {
    [self log:@"[router-test] starting router fixture self-test"];
    NSArray<NSString *> *commands = @[
        @"mkdir -p '/var/tmp/weaponx/router-test/a'",
        @"touch '/var/tmp/weaponx/router-test/a/file.txt'",
        @"chmod -R 0777 '/var/tmp/weaponx/router-test'",
        @"chflags -R nouchg,noschg,nohidden '/var/tmp/weaponx/router-test'",
        @"rm -rf '/var/tmp/weaponx/router-test/a/file.txt'",
        @"find '/var/tmp/weaponx/router-test' -depth -type d -empty -delete",
        @"sync"
    ];
    NSMutableArray *results = [NSMutableArray array];
    for (NSString *cmd in commands) {
        NSError *err = nil;
        BOOL ok = [[PXShellRouter sharedRouter] runShellCommand:cmd error:&err];
        NSDictionary *row = @{
            @"command": cmd,
            @"ok": ok ? @"YES" : @"NO",
            @"error": err.localizedDescription ?: @"",
        };
        [results addObject:row];
        [self log:@"[router-test] %@", row];
    }
    return @{@"results": results};
}

+ (NSDictionary<NSString *,id> *)injectionSnapshotForBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[inject] starting injection snapshot bundleID=%@", targetBundleID];
    NSError *err = nil;
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:targetBundleID error:&err];
    NSDictionary *status = [PXRuntimeSnapshot statusForBundleID:targetBundleID];
    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:status ?: @{}];
    info[@"exportOK"] = snapshot ? @"YES" : @"NO";
    info[@"exportError"] = err.localizedDescription ?: @"";
    [self log:@"[inject] snapshot status=%@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)enableObjCHooksSnapshotForBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[inject] enabling objc hooks snapshot bundleID=%@", targetBundleID];
    NSError *err = nil;
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:targetBundleID enableObjCHooks:YES error:&err];
    NSDictionary *status = [PXRuntimeSnapshot statusForBundleID:targetBundleID];
    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:status ?: @{}];
    info[@"exportOK"] = snapshot ? @"YES" : @"NO";
    info[@"exportError"] = err.localizedDescription ?: @"";
    info[@"EnableObjCHooks"] = snapshot[@"EnableObjCHooks"] ?: @"";
    info[@"note"] = @"ObjC hooks will be active on next target launch. Reopen the target app, then check Injection Marker Status.";
    [self log:@"[inject] objc hooks snapshot status=%@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)enableCHooksSnapshotForBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[inject] enabling c hooks snapshot bundleID=%@", targetBundleID];
    NSError *err = nil;
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:targetBundleID
                                                           enableObjCHooks:YES
                                                              enableCHooks:YES
                                                              cHookOptions:@{@"CHookTestMode": @"sysctlbyname-safe",
                                                                             @"EnableSysctlByNameHook": @YES,
                                                                             @"EnableSysctlHook": @YES,
                                                                             @"EnableUnameHook": @YES,
                                                                             @"EnableDlsymHook": @NO,
                                                                             @"EnableDeviceMetricsHook": @NO,
                                                                             @"EnableMobileGestaltHook": @YES,
                                                                             @"EnableSysctlName_hw.machine": @YES,
                                                                             @"EnableSysctlName_hw.model": @YES,
                                                                             @"EnableSysctlName_kern.osversion": @YES,
                                                                             @"EnableSysctlName_kern.version": @YES}
                                                                     error:&err];
    NSDictionary *status = [PXRuntimeSnapshot statusForBundleID:targetBundleID];
    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:status ?: @{}];
    info[@"exportOK"] = snapshot ? @"YES" : @"NO";
    info[@"exportError"] = err.localizedDescription ?: @"";
    info[@"EnableObjCHooks"] = snapshot[@"EnableObjCHooks"] ?: @"";
    info[@"EnableCHooks"] = snapshot[@"EnableCHooks"] ?: @"";
    info[@"CHookTestMode"] = snapshot[@"CHookTestMode"] ?: @"";
    info[@"EnableSysctlHook"] = snapshot[@"EnableSysctlHook"] ?: @"";
    info[@"EnableUnameHook"] = snapshot[@"EnableUnameHook"] ?: @"";
    info[@"EnableDlsymHook"] = snapshot[@"EnableDlsymHook"] ?: @"";
    info[@"EnableDeviceMetricsHook"] = snapshot[@"EnableDeviceMetricsHook"] ?: @"";
    info[@"note"] = @"ObjC, safe sysctlbyname, and bundle-local sysctl/uname rebind will be active on next target launch. Dlsym is diagnostic-only. Reopen the target app, then check Injection Marker Status.";
    [self log:@"[inject] c hooks snapshot status=%@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)enableDlsymHookSnapshotForBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[inject] enabling dlsym hook snapshot bundleID=%@", targetBundleID];
    NSError *err = nil;
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:targetBundleID
                                                           enableObjCHooks:YES
                                                              enableCHooks:YES
                                                              cHookOptions:@{@"CHookTestMode": @"dlsym-diagnostic",
                                                                             @"EnableSysctlByNameHook": @YES,
                                                                             @"EnableSysctlHook": @YES,
                                                                             @"EnableUnameHook": @YES,
                                                                             @"EnableDlsymHook": @YES,
                                                                             @"EnableDeviceMetricsHook": @NO,
                                                                             @"EnableMobileGestaltHook": @YES,
                                                                             @"EnableSysctlName_hw.machine": @YES,
                                                                             @"EnableSysctlName_hw.model": @YES,
                                                                             @"EnableSysctlName_kern.osversion": @YES,
                                                                             @"EnableSysctlName_kern.version": @YES}
                                                                     error:&err];
    NSDictionary *status = [PXRuntimeSnapshot statusForBundleID:targetBundleID];
    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:status ?: @{}];
    info[@"exportOK"] = snapshot ? @"YES" : @"NO";
    info[@"exportError"] = err.localizedDescription ?: @"";
    info[@"EnableObjCHooks"] = snapshot[@"EnableObjCHooks"] ?: @"";
    info[@"EnableCHooks"] = snapshot[@"EnableCHooks"] ?: @"";
    info[@"CHookTestMode"] = snapshot[@"CHookTestMode"] ?: @"";
    info[@"EnableSysctlHook"] = snapshot[@"EnableSysctlHook"] ?: @"";
    info[@"EnableUnameHook"] = snapshot[@"EnableUnameHook"] ?: @"";
    info[@"EnableDlsymHook"] = snapshot[@"EnableDlsymHook"] ?: @"";
    info[@"EnableDeviceMetricsHook"] = snapshot[@"EnableDeviceMetricsHook"] ?: @"";
    info[@"note"] = @"Dlsym diagnostic hook will be active on next target launch. Use only if model spoofing regresses or MobileGestalt/dynamic lookup needs investigation.";
    [self log:@"[inject] dlsym hook snapshot status=%@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)enableDeviceMetricsHookSnapshotForBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[inject] enabling device metrics hook snapshot bundleID=%@", targetBundleID];
    NSError *err = nil;
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:targetBundleID
                                                           enableObjCHooks:YES
                                                              enableCHooks:YES
                                                              cHookOptions:@{@"CHookTestMode": @"device-metrics-diagnostic",
                                                                             @"EnableSysctlByNameHook": @YES,
                                                                             @"EnableSysctlHook": @YES,
                                                                             @"EnableUnameHook": @YES,
                                                                             @"EnableDlsymHook": @NO,
                                                                             @"EnableDeviceMetricsHook": @YES,
                                                                             @"EnableMobileGestaltHook": @YES,
                                                                             @"EnableSysctlName_hw.machine": @YES,
                                                                             @"EnableSysctlName_hw.model": @YES,
                                                                             @"EnableSysctlName_kern.osversion": @YES,
                                                                             @"EnableSysctlName_kern.version": @YES}
                                                                     error:&err];
    NSDictionary *status = [PXRuntimeSnapshot statusForBundleID:targetBundleID];
    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:status ?: @{}];
    info[@"exportOK"] = snapshot ? @"YES" : @"NO";
    info[@"exportError"] = err.localizedDescription ?: @"";
    info[@"EnableObjCHooks"] = snapshot[@"EnableObjCHooks"] ?: @"";
    info[@"EnableCHooks"] = snapshot[@"EnableCHooks"] ?: @"";
    info[@"CHookTestMode"] = snapshot[@"CHookTestMode"] ?: @"";
    info[@"EnableSysctlHook"] = snapshot[@"EnableSysctlHook"] ?: @"";
    info[@"EnableUnameHook"] = snapshot[@"EnableUnameHook"] ?: @"";
    info[@"EnableDlsymHook"] = snapshot[@"EnableDlsymHook"] ?: @"";
    info[@"EnableDeviceMetricsHook"] = snapshot[@"EnableDeviceMetricsHook"] ?: @"";
    info[@"note"] = @"Device metrics hooks will be active on next target launch for CPU cores, memory, and screen metrics. Reopen AIDA64, visit device/display pages, then check Injection Marker Status.";
    [self log:@"[inject] device metrics hook snapshot status=%@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)enableCHookTestSnapshotForBundleID:(NSString *)bundleID mode:(NSString *)mode {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    NSString *testMode = mode.length ? mode : @"sysctlbyname-safe";
    NSMutableDictionary *options = [@{
        @"CHookTestMode": testMode,
        @"EnableSysctlByNameHook": @NO,
        @"EnableSysctlName_hw.machine": @NO,
        @"EnableSysctlName_hw.model": @NO,
        @"EnableSysctlName_kern.osversion": @NO,
        @"EnableSysctlName_kern.version": @NO
    } mutableCopy];

    if ([testMode isEqualToString:@"sysctlbyname-safe"]) {
        options[@"EnableSysctlByNameHook"] = @YES;
        options[@"EnableSysctlName_hw.machine"] = @YES;
        options[@"EnableSysctlName_hw.model"] = @YES;
        options[@"EnableSysctlName_kern.osversion"] = @YES;
        options[@"EnableSysctlName_kern.version"] = @YES;
    } else if ([testMode isEqualToString:@"sysctlbyname-hw.machine"]) {
        options[@"EnableSysctlByNameHook"] = @YES;
        options[@"EnableSysctlName_hw.machine"] = @YES;
    } else if ([testMode isEqualToString:@"sysctlbyname-hw.model"]) {
        options[@"EnableSysctlByNameHook"] = @YES;
        options[@"EnableSysctlName_hw.model"] = @YES;
    } else if ([testMode isEqualToString:@"sysctlbyname-kern.osversion"]) {
        options[@"EnableSysctlByNameHook"] = @YES;
        options[@"EnableSysctlName_kern.osversion"] = @YES;
    } else if ([testMode isEqualToString:@"sysctlbyname-kern.version"]) {
        options[@"EnableSysctlByNameHook"] = @YES;
        options[@"EnableSysctlName_kern.version"] = @YES;
    }

    [self log:@"[inject] enabling c hook test snapshot bundleID=%@ mode=%@ options=%@", targetBundleID, testMode, options];
    NSError *err = nil;
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:targetBundleID
                                                           enableObjCHooks:YES
                                                              enableCHooks:YES
                                                              cHookOptions:options
                                                                     error:&err];
    NSDictionary *status = [PXRuntimeSnapshot statusForBundleID:targetBundleID];
    NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:status ?: @{}];
    info[@"exportOK"] = snapshot ? @"YES" : @"NO";
    info[@"exportError"] = err.localizedDescription ?: @"";
    info[@"CHookTestMode"] = snapshot[@"CHookTestMode"] ?: testMode;
    info[@"EnableSysctlByNameHook"] = snapshot[@"EnableSysctlByNameHook"] ?: @"";
    info[@"note"] = @"Reopen AIDA64 once, then check Injection Marker Status. If AIDA64 exits, this sysctlbyname value is the suspect.";
    [self log:@"[inject] c hook test snapshot status=%@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)injectionMarkerStatusForBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[inject] marker status bundleID=%@", targetBundleID];
    NSDictionary *runtimeStatus = [PXRuntimeSnapshot statusForBundleID:targetBundleID] ?: @{};
    NSDictionary *patchStatus = [PXInPlacePatcher statusForBundleID:targetBundleID] ?: @{};
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    info[@"bundleID"] = targetBundleID ?: @"";
    info[@"runtime"] = runtimeStatus;
    info[@"patch"] = patchStatus;
    info[@"markerExists"] = runtimeStatus[@"markerExists"] ?: @"NO";
    info[@"targetMarkerExists"] = runtimeStatus[@"targetMarkerExists"] ?: @"NO";
    info[@"injectionLoaded"] = ([runtimeStatus[@"markerExists"] isEqual:@"YES"] || [runtimeStatus[@"targetMarkerExists"] isEqual:@"YES"]) ? @"YES" : @"NO";
    info[@"markerPath"] = runtimeStatus[@"markerPath"] ?: @"";
    info[@"targetMarkerPath"] = runtimeStatus[@"targetMarkerPath"] ?: @"";
    info[@"targetDylibExists"] = patchStatus[@"targetDylibExists"] ?: @"";
    info[@"installedCarrierHasLoadCommand"] = patchStatus[@"installedCarrierHasLoadCommand"] ?: @"";
    info[@"targetHookStatsExists"] = runtimeStatus[@"targetHookStatsExists"] ?: @"NO";
    info[@"targetHookStatsPath"] = runtimeStatus[@"targetHookStatsPath"] ?: @"";
    info[@"targetHookStats"] = runtimeStatus[@"targetHookStats"] ?: @{};
    [self log:@"[inject] marker status result=%@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)dyldLaunchBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[dyld] diagnostic launch bundleID=%@", targetBundleID];
    return [PXDYLDLauncher launchBundleID:targetBundleID timeout:6.0];
}

+ (NSDictionary<NSString *,id> *)prepareInPlaceBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[patch] diagnostic prepare bundleID=%@", targetBundleID];
    return [PXInPlacePatcher prepareBundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)scanFrameworkCarriersBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[carrier] diagnostic scan bundleID=%@", targetBundleID];
    return [PXInPlacePatcher scanFrameworkCarriersBundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)patchFrameworkCarrierBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[carrier] diagnostic patch bundleID=%@", targetBundleID];
    return [PXInPlacePatcher patchFrameworkCarrierBundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)patchPreparedInPlaceCopyBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[patch] diagnostic patch prepared copy bundleID=%@", targetBundleID];
    return [PXInPlacePatcher patchPreparedCopyBundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)exportPatchedTIPABundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[patch] diagnostic export patched TIPA bundleID=%@", targetBundleID];
    return [PXInPlacePatcher exportPatchedTIPABundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)installPatchedInPlaceCopyBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[patch] diagnostic install patched copy bundleID=%@", targetBundleID];
    return [PXInPlacePatcher installPatchedCopyBundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)installPatchedInPlaceCopyWithoutLaunchBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[patch] diagnostic install patched copy without launch bundleID=%@", targetBundleID];
    return [PXInPlacePatcher installPatchedCopyWithoutLaunchBundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)restoreInPlaceBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[patch] diagnostic restore bundleID=%@", targetBundleID];
    return [PXInPlacePatcher restoreBundleID:targetBundleID];
}

+ (NSDictionary<NSString *,id> *)inPlaceStatusBundleID:(NSString *)bundleID {
    NSString *targetBundleID = bundleID.length ? bundleID : @"com.finalwire.aida64";
    [self log:@"[patch] diagnostic status bundleID=%@", targetBundleID];
    NSDictionary *status = [PXInPlacePatcher statusForBundleID:targetBundleID];
    [self log:@"[patch] status result=%@", status ?: @{}];
    return status;
}

@end
