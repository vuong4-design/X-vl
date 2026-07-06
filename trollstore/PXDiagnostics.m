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
