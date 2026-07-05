// PXDYLDLauncher.m - experimental DYLD_INSERT_LIBRARIES launcher backend.

#import "PXDYLDLauncher.h"
#import "PXDiagnostics.h"
#import "PXRootHelper.h"
#import "PXRuntimeSnapshot.h"

#import <objc/message.h>

NSString * const PXDYLDLauncherErrorDomain = @"PXDYLDLauncherErrorDomain";

static NSError *PXDYLError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:PXDYLDLauncherErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"DYLD launch error"}];
}

static id PXAppProxy(NSString *bundleID) {
    Class proxyCls = NSClassFromString(@"LSApplicationProxy");
    SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    return (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
}

static NSString *PXProxyURLPath(id proxy, NSString *key) {
    id value = nil;
    @try { value = [proxy valueForKey:key]; } @catch (__unused NSException *e) {}
    if ([value isKindOfClass:[NSURL class]]) return [(NSURL *)value path];
    if ([value isKindOfClass:[NSString class]]) return value;
    return nil;
}

static NSString *PXProxyString(id proxy, NSString *key) {
    id value = nil;
    @try { value = [proxy valueForKey:key]; } @catch (__unused NSException *e) {}
    if ([value isKindOfClass:[NSString class]]) return value;
    return nil;
}

static NSString *PXBundlePathForProxy(id proxy) {
    NSString *bundlePath = PXProxyURLPath(proxy, @"bundleURL");
    if (bundlePath.length) return bundlePath;
    NSString *containerPath = PXProxyURLPath(proxy, @"bundleContainerURL");
    if (!containerPath.length) return nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([containerPath.pathExtension isEqualToString:@"app"] && [fm fileExistsAtPath:containerPath isDirectory:&isDir] && isDir) {
        return containerPath;
    }
    NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:containerPath error:nil];
    for (NSString *item in items) {
        if (![item.pathExtension isEqualToString:@"app"]) continue;
        NSString *candidate = [containerPath stringByAppendingPathComponent:item];
        if ([fm fileExistsAtPath:candidate isDirectory:&isDir] && isDir) return candidate;
    }
    return nil;
}

static NSString *PXExecutablePathForBundleID(NSString *bundleID, NSString **outBundlePath, NSString **outDataPath) {
    id proxy = PXAppProxy(bundleID);
    if (!proxy) return nil;
    NSString *bundlePath = PXBundlePathForProxy(proxy);
    NSString *exeName = PXProxyString(proxy, @"bundleExecutable");
    if (!exeName.length && bundlePath.length) {
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
        exeName = [info[@"CFBundleExecutable"] isKindOfClass:[NSString class]] ? info[@"CFBundleExecutable"] : nil;
    }
    NSString *dataPath = PXProxyURLPath(proxy, @"dataContainerURL");
    if (outBundlePath) *outBundlePath = bundlePath;
    if (outDataPath) *outDataPath = dataPath;
    if (!bundlePath.length || !exeName.length) return nil;
    return [bundlePath stringByAppendingPathComponent:exeName];
}

static BOOL PXCopyDylibToTargetContainer(NSString *sourceDylib, NSString *dataPath, NSString **outTargetDylib, NSError **error) {
    if (!sourceDylib.length || !dataPath.length) {
        if (error) *error = PXDYLError(10, @"Missing dylib or data container path");
        return NO;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [[dataPath stringByAppendingPathComponent:@"Library"] stringByAppendingPathComponent:@"ProjectX"];
    NSError *mkErr = nil;
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&mkErr];
    if (mkErr) {
        if (error) *error = mkErr;
        return NO;
    }
    NSString *dst = [dir stringByAppendingPathComponent:@"ProjectXInject.dylib"];
    [fm removeItemAtPath:dst error:nil];
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:sourceDylib toPath:dst error:&copyErr]) {
        if (error) *error = copyErr ?: PXDYLError(11, @"Failed to copy ProjectXInject.dylib to target container");
        return NO;
    }
    [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:dst error:nil];
    if (outTargetDylib) *outTargetDylib = dst;
    return YES;
}

@implementation PXDYLDLauncher

+ (NSDictionary<NSString *, id> *)launchBundleID:(NSString *)bundleID timeout:(NSTimeInterval)timeout {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    info[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[dyld] launch requested bundleID=%@", bundleID ?: @""];

    if (!bundleID.length) {
        info[@"ok"] = @"NO";
        info[@"error"] = @"Missing bundleID";
        return info;
    }

    NSString *bundlePath = nil;
    NSString *dataPath = nil;
    NSString *executablePath = PXExecutablePathForBundleID(bundleID, &bundlePath, &dataPath);
    info[@"bundlePath"] = bundlePath ?: @"";
    info[@"dataPath"] = dataPath ?: @"";
    info[@"executablePath"] = executablePath ?: @"";
    if (!executablePath.length || !dataPath.length) {
        info[@"ok"] = @"NO";
        info[@"error"] = @"Failed to resolve executable or data container";
        [PXDiagnostics log:@"[dyld] resolve failed info=%@", info];
        return info;
    }

    NSError *snapshotErr = nil;
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:bundleID error:&snapshotErr];
    info[@"snapshotOK"] = snapshot ? @"YES" : @"NO";
    info[@"snapshotError"] = snapshotErr.localizedDescription ?: @"";

    NSString *targetDylib = nil;
    NSError *copyErr = nil;
    BOOL copied = PXCopyDylibToTargetContainer([PXRuntimeSnapshot bundledInjectDylibPath], dataPath, &targetDylib, &copyErr);
    info[@"targetDylib"] = targetDylib ?: @"";
    info[@"copyDylibOK"] = copied ? @"YES" : @"NO";
    info[@"copyDylibError"] = copyErr.localizedDescription ?: @"";
    if (!copied) {
        info[@"ok"] = @"NO";
        info[@"error"] = copyErr.localizedDescription ?: @"Failed to prepare target dylib";
        [PXDiagnostics log:@"[dyld] copy failed info=%@", info];
        return info;
    }

    NSString *markerPath = [dataPath stringByAppendingPathComponent:@"Library/ProjectX/loaded_marker.plist"];
    NSString *dyldLogPath = [dataPath stringByAppendingPathComponent:@"Library/ProjectX/dyldlaunch.log"];
    [[NSFileManager defaultManager] removeItemAtPath:markerPath error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:dyldLogPath error:nil];
    info[@"markerPath"] = markerPath ?: @"";
    info[@"dyldLogPath"] = dyldLogPath ?: @"";

    int exitCode = -999;
    NSString *stdOut = nil;
    NSString *stdErr = nil;
    NSError *rootErr = nil;
    BOOL launched = [[PXRootHelper sharedHelper] runAsRoot:@[@"dyldlaunch", executablePath, targetDylib, dataPath, bundleID, dyldLogPath]
                                              exitCode:&exitCode
                                                stdOut:&stdOut
                                                stdErr:&stdErr
                                                 error:&rootErr];
    info[@"helperOK"] = launched ? @"YES" : @"NO";
    info[@"helperExitCode"] = @(exitCode);
    info[@"helperStdout"] = stdOut ?: @"";
    info[@"helperStderr"] = stdErr ?: @"";
    info[@"helperError"] = rootErr.localizedDescription ?: @"";
    if (!launched) {
        info[@"ok"] = @"NO";
        info[@"error"] = rootErr.localizedDescription ?: @"dyldlaunch helper failed";
        [PXDiagnostics log:@"[dyld] helper failed info=%@", info];
        return info;
    }

    NSTimeInterval deadline = [[NSDate date] timeIntervalSince1970] + MAX(timeout, 1.0);
    NSDictionary *marker = nil;
    while ([[NSDate date] timeIntervalSince1970] < deadline) {
        marker = [NSDictionary dictionaryWithContentsOfFile:markerPath];
        if ([marker isKindOfClass:[NSDictionary class]] && marker.count) break;
        [NSThread sleepForTimeInterval:0.25];
    }
    info[@"markerFound"] = marker.count ? @"YES" : @"NO";
    info[@"marker"] = marker ?: @{};
    NSData *dyldLogData = [NSData dataWithContentsOfFile:dyldLogPath];
    NSString *dyldLog = dyldLogData.length ? [[NSString alloc] initWithData:dyldLogData encoding:NSUTF8StringEncoding] : @"";
    if (dyldLog.length > 12000) dyldLog = [dyldLog substringFromIndex:dyldLog.length - 12000];
    info[@"dyldLog"] = dyldLog ?: @"";
    info[@"ok"] = marker.count ? @"YES" : @"NO";
    if (!marker.count) info[@"error"] = @"DYLD launch returned but ProjectXInject marker was not written";
    [PXDiagnostics log:@"[dyld] launch result=%@", info];
    return info;
}

@end
