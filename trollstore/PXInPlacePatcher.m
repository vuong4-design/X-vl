// PXInPlacePatcher.m - safe in-place injection preparation and restore.

#import "PXInPlacePatcher.h"
#import "PXDiagnostics.h"
#import "PXRuntimeSnapshot.h"

#import <objc/message.h>

NSString * const PXInPlacePatcherErrorDomain = @"PXInPlacePatcherErrorDomain";

static NSString *PXIPBaseDir(void) {
    return @"/var/mobile/Library/ProjectXTroll";
}

static NSString *PXIPStateDir(void) {
    return [PXIPBaseDir() stringByAppendingPathComponent:@"InjectionState"];
}

static NSString *PXIPBackupRoot(void) {
    return [PXIPBaseDir() stringByAppendingPathComponent:@"InjectionBackups"];
}

static NSString *PXIPSafeName(NSString *value) {
    NSMutableString *s = [value ?: @"unknown" mutableCopy];
    [s replaceOccurrencesOfString:@"/" withString:@"_" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@":" withString:@"_" options:0 range:NSMakeRange(0, s.length)];
    return s.length ? [s copy] : @"unknown";
}

static NSString *PXIPFileFingerprint(NSString *path) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSNumber *size = attrs[NSFileSize] ?: @0;
    NSDate *mtime = attrs[NSFileModificationDate];
    NSTimeInterval ts = mtime ? [mtime timeIntervalSince1970] : 0;
    return [NSString stringWithFormat:@"size:%@ mtime:%.0f", size, ts];
}

static id PXIPProxy(NSString *bundleID) {
    Class proxyCls = NSClassFromString(@"LSApplicationProxy");
    SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    return (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
}

static NSString *PXIPURLPath(id proxy, NSString *key) {
    id value = nil;
    @try { value = [proxy valueForKey:key]; } @catch (__unused NSException *e) {}
    if ([value isKindOfClass:[NSURL class]]) return [(NSURL *)value path];
    if ([value isKindOfClass:[NSString class]]) return value;
    return nil;
}

static NSString *PXIPString(id proxy, NSString *key) {
    id value = nil;
    @try { value = [proxy valueForKey:key]; } @catch (__unused NSException *e) {}
    return [value isKindOfClass:[NSString class]] ? value : nil;
}

static NSString *PXIPBundlePath(id proxy) {
    NSString *bundlePath = PXIPURLPath(proxy, @"bundleURL");
    if (bundlePath.length) return bundlePath;
    NSString *containerPath = PXIPURLPath(proxy, @"bundleContainerURL");
    if (!containerPath.length) return nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([containerPath.pathExtension isEqualToString:@"app"] && [fm fileExistsAtPath:containerPath isDirectory:&isDir] && isDir) return containerPath;
    for (NSString *item in [fm contentsOfDirectoryAtPath:containerPath error:nil]) {
        if (![item.pathExtension isEqualToString:@"app"]) continue;
        NSString *candidate = [containerPath stringByAppendingPathComponent:item];
        if ([fm fileExistsAtPath:candidate isDirectory:&isDir] && isDir) return candidate;
    }
    return nil;
}

static NSDictionary *PXIPResolve(NSString *bundleID) {
    id proxy = PXIPProxy(bundleID);
    if (!proxy) return @{};
    NSString *bundlePath = PXIPBundlePath(proxy);
    NSString *exeName = PXIPString(proxy, @"bundleExecutable");
    if (!exeName.length && bundlePath.length) {
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
        exeName = [info[@"CFBundleExecutable"] isKindOfClass:[NSString class]] ? info[@"CFBundleExecutable"] : nil;
    }
    NSString *version = PXIPString(proxy, @"shortVersionString") ?: @"";
    NSString *build = PXIPString(proxy, @"bundleVersion") ?: PXIPString(proxy, @"buildVersionString") ?: @"";
    NSString *executablePath = (bundlePath.length && exeName.length) ? [bundlePath stringByAppendingPathComponent:exeName] : @"";
    NSString *frameworksPath = bundlePath.length ? [bundlePath stringByAppendingPathComponent:@"Frameworks"] : @"";
    return @{
        @"bundleID": bundleID ?: @"",
        @"bundlePath": bundlePath ?: @"",
        @"executableName": exeName ?: @"",
        @"executablePath": executablePath ?: @"",
        @"frameworksPath": frameworksPath ?: @"",
        @"version": version ?: @"",
        @"build": build ?: @"",
    };
}

static NSString *PXIPStatePath(NSString *bundleID) {
    return [[PXIPStateDir() stringByAppendingPathComponent:PXIPSafeName(bundleID)] stringByAppendingPathExtension:@"plist"];
}

static NSDictionary *PXIPReadState(NSString *bundleID) {
    NSDictionary *state = [NSDictionary dictionaryWithContentsOfFile:PXIPStatePath(bundleID)];
    return [state isKindOfClass:[NSDictionary class]] ? state : @{};
}

static BOOL PXIPWriteState(NSString *bundleID, NSDictionary *state) {
    [[NSFileManager defaultManager] createDirectoryAtPath:PXIPStateDir() withIntermediateDirectories:YES attributes:nil error:nil];
    return [state writeToFile:PXIPStatePath(bundleID) atomically:YES];
}

@implementation PXInPlacePatcher

+ (NSDictionary<NSString *,id> *)prepareBundleID:(NSString *)bundleID {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[patch] prepare requested bundleID=%@", bundleID ?: @""];
    @try {
    if (!bundleID.length) {
        result[@"ok"] = @"NO";
        result[@"error"] = @"Missing bundleID";
        return result;
    }

    NSDictionary *resolved = PXIPResolve(bundleID);
    [result addEntriesFromDictionary:resolved];
    [PXDiagnostics log:@"[patch] prepare resolved=%@", resolved];
    NSString *bundlePath = resolved[@"bundlePath"];
    NSString *executablePath = resolved[@"executablePath"];
    NSString *frameworksPath = resolved[@"frameworksPath"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (!bundlePath.length || !executablePath.length || ![fm fileExistsAtPath:executablePath]) {
        result[@"ok"] = @"NO";
        result[@"error"] = @"Failed to resolve target executable";
        [PXDiagnostics log:@"[patch] prepare resolve failed result=%@", result];
        return result;
    }

    NSError *snapshotErr = nil;
    [PXDiagnostics log:@"[patch] prepare exporting snapshot"];
    NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:bundleID error:&snapshotErr];
    result[@"snapshotOK"] = snapshot ? @"YES" : @"NO";
    result[@"snapshotError"] = snapshotErr.localizedDescription ?: @"";

    [PXDiagnostics log:@"[patch] prepare fingerprint executable=%@", executablePath ?: @""];
    NSString *safeVersion = PXIPSafeName([NSString stringWithFormat:@"%@-%@", resolved[@"version"] ?: @"", resolved[@"build"] ?: @""]);
    NSString *backupDir = [[PXIPBackupRoot() stringByAppendingPathComponent:PXIPSafeName(bundleID)] stringByAppendingPathComponent:safeVersion];
    NSString *backupExecutable = [backupDir stringByAppendingPathComponent:[executablePath lastPathComponent]];
    NSString *backupMetadata = [backupDir stringByAppendingPathComponent:@"metadata.plist"];
    NSString *originalHash = PXIPFileFingerprint(executablePath);
    [PXDiagnostics log:@"[patch] prepare fingerprint=%@", originalHash ?: @""];
    NSError *mkErr = nil;
    [PXDiagnostics log:@"[patch] prepare create backupDir=%@", backupDir ?: @""];
    [fm createDirectoryAtPath:backupDir withIntermediateDirectories:YES attributes:nil error:&mkErr];
    if (mkErr) {
        result[@"ok"] = @"NO";
        result[@"error"] = mkErr.localizedDescription ?: @"Failed to create backup directory";
        return result;
    }
    if (![fm fileExistsAtPath:backupExecutable]) {
        [PXDiagnostics log:@"[patch] prepare copying executable to backup=%@", backupExecutable ?: @""];
        NSError *copyErr = nil;
        if (![fm copyItemAtPath:executablePath toPath:backupExecutable error:&copyErr]) {
            result[@"ok"] = @"NO";
            result[@"error"] = copyErr.localizedDescription ?: @"Failed to backup executable";
            return result;
        }
        [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:backupExecutable error:nil];
    } else {
        [PXDiagnostics log:@"[patch] prepare backup already exists=%@", backupExecutable ?: @""];
    }

    [PXDiagnostics log:@"[patch] prepare create frameworksPath=%@", frameworksPath ?: @""];
    [fm createDirectoryAtPath:frameworksPath withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *targetDylib = [frameworksPath stringByAppendingPathComponent:@"ProjectXInject.dylib"];
    [fm removeItemAtPath:targetDylib error:nil];
    NSError *dylibCopyErr = nil;
    [PXDiagnostics log:@"[patch] prepare copying dylib source=%@ target=%@", [PXRuntimeSnapshot bundledInjectDylibPath] ?: @"", targetDylib ?: @""];
    if (![fm copyItemAtPath:[PXRuntimeSnapshot bundledInjectDylibPath] toPath:targetDylib error:&dylibCopyErr]) {
        result[@"ok"] = @"NO";
        result[@"error"] = dylibCopyErr.localizedDescription ?: @"Failed to copy ProjectXInject.dylib into target bundle";
        return result;
    }
    [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:targetDylib error:nil];

    NSMutableDictionary *state = [NSMutableDictionary dictionaryWithDictionary:resolved];
    state[@"mode"] = @"inplace-prepared";
    state[@"preparedAt"] = @([[NSDate date] timeIntervalSince1970]);
    state[@"backupDir"] = backupDir ?: @"";
    state[@"backupExecutable"] = backupExecutable ?: @"";
    state[@"targetDylib"] = targetDylib ?: @"";
    state[@"originalExecutableHash"] = originalHash ?: @"";
    state[@"loadCommandInserted"] = @"NO";
    state[@"dylibLoadPath"] = @"@executable_path/Frameworks/ProjectXInject.dylib";
    [PXDiagnostics log:@"[patch] prepare writing backup metadata=%@", backupMetadata ?: @""];
    [state writeToFile:backupMetadata atomically:YES];
    [PXDiagnostics log:@"[patch] prepare writing state=%@", PXIPStatePath(bundleID) ?: @""];
    BOOL stateOK = PXIPWriteState(bundleID, state);

    result[@"ok"] = stateOK ? @"YES" : @"NO";
    result[@"error"] = stateOK ? @"" : @"Failed to write injection state";
    result[@"backupDir"] = backupDir ?: @"";
    result[@"backupExecutable"] = backupExecutable ?: @"";
    result[@"targetDylib"] = targetDylib ?: @"";
    result[@"originalExecutableHash"] = originalHash ?: @"";
    result[@"statePath"] = PXIPStatePath(bundleID);
    [PXDiagnostics log:@"[patch] prepare result=%@", result];
    return result;
    } @catch (NSException *ex) {
        result[@"ok"] = @"NO";
        result[@"error"] = [NSString stringWithFormat:@"Exception during prepare: %@ %@", ex.name ?: @"", ex.reason ?: @""];
        [PXDiagnostics log:@"[patch] prepare exception=%@", result[@"error"]];
        return result;
    }
}

+ (NSDictionary<NSString *,id> *)restoreBundleID:(NSString *)bundleID {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[patch] restore requested bundleID=%@", bundleID ?: @""];
    @try {
    NSDictionary *state = PXIPReadState(bundleID);
    [result setObject:state ?: @{} forKey:@"state"];
    NSString *executablePath = state[@"executablePath"];
    NSString *backupExecutable = state[@"backupExecutable"];
    NSString *targetDylib = state[@"targetDylib"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (!executablePath.length || !backupExecutable.length || ![fm fileExistsAtPath:backupExecutable]) {
        result[@"ok"] = @"NO";
        result[@"error"] = @"No backup executable found for this bundle";
        return result;
    }
    [fm removeItemAtPath:executablePath error:nil];
    NSError *copyErr = nil;
    if (![fm copyItemAtPath:backupExecutable toPath:executablePath error:&copyErr]) {
        result[@"ok"] = @"NO";
        result[@"error"] = copyErr.localizedDescription ?: @"Failed to restore executable";
        return result;
    }
    [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:executablePath error:nil];
    if (targetDylib.length) [fm removeItemAtPath:targetDylib error:nil];
    [fm removeItemAtPath:PXIPStatePath(bundleID) error:nil];
    result[@"ok"] = @"YES";
    result[@"error"] = @"";
    [PXDiagnostics log:@"[patch] restore result=%@", result];
    return result;
    } @catch (NSException *ex) {
        result[@"ok"] = @"NO";
        result[@"error"] = [NSString stringWithFormat:@"Exception during restore: %@ %@", ex.name ?: @"", ex.reason ?: @""];
        [PXDiagnostics log:@"[patch] restore exception=%@", result[@"error"]];
        return result;
    }
}

+ (NSDictionary<NSString *,id> *)statusForBundleID:(NSString *)bundleID {
    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:PXIPResolve(bundleID)];
    NSDictionary *state = PXIPReadState(bundleID);
    NSFileManager *fm = [NSFileManager defaultManager];
    result[@"bundleID"] = bundleID ?: @"";
    result[@"statePath"] = PXIPStatePath(bundleID ?: @"");
    result[@"stateExists"] = [fm fileExistsAtPath:PXIPStatePath(bundleID ?: @"")] ? @"YES" : @"NO";
    result[@"state"] = state ?: @{};
    NSString *targetDylib = state[@"targetDylib"];
    result[@"targetDylibExists"] = (targetDylib.length && [fm fileExistsAtPath:targetDylib]) ? @"YES" : @"NO";
    return result;
}

@end
