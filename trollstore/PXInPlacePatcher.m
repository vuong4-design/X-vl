// PXInPlacePatcher.m - safe in-place injection preparation and restore.

#import "PXInPlacePatcher.h"
#import "PXDiagnostics.h"
#import "PXEntitlements.h"
#import "PXMachOInjector.h"
#import "PXRootHelper.h"
#import "PXRuntimeSnapshot.h"
#import "common/PXProcessKiller.h"

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

static NSString *PXIPFilePermissions(NSString *path) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSNumber *perms = attrs[NSFilePosixPermissions];
    return perms ? [NSString stringWithFormat:@"%04o", perms.unsignedShortValue & 07777] : @"";
}

static void PXIPAddLoadCommandStatus(NSMutableDictionary *result, NSString *keyPrefix, NSString *path, NSString *dylibLoadPath) {
    BOOL exists = path.length && [[NSFileManager defaultManager] fileExistsAtPath:path];
    result[[keyPrefix stringByAppendingString:@"Exists"]] = exists ? @"YES" : @"NO";
    result[[keyPrefix stringByAppendingString:@"Path"]] = path ?: @"";
    result[[keyPrefix stringByAppendingString:@"Fingerprint"]] = exists ? (PXIPFileFingerprint(path) ?: @"") : @"";
    result[[keyPrefix stringByAppendingString:@"Permissions"]] = exists ? PXIPFilePermissions(path) : @"";
    if (!exists || !dylibLoadPath.length) {
        result[[keyPrefix stringByAppendingString:@"HasLoadCommand"]] = @"NO";
        result[[keyPrefix stringByAppendingString:@"LoadCommandError"]] = exists ? @"Missing dylib load path" : @"File missing";
        return;
    }
    NSError *err = nil;
    BOOL has = [PXMachOInjector hasDylibLoadCommand:dylibLoadPath inMachOAtPath:path error:&err];
    result[[keyPrefix stringByAppendingString:@"HasLoadCommand"]] = has ? @"YES" : @"NO";
    result[[keyPrefix stringByAppendingString:@"LoadCommandError"]] = has ? @"" : (err.localizedDescription ?: @"");

    NSError *sigErr = nil;
    NSDictionary *sig = [PXMachOInjector codeSignatureSummaryForMachOAtPath:path error:&sigErr];
    result[[keyPrefix stringByAppendingString:@"CodeSignature"]] = sig ?: @{};
    result[[keyPrefix stringByAppendingString:@"CodeSignatureError"]] = sigErr.localizedDescription ?: @"";
}

static void PXIPAddCodeSignatureOnlyStatus(NSMutableDictionary *result, NSString *keyPrefix, NSString *path) {
    BOOL exists = path.length && [[NSFileManager defaultManager] fileExistsAtPath:path];
    result[[keyPrefix stringByAppendingString:@"Exists"]] = exists ? @"YES" : @"NO";
    result[[keyPrefix stringByAppendingString:@"Path"]] = path ?: @"";
    result[[keyPrefix stringByAppendingString:@"Fingerprint"]] = exists ? (PXIPFileFingerprint(path) ?: @"") : @"";
    result[[keyPrefix stringByAppendingString:@"Permissions"]] = exists ? PXIPFilePermissions(path) : @"";
    if (!exists) {
        result[[keyPrefix stringByAppendingString:@"CodeSignature"]] = @{};
        result[[keyPrefix stringByAppendingString:@"CodeSignatureError"]] = @"File missing";
        return;
    }
    NSError *sigErr = nil;
    NSDictionary *sig = [PXMachOInjector codeSignatureSummaryForMachOAtPath:path error:&sigErr];
    result[[keyPrefix stringByAppendingString:@"CodeSignature"]] = sig ?: @{};
    result[[keyPrefix stringByAppendingString:@"CodeSignatureError"]] = sigErr.localizedDescription ?: @"";
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

static BOOL PXIPOpenBundleID(NSString *bundleID) {
    @try {
        Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
        id ws = [wsCls respondsToSelector:@selector(defaultWorkspace)] ? ((id (*)(id, SEL))objc_msgSend)(wsCls, @selector(defaultWorkspace)) : nil;
        SEL openSel = NSSelectorFromString(@"openApplicationWithBundleID:");
        if (ws && [ws respondsToSelector:openSel]) {
            return ((BOOL (*)(id, SEL, id))objc_msgSend)(ws, openSel, bundleID);
        }
    } @catch (__unused NSException *e) {
    }
    return NO;
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

static BOOL PXIPRunRoot(NSArray<NSString *> *argv, NSString **outError) {
    int exitCode = -999;
    NSString *stdOut = nil;
    NSString *stdErr = nil;
    NSError *err = nil;
    BOOL ok = [[PXRootHelper sharedHelper] runAsRoot:argv exitCode:&exitCode stdOut:&stdOut stdErr:&stdErr error:&err];
    if (!ok && outError) {
        *outError = err.localizedDescription ?: stdErr ?: [NSString stringWithFormat:@"root helper failed exit=%d", exitCode];
    }
    return ok;
}

static NSDictionary<NSString *, id> *PXIPRunRootDetailed(NSArray<NSString *> *argv) {
    int exitCode = -999;
    NSString *stdOut = nil;
    NSString *stdErr = nil;
    NSError *err = nil;
    BOOL ok = [[PXRootHelper sharedHelper] runAsRoot:argv exitCode:&exitCode stdOut:&stdOut stdErr:&stdErr error:&err];
    return @{
        @"ok": ok ? @"YES" : @"NO",
        @"exitCode": @(exitCode),
        @"stdout": stdOut ?: @"",
        @"stderr": stdErr ?: @"",
        @"error": err.localizedDescription ?: @"",
    };
}

static NSDictionary<NSString *, id> *PXIPTrySignPath(NSString *path, NSString *entitlementsPath) {
    if (!path.length) return @{@"ok": @"NO", @"error": @"Missing path"};
    NSDictionary *probe = PXIPRunRootDetailed(@[@"ldidprobe"]);
    if (![probe[@"ok"] isEqual:@"YES"]) {
        return @{
            @"ok": @"NO",
            @"status": @"ldid-unavailable",
            @"probe": probe ?: @{},
        };
    }
    NSMutableArray<NSString *> *argv = [NSMutableArray arrayWithObjects:@"ldidsign", path, nil];
    if (entitlementsPath.length && [[NSFileManager defaultManager] fileExistsAtPath:entitlementsPath]) {
        [argv addObject:entitlementsPath];
    }
    NSDictionary *sign = PXIPRunRootDetailed(argv);
    return @{
        @"ok": [sign[@"ok"] isEqual:@"YES"] ? @"YES" : @"NO",
        @"status": [sign[@"ok"] isEqual:@"YES"] ? @"ldid-signed" : @"ldid-failed",
        @"entitlementsPath": entitlementsPath ?: @"",
        @"probe": probe ?: @{},
        @"sign": sign ?: @{},
    };
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
    NSString *entitlementsPath = [backupDir stringByAppendingPathComponent:@"original_entitlements.plist"];
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

    NSError *entErr = nil;
    NSData *entData = [PXEntitlements entitlementsDataForBinaryAtPath:backupExecutable error:&entErr];
    BOOL entWriteOK = entData.length ? [entData writeToFile:entitlementsPath atomically:YES] : NO;
    result[@"originalEntitlementsPath"] = entWriteOK ? entitlementsPath : @"";
    result[@"originalEntitlementsOK"] = entWriteOK ? @"YES" : @"NO";
    result[@"originalEntitlementsError"] = entWriteOK ? @"" : (entErr.localizedDescription ?: @"No entitlements data");
    [PXDiagnostics log:@"[patch] prepare entitlements ok=%@ path=%@ error=%@", result[@"originalEntitlementsOK"], result[@"originalEntitlementsPath"], result[@"originalEntitlementsError"]];

    [PXDiagnostics log:@"[patch] prepare create frameworksPath=%@", frameworksPath ?: @""];
    NSString *rootErr = nil;
    if (!PXIPRunRoot(@[@"mkdir", frameworksPath], &rootErr)) {
        result[@"ok"] = @"NO";
        result[@"error"] = rootErr ?: @"Failed to create Frameworks directory via root helper";
        return result;
    }
    NSString *targetDylib = [frameworksPath stringByAppendingPathComponent:@"ProjectXInject.dylib"];
    [PXDiagnostics log:@"[patch] prepare copying dylib source=%@ target=%@", [PXRuntimeSnapshot bundledInjectDylibPath] ?: @"", targetDylib ?: @""];
    rootErr = nil;
    if (!PXIPRunRoot(@[@"cpfile", [PXRuntimeSnapshot bundledInjectDylibPath], targetDylib], &rootErr)) {
        result[@"ok"] = @"NO";
        result[@"error"] = rootErr ?: @"Failed to copy ProjectXInject.dylib into target bundle";
        return result;
    }

    NSMutableDictionary *state = [NSMutableDictionary dictionaryWithDictionary:resolved];
    state[@"mode"] = @"inplace-prepared";
    state[@"preparedAt"] = @([[NSDate date] timeIntervalSince1970]);
    state[@"backupDir"] = backupDir ?: @"";
    state[@"backupExecutable"] = backupExecutable ?: @"";
    state[@"targetDylib"] = targetDylib ?: @"";
    state[@"originalExecutableHash"] = originalHash ?: @"";
    state[@"originalEntitlementsPath"] = entWriteOK ? entitlementsPath : @"";
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

+ (NSDictionary<NSString *,id> *)patchPreparedCopyBundleID:(NSString *)bundleID {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[patch] patch prepared copy requested bundleID=%@", bundleID ?: @""];
    @try {
        NSDictionary *state = PXIPReadState(bundleID);
        result[@"state"] = state ?: @{};
        NSString *backupExecutable = state[@"backupExecutable"];
        NSString *backupDir = state[@"backupDir"];
        NSString *dylibLoadPath = state[@"dylibLoadPath"] ?: @"@executable_path/Frameworks/ProjectXInject.dylib";
        if (!backupExecutable.length || ![[NSFileManager defaultManager] fileExistsAtPath:backupExecutable]) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"No prepared backup executable found. Run Prepare In-Place first.";
            return result;
        }
        NSString *patchedCopy = [backupDir stringByAppendingPathComponent:[[backupExecutable lastPathComponent] stringByAppendingString:@".patched"]];
        [[NSFileManager defaultManager] removeItemAtPath:patchedCopy error:nil];
        NSError *copyErr = nil;
        if (![[NSFileManager defaultManager] copyItemAtPath:backupExecutable toPath:patchedCopy error:&copyErr]) {
            result[@"ok"] = @"NO";
            result[@"error"] = copyErr.localizedDescription ?: @"Failed to create patched copy";
            return result;
        }
        [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:patchedCopy error:nil];
        NSError *patchErr = nil;
        [PXDiagnostics log:@"[patch] patching prepared copy=%@ loadPath=%@", patchedCopy ?: @"", dylibLoadPath ?: @""];
        BOOL patched = [PXMachOInjector insertDylibLoadCommand:dylibLoadPath intoMachOAtPath:patchedCopy error:&patchErr];
        result[@"ok"] = patched ? @"YES" : @"NO";
        result[@"error"] = patched ? @"" : (patchErr.localizedDescription ?: @"Mach-O patch failed");
        result[@"patchedCopy"] = patchedCopy ?: @"";
        result[@"dylibLoadPath"] = dylibLoadPath ?: @"";
        PXIPAddLoadCommandStatus(result, @"patchedCopy", patchedCopy, dylibLoadPath);
        if (patched) {
            NSMutableDictionary *newState = [NSMutableDictionary dictionaryWithDictionary:state ?: @{}];
            newState[@"patchedCopy"] = patchedCopy ?: @"";
            newState[@"patchedCopyReady"] = @"YES";
            newState[@"patchedCopyHasLoadCommand"] = result[@"patchedCopyHasLoadCommand"] ?: @"NO";
            newState[@"patchedCopyPreparedAt"] = @([[NSDate date] timeIntervalSince1970]);
            PXIPWriteState(bundleID, newState);
        }
        [PXDiagnostics log:@"[patch] patch prepared copy result=%@", result];
        return result;
    } @catch (NSException *ex) {
        result[@"ok"] = @"NO";
        result[@"error"] = [NSString stringWithFormat:@"Exception during patch prepared copy: %@ %@", ex.name ?: @"", ex.reason ?: @""];
        [PXDiagnostics log:@"[patch] patch prepared copy exception=%@", result[@"error"]];
        return result;
    }
}

+ (NSDictionary<NSString *,id> *)installPatchedCopyBundleID:(NSString *)bundleID {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[patch] install patched copy requested bundleID=%@", bundleID ?: @""];
    @try {
        NSDictionary *state = PXIPReadState(bundleID);
        result[@"state"] = state ?: @{};
        NSString *patchedCopy = state[@"patchedCopy"];
        NSString *executablePath = state[@"executablePath"];
        NSString *executableName = state[@"executableName"];
        NSString *dylibLoadPath = state[@"dylibLoadPath"] ?: @"@executable_path/Frameworks/ProjectXInject.dylib";
        NSString *entitlementsPath = state[@"originalEntitlementsPath"];
        if (!patchedCopy.length || ![[NSFileManager defaultManager] fileExistsAtPath:patchedCopy]) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"No patched copy found. Run Patch Prepared Copy first.";
            return result;
        }
        if (!executablePath.length) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"Missing executable path in state";
            return result;
        }

        if (executableName.length) {
            [PXDiagnostics log:@"[patch] killing target process before install name=%@", executableName];
            PXKillallTermThenKill(executableName, 0.5);
            PXWaitForProcessesToExit(@[executableName], 2.0);
        }

        NSString *rootErr = nil;
        [PXDiagnostics log:@"[patch] installing patched copy source=%@ executable=%@", patchedCopy ?: @"", executablePath ?: @""];
        if (!PXIPRunRoot(@[@"cpfile", patchedCopy, executablePath], &rootErr)) {
            result[@"ok"] = @"NO";
            result[@"error"] = rootErr ?: @"Failed to install patched executable";
            return result;
        }

        PXIPAddLoadCommandStatus(result, @"patchedCopy", patchedCopy, dylibLoadPath);
        PXIPAddLoadCommandStatus(result, @"installedExecutable", executablePath, dylibLoadPath);

        NSDictionary *signExecutable = PXIPTrySignPath(executablePath, entitlementsPath);
        result[@"signExecutable"] = signExecutable ?: @{};
        if ([signExecutable[@"ok"] isEqual:@"YES"]) {
            PXIPAddLoadCommandStatus(result, @"installedExecutableAfterSign", executablePath, dylibLoadPath);
        }

        NSMutableDictionary *newState = [NSMutableDictionary dictionaryWithDictionary:state ?: @{}];
        newState[@"mode"] = [signExecutable[@"ok"] isEqual:@"YES"] ? @"inplace-installed-signed" : @"inplace-installed-unsigned";
        newState[@"installedPatchedCopy"] = @"YES";
        newState[@"installedExecutableHasLoadCommand"] = result[@"installedExecutableHasLoadCommand"] ?: @"NO";
        newState[@"installedExecutableFingerprint"] = result[@"installedExecutableFingerprint"] ?: @"";
        newState[@"signatureStatus"] = signExecutable[@"status"] ?: @"not-resigned";
        newState[@"installedAt"] = @([[NSDate date] timeIntervalSince1970]);
        PXIPWriteState(bundleID, newState);

        NSDictionary *runtimeStatus = [PXRuntimeSnapshot statusForBundleID:bundleID];
        NSString *targetMarkerPath = runtimeStatus[@"targetMarkerPath"];
        if (targetMarkerPath.length) [[NSFileManager defaultManager] removeItemAtPath:targetMarkerPath error:nil];
        BOOL opened = PXIPOpenBundleID(bundleID);
        result[@"openApplication"] = opened ? @"YES" : @"NO";
        result[@"targetMarkerPath"] = targetMarkerPath ?: @"";
        if (executableName.length) {
            result[@"processRunningAfterOpen"] = PXProcessIsRunning(executableName) ? @"YES" : @"NO";
        }

        NSDictionary *marker = nil;
        NSTimeInterval deadline = [[NSDate date] timeIntervalSince1970] + 6.0;
        while ([[NSDate date] timeIntervalSince1970] < deadline) {
            marker = targetMarkerPath.length ? [NSDictionary dictionaryWithContentsOfFile:targetMarkerPath] : nil;
            if ([marker isKindOfClass:[NSDictionary class]] && marker.count) break;
            [NSThread sleepForTimeInterval:0.25];
        }
        result[@"markerFound"] = marker.count ? @"YES" : @"NO";
        result[@"marker"] = marker ?: @{};
        result[@"ok"] = @"YES";
        result[@"error"] = marker.count ? @"" : @"Patched executable installed, but marker was not written. App may need re-signing or may have crashed.";
        [PXDiagnostics log:@"[patch] install patched copy result=%@", result];
        return result;
    } @catch (NSException *ex) {
        result[@"ok"] = @"NO";
        result[@"error"] = [NSString stringWithFormat:@"Exception during install patched copy: %@ %@", ex.name ?: @"", ex.reason ?: @""];
        [PXDiagnostics log:@"[patch] install patched copy exception=%@", result[@"error"]];
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
    NSString *rootErr = nil;
    if (!PXIPRunRoot(@[@"cpfile", backupExecutable, executablePath], &rootErr)) {
        result[@"ok"] = @"NO";
        result[@"error"] = rootErr ?: @"Failed to restore executable";
        return result;
    }
    if (targetDylib.length) {
        rootErr = nil;
        if (!PXIPRunRoot(@[@"rm", targetDylib], &rootErr)) {
            [PXDiagnostics log:@"[patch] restore warning remove dylib failed=%@", rootErr ?: @""];
        }
    }
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
    result[@"targetDylibPath"] = targetDylib ?: @"";
    result[@"targetDylibFingerprint"] = (targetDylib.length && [fm fileExistsAtPath:targetDylib]) ? (PXIPFileFingerprint(targetDylib) ?: @"") : @"";
    result[@"targetDylibPermissions"] = (targetDylib.length && [fm fileExistsAtPath:targetDylib]) ? PXIPFilePermissions(targetDylib) : @"";
    PXIPAddCodeSignatureOnlyStatus(result, @"targetDylib", targetDylib);
    NSString *patchedCopy = state[@"patchedCopy"];
    result[@"patchedCopyExists"] = (patchedCopy.length && [fm fileExistsAtPath:patchedCopy]) ? @"YES" : @"NO";
    NSString *dylibLoadPath = state[@"dylibLoadPath"] ?: @"@executable_path/Frameworks/ProjectXInject.dylib";
    PXIPAddLoadCommandStatus(result, @"patchedCopy", patchedCopy, dylibLoadPath);
    NSString *executablePath = result[@"executablePath"];
    if (![executablePath isKindOfClass:[NSString class]] || !executablePath.length) executablePath = state[@"executablePath"];
    PXIPAddLoadCommandStatus(result, @"installedExecutable", executablePath, dylibLoadPath);
    return result;
}

@end
