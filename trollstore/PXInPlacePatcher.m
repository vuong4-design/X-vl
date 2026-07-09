// PXInPlacePatcher.m - safe in-place injection preparation and restore.

#import "PXInPlacePatcher.h"
#import "PXDiagnostics.h"
#import "PXEntitlements.h"
#import "PXMachOInjector.h"
#import "PXRootHelper.h"
#import "PXRuntimeSnapshot.h"
#import "common/PXProcessKiller.h"

#import <objc/message.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <zlib.h>

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

static NSString *PXIPStagingRoot(void) {
    return [PXIPBaseDir() stringByAppendingPathComponent:@"AppStaging"];
}

static NSString *PXIPPatchedAppsRoot(void) {
    return [PXIPBaseDir() stringByAppendingPathComponent:@"PatchedApps"];
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

static NSDictionary<NSString *, id> *PXIPSafeSysctlByNameOptions(void) {
    return @{@"CHookTestMode": @"sysctlbyname-safe",
             @"EnableSysctlByNameHook": @YES,
             @"EnableSysctlHook": @YES,
             @"EnableUnameHook": @YES,
             @"EnableDlsymHook": @NO,
             @"EnableDeviceMetricsHook": @NO,
             @"EnableNetworkHook": @NO,
             @"EnableCarrierHook": @NO,
             @"EnablePrivateWiFiHook": @NO,
             @"EnableMobileGestaltHook": @YES,
             @"EnableSysctlName_hw.machine": @YES,
             @"EnableSysctlName_hw.model": @YES,
             @"EnableSysctlName_kern.osversion": @YES,
             @"EnableSysctlName_kern.version": @YES};
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

static NSString *PXIPResolveLoadCommandPathWithLoader(NSString *loadName, NSString *executablePath, NSString *frameworksPath, NSString *loaderPath) {
    if (!loadName.length) return nil;
    NSString *resolved = loadName;
    if ([resolved hasPrefix:@"@executable_path/"]) {
        NSString *exeDir = [executablePath stringByDeletingLastPathComponent];
        resolved = [exeDir stringByAppendingPathComponent:[resolved substringFromIndex:@"@executable_path/".length]];
    } else if ([resolved hasPrefix:@"@loader_path/"]) {
        NSString *loaderDir = loaderPath.length ? [loaderPath stringByDeletingLastPathComponent] : [executablePath stringByDeletingLastPathComponent];
        resolved = [loaderDir stringByAppendingPathComponent:[resolved substringFromIndex:@"@loader_path/".length]];
    } else if ([resolved hasPrefix:@"@rpath/"]) {
        resolved = [frameworksPath stringByAppendingPathComponent:[resolved substringFromIndex:@"@rpath/".length]];
    } else if (![resolved isAbsolutePath]) {
        return nil;
    }
    return [[resolved stringByStandardizingPath] copy];
}

static NSString *PXIPResolveLoadCommandPath(NSString *loadName, NSString *executablePath, NSString *frameworksPath) {
    return PXIPResolveLoadCommandPathWithLoader(loadName, executablePath, frameworksPath, executablePath);
}

static NSString *PXIPCanonicalPathKey(NSString *path) {
    NSString *rawPath = path ? path : @"";
    NSString *key = [[rawPath stringByStandardizingPath] copy];
    if ([key hasPrefix:@"/private/var/"]) {
        key = [@"/var/" stringByAppendingString:[key substringFromIndex:@"/private/var/".length]];
    }
    return key ?: @"";
}

static NSString *PXIPFrameworkRelativeLoadKey(NSString *loadName) {
    if (!loadName.length) return @"";
    NSString *s = loadName;
    if ([s hasPrefix:@"@rpath/"]) return [s substringFromIndex:@"@rpath/".length];
    if ([s hasPrefix:@"@executable_path/Frameworks/"]) return [s substringFromIndex:@"@executable_path/Frameworks/".length];
    if ([s hasPrefix:@"@loader_path/Frameworks/"]) return [s substringFromIndex:@"@loader_path/Frameworks/".length];
    NSRange r = [s rangeOfString:@"/Frameworks/" options:NSBackwardsSearch];
    if (r.location != NSNotFound) return [s substringFromIndex:r.location + r.length];
    return @"";
}

static void PXIPReturnCarrierResult(NSDictionary *result) {
    [PXDiagnostics log:@"[carrier] patch result=%@", result ?: @{}];
}

static NSDictionary *PXIPCarrierFail(NSMutableDictionary *result, NSString *message) {
    result[@"ok"] = @"NO";
    result[@"error"] = message ?: @"Carrier patch failed";
    PXIPReturnCarrierResult(result);
    return result;
}

static NSString *PXIPTeamIDFromExecutable(NSString *executablePath) {
    NSError *err = nil;
    NSDictionary *entitlements = [PXEntitlements entitlementsForBinaryAtPath:executablePath error:&err];
    NSString *appIdentifier = [entitlements[@"application-identifier"] isKindOfClass:[NSString class]] ? entitlements[@"application-identifier"] : nil;
    NSArray<NSString *> *parts = [appIdentifier componentsSeparatedByString:@"."];
    NSString *teamID = parts.count > 1 ? parts.firstObject : nil;
    if (teamID.length) return teamID;
    NSString *teamIdentifier = [entitlements[@"com.apple.developer.team-identifier"] isKindOfClass:[NSString class]] ? entitlements[@"com.apple.developer.team-identifier"] : nil;
    return teamIdentifier.length ? teamIdentifier : nil;
}

static NSDictionary<NSString *, id> *PXIPTryCoreTrustBypass(NSString *path, NSString *teamID) {
    if (!path.length || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return @{@"ok": @"NO", @"status": @"missing-file", @"path": path ?: @"", @"teamID": teamID ?: @""};
    }
    if (!teamID.length) {
        return @{@"ok": @"NO", @"status": @"missing-team-id", @"path": path ?: @"", @"teamID": @""};
    }
    NSDictionary *run = PXIPRunRootDetailed(@[@"ctbypass", path, teamID]);
    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:run ?: @{}];
    result[@"path"] = path ?: @"";
    result[@"teamID"] = teamID ?: @"";
    result[@"status"] = [result[@"ok"] isEqual:@"YES"] ? @"ct-bypass-applied" : @"ct-bypass-failed";
    return result;
}

static unsigned long long PXIPFileInfoSize(NSDictionary *fileInfo) {
    NSString *stdoutText = [fileInfo[@"stdout"] isKindOfClass:[NSString class]] ? fileInfo[@"stdout"] : @"";
    for (NSString *line in [stdoutText componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        if ([line hasPrefix:@"size="]) {
            return (unsigned long long)[[line substringFromIndex:@"size=".length] longLongValue];
        }
    }
    return 0;
}

static BOOL PXIPIsIgnoredCarrierName(NSString *name) {
    NSString *lower = name.lowercaseString ?: @"";
    NSArray<NSString *> *ignored = @[
        @"projectxinject.dylib",
        @"cydiasubstrate",
        @"cydiasubstrate.framework",
        @"ellekit",
        @"ellekit.framework",
        @"libsubstrate.dylib",
        @"libsubstitute.dylib",
        @"libellekit.dylib",
    ];
    return [ignored containsObject:lower];
}

static BOOL PXIPIsSwiftRuntimeName(NSString *name) {
    NSString *rawName = name ? name : @"";
    return [rawName.lowercaseString hasPrefix:@"libswift"];
}

static BOOL PXIPIsSystemLoadName(NSString *loadName) {
    NSString *s = loadName ?: @"";
    return [s hasPrefix:@"/System/Library/"] || [s hasPrefix:@"/usr/lib/"];
}

static NSString *PXIPCarrierCategory(BOOL linked, BOOL dependency, BOOL swiftRuntime, BOOL weakMissing, BOOL extensionOnly, BOOL eligible) {
    if (weakMissing) return @"weak-missing-load";
    if (extensionOnly) return @"extension-only";
    if (linked && swiftRuntime) return @"swift-runtime-linked";
    if (linked) return @"linked-from-main";
    if (dependency) return @"dependency-chain";
    if (swiftRuntime) return @"swift-runtime-unlinked";
    return eligible ? @"fallback-unlinked" : @"rejected";
}

static BOOL PXIPLooksLikeMachO(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:nil];
    if (data.length < sizeof(uint32_t)) return NO;
    uint32_t magic = 0;
    [data getBytes:&magic length:sizeof(magic)];
    return magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == FAT_MAGIC || magic == FAT_CIGAM;
}

static void PXIPWriteLE16(NSMutableData *data, uint16_t value) {
    uint8_t b[2] = { (uint8_t)(value & 0xff), (uint8_t)((value >> 8) & 0xff) };
    [data appendBytes:b length:sizeof(b)];
}

static void PXIPWriteLE32(NSMutableData *data, uint32_t value) {
    uint8_t b[4] = { (uint8_t)(value & 0xff), (uint8_t)((value >> 8) & 0xff), (uint8_t)((value >> 16) & 0xff), (uint8_t)((value >> 24) & 0xff) };
    [data appendBytes:b length:sizeof(b)];
}

static uint32_t PXIPDOSDateTime(NSDate *date) {
    NSDateComponents *c = [[NSCalendar calendarWithIdentifier:NSCalendarIdentifierGregorian] components:NSCalendarUnitYear | NSCalendarUnitMonth | NSCalendarUnitDay | NSCalendarUnitHour | NSCalendarUnitMinute | NSCalendarUnitSecond fromDate:date ?: [NSDate date]];
    NSInteger year = MAX(1980, c.year);
    uint32_t dosTime = (uint32_t)((c.hour << 11) | (c.minute << 5) | (c.second / 2));
    uint32_t dosDate = (uint32_t)(((year - 1980) << 9) | (c.month << 5) | c.day);
    return (dosDate << 16) | dosTime;
}

static BOOL PXIPEnumerateFiles(NSString *root, NSMutableArray<NSString *> *relativeFiles, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:root];
    NSString *relativePath = nil;
    while ((relativePath = [en nextObject])) {
        NSString *fullPath = [root stringByAppendingPathComponent:relativePath];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        NSString *type = attrs[NSFileType];
        if (![type isEqualToString:NSFileTypeRegular] && ![type isEqualToString:NSFileTypeSymbolicLink]) continue;
        [relativeFiles addObject:relativePath];
    }
    [relativeFiles sortUsingSelector:@selector(compare:)];
    if (!relativeFiles.count && error) {
        *error = [NSError errorWithDomain:PXInPlacePatcherErrorDomain
                                     code:82
                                 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"No files found while packaging %@", root ?: @""]}];
    }
    return relativeFiles.count > 0;
}

static BOOL PXIPCreateStoredZip(NSString *sourceRoot, NSString *zipPath, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSString *> *relativeFiles = [NSMutableArray array];
    NSError *enumErr = nil;
    if (!PXIPEnumerateFiles(sourceRoot, relativeFiles, &enumErr)) {
        if (error) *error = enumErr;
        return NO;
    }

    NSMutableData *zip = [NSMutableData data];
    NSMutableData *central = [NSMutableData data];
    for (NSString *relativePath in relativeFiles) {
        NSString *fullPath = [sourceRoot stringByAppendingPathComponent:relativePath];
        NSData *fileData = [NSData dataWithContentsOfFile:fullPath options:0 error:error];
        if (!fileData) return NO;
        NSData *nameData = [[relativePath stringByReplacingOccurrencesOfString:@"\\" withString:@"/"] dataUsingEncoding:NSUTF8StringEncoding];
        if (nameData.length > UINT16_MAX || fileData.length > UINT32_MAX || zip.length > UINT32_MAX) {
            if (error) *error = [NSError errorWithDomain:PXInPlacePatcherErrorDomain code:80 userInfo:@{NSLocalizedDescriptionKey: @"ZIP64 not supported for patched TIPA export"}];
            return NO;
        }
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil] ?: @{};
        uint32_t dos = PXIPDOSDateTime(attrs[NSFileModificationDate]);
        uint32_t crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, fileData.bytes, (uInt)fileData.length);
        uint32_t localOffset = (uint32_t)zip.length;

        PXIPWriteLE32(zip, 0x04034b50);
        PXIPWriteLE16(zip, 20);
        PXIPWriteLE16(zip, 0);
        PXIPWriteLE16(zip, 0);
        PXIPWriteLE32(zip, dos);
        PXIPWriteLE32(zip, crc);
        PXIPWriteLE32(zip, (uint32_t)fileData.length);
        PXIPWriteLE32(zip, (uint32_t)fileData.length);
        PXIPWriteLE16(zip, (uint16_t)nameData.length);
        PXIPWriteLE16(zip, 0);
        [zip appendData:nameData];
        [zip appendData:fileData];

        PXIPWriteLE32(central, 0x02014b50);
        PXIPWriteLE16(central, 0x0314);
        PXIPWriteLE16(central, 20);
        PXIPWriteLE16(central, 0);
        PXIPWriteLE16(central, 0);
        PXIPWriteLE32(central, dos);
        PXIPWriteLE32(central, crc);
        PXIPWriteLE32(central, (uint32_t)fileData.length);
        PXIPWriteLE32(central, (uint32_t)fileData.length);
        PXIPWriteLE16(central, (uint16_t)nameData.length);
        PXIPWriteLE16(central, 0);
        PXIPWriteLE16(central, 0);
        PXIPWriteLE16(central, 0);
        PXIPWriteLE16(central, 0);
        PXIPWriteLE32(central, 0100644 << 16);
        PXIPWriteLE32(central, localOffset);
        [central appendData:nameData];
    }

    if (relativeFiles.count > UINT16_MAX || central.length > UINT32_MAX || zip.length > UINT32_MAX) {
        if (error) *error = [NSError errorWithDomain:PXInPlacePatcherErrorDomain code:81 userInfo:@{NSLocalizedDescriptionKey: @"ZIP central directory too large"}];
        return NO;
    }
    uint32_t centralOffset = (uint32_t)zip.length;
    [zip appendData:central];
    PXIPWriteLE32(zip, 0x06054b50);
    PXIPWriteLE16(zip, 0);
    PXIPWriteLE16(zip, 0);
    PXIPWriteLE16(zip, (uint16_t)relativeFiles.count);
    PXIPWriteLE16(zip, (uint16_t)relativeFiles.count);
    PXIPWriteLE32(zip, (uint32_t)central.length);
    PXIPWriteLE32(zip, centralOffset);
    PXIPWriteLE16(zip, 0);

    [fm createDirectoryAtPath:[zipPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    return [zip writeToFile:zipPath options:NSDataWritingAtomic error:error];
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

+ (NSDictionary<NSString *,id> *)scanFrameworkCarriersBundleID:(NSString *)bundleID {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[carrier] scan requested bundleID=%@", bundleID ?: @""];
    @try {
        NSDictionary *resolved = PXIPResolve(bundleID);
        [result addEntriesFromDictionary:resolved];
        NSString *bundlePath = resolved[@"bundlePath"];
        NSString *executablePath = resolved[@"executablePath"];
        NSString *frameworksPath = resolved[@"frameworksPath"];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (!bundlePath.length || !executablePath.length || ![fm fileExistsAtPath:executablePath]) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"Failed to resolve target executable";
            return result;
        }

        NSError *mainEncErr = nil;
        NSDictionary *mainEncryption = [PXMachOInjector encryptionSummaryForMachOAtPath:executablePath error:&mainEncErr];
        NSError *mainLoadErr = nil;
        NSDictionary *mainLoad = [PXMachOInjector loadCommandSummaryForMachOAtPath:executablePath error:&mainLoadErr];
        result[@"mainExecutableEncrypted"] = [mainEncryption[@"encrypted"] isEqual:@"YES"] ? @"YES" : @"NO";
        result[@"mainEncryption"] = mainEncryption ?: @{};
        result[@"mainEncryptionError"] = mainEncErr.localizedDescription ?: @"";
        result[@"mainLoadCommandError"] = mainLoadErr.localizedDescription ?: @"";
        result[@"mainLoadedDylibs"] = mainLoad[@"loadedDylibs"] ?: @[];
        result[@"mainLoadCommands"] = mainLoad[@"loadCommands"] ?: @[];
        result[@"mainRpaths"] = mainLoad[@"rpaths"] ?: @[];

        NSMutableSet<NSString *> *linkedPaths = [NSMutableSet set];
        NSMutableSet<NSString *> *linkedRelativeKeys = [NSMutableSet set];
        NSMutableArray<NSDictionary *> *weakMissingLoads = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *extensionOnlyCandidates = [NSMutableArray array];
        for (NSString *loadName in mainLoad[@"loadedDylibs"] ?: @[]) {
            NSString *relativeKey = PXIPFrameworkRelativeLoadKey(loadName);
            if (relativeKey.length) [linkedRelativeKeys addObject:relativeKey];
            NSString *resolvedPath = PXIPResolveLoadCommandPath(loadName, executablePath, frameworksPath);
            if (resolvedPath.length && [fm fileExistsAtPath:resolvedPath] && [PXIPCanonicalPathKey(resolvedPath) hasPrefix:PXIPCanonicalPathKey(frameworksPath)]) {
                [linkedPaths addObject:PXIPCanonicalPathKey(resolvedPath)];
            }
        }
        for (NSDictionary *loadCommand in mainLoad[@"loadCommands"] ?: @[]) {
            NSString *loadName = [loadCommand[@"name"] isKindOfClass:[NSString class]] ? loadCommand[@"name"] : @"";
            if (![loadCommand[@"weak"] isEqual:@"YES"] || PXIPIsSystemLoadName(loadName)) continue;
            NSString *resolvedPath = PXIPResolveLoadCommandPath(loadName, executablePath, frameworksPath);
            if (resolvedPath.length && ![fm fileExistsAtPath:resolvedPath]) {
                [weakMissingLoads addObject:@{
                    @"loadName": loadName ?: @"",
                    @"resolvedPath": resolvedPath ?: @"",
                    @"relativeLoadKey": PXIPFrameworkRelativeLoadKey(loadName) ?: @"",
                    @"cmdName": loadCommand[@"cmdName"] ?: @"",
                    @"category": @"weak-missing-load",
                }];
            }
        }

        NSString *pluginsPath = [bundlePath stringByAppendingPathComponent:@"PlugIns"];
        BOOL pluginsIsDir = NO;
        if ([fm fileExistsAtPath:pluginsPath isDirectory:&pluginsIsDir] && pluginsIsDir) {
            NSDirectoryEnumerator *pluginEnum = [fm enumeratorAtPath:pluginsPath];
            NSString *pluginRel = nil;
            while ((pluginRel = [pluginEnum nextObject])) {
                if (![pluginRel containsString:@".appex/Frameworks/"]) continue;
                NSString *path = [pluginsPath stringByAppendingPathComponent:pluginRel];
                NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
                if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular]) continue;
                NSString *parentExt = path.stringByDeletingLastPathComponent.pathExtension.lowercaseString ?: @"";
                BOOL extensionLooksEligible = [path.pathExtension.lowercaseString isEqualToString:@"dylib"] || [parentExt isEqualToString:@"framework"] || path.pathExtension.length == 0;
                if (!extensionLooksEligible || !PXIPLooksLikeMachO(path)) continue;
                NSError *encErr = nil;
                NSDictionary *enc = [PXMachOInjector encryptionSummaryForMachOAtPath:path error:&encErr];
                [extensionOnlyCandidates addObject:@{
                    @"path": path ?: @"",
                    @"relativePath": [@"PlugIns" stringByAppendingPathComponent:pluginRel] ?: @"",
                    @"name": path.lastPathComponent ?: @"",
                    @"fileSize": attrs[NSFileSize] ?: @0,
                    @"encrypted": [enc[@"encrypted"] isEqual:@"YES"] ? @"YES" : @"NO",
                    @"eligible": @"NO",
                    @"category": @"extension-only",
                    @"skipReason": @"extension-only-not-loaded-by-main-app",
                    @"encryption": enc ?: @{},
                    @"encryptionError": encErr.localizedDescription ?: @"",
                }];
            }
        }

        NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
        BOOL frameworksIsDir = NO;
        if (![fm fileExistsAtPath:frameworksPath isDirectory:&frameworksIsDir] || !frameworksIsDir) {
            BOOL mainEncrypted = [mainEncryption[@"encrypted"] isEqual:@"YES"];
            result[@"ok"] = @"YES";
            result[@"error"] = @"";
            result[@"frameworksExists"] = @"NO";
            result[@"candidateCount"] = @0;
            result[@"eligibleCount"] = @0;
            result[@"linkedEligibleCount"] = @0;
            result[@"standardLinkedEligibleCount"] = @0;
            result[@"dependencyEligibleCount"] = @0;
            result[@"swiftRuntimeCandidateCount"] = @0;
            result[@"fallbackEligibleCount"] = @0;
            result[@"rejectedCandidateCount"] = @0;
            result[@"selectedCarrier"] = @{};
            result[@"selectedCarrierPath"] = @"";
            result[@"selectedCarrierRelativePath"] = @"";
            result[@"selectedCarrierLinkedFromMain"] = @"NO";
            result[@"selectedCarrierCategory"] = @"";
            result[@"selectionReason"] = weakMissingLoads.count ? @"weak-missing-load" : @"no-frameworks-directory";
            result[@"recommendedPatchAction"] = weakMissingLoads.count ? @"Weak Missing Load Candidate" : @"No carrier action available";
            result[@"recommendationReason"] = weakMissingLoads.count ? @"Main executable has a weak non-system load command whose resolved file is missing; a synthetic carrier may be possible but is not implemented." : (mainEncrypted ? @"Main executable is encrypted and the app has no Frameworks directory, so in-place carrier injection is blocked." : @"App has no Frameworks directory and no bundled Mach-O carrier was found.");
            result[@"linkedFrameworkCandidates"] = @[];
            result[@"dependencyChainCandidates"] = @[];
            result[@"swiftRuntimeCandidates"] = @[];
            result[@"fallbackCandidates"] = @[];
            result[@"weakMissingLoadCandidates"] = weakMissingLoads ?: @[];
            result[@"extensionOnlyCandidates"] = extensionOnlyCandidates ?: @[];
            result[@"rejectedCandidates"] = @[];
            result[@"candidates"] = @[];
            [PXDiagnostics log:@"[carrier] scan result=%@", result];
            return result;
        }

        NSDirectoryEnumerator *en = [fm enumeratorAtPath:frameworksPath];
        NSString *rel = nil;
        while ((rel = [en nextObject])) {
            if ([rel containsString:@".troll-fools.bak"] || [rel containsString:@".projectx.bak"]) continue;
            NSString *path = [frameworksPath stringByAppendingPathComponent:rel];
            NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
            NSString *type = attrs[NSFileType];
            if (![type isEqualToString:NSFileTypeRegular]) continue;
            NSString *last = path.lastPathComponent ?: @"";
            NSString *parentExt = path.stringByDeletingLastPathComponent.pathExtension.lowercaseString ?: @"";
            BOOL extensionLooksEligible = [path.pathExtension.lowercaseString isEqualToString:@"dylib"] || [parentExt isEqualToString:@"framework"] || path.pathExtension.length == 0;
            if (!extensionLooksEligible || !PXIPLooksLikeMachO(path)) continue;

            NSError *encErr = nil;
            NSDictionary *enc = [PXMachOInjector encryptionSummaryForMachOAtPath:path error:&encErr];
            NSError *loadErr = nil;
            NSDictionary *load = [PXMachOInjector loadCommandSummaryForMachOAtPath:path error:&loadErr];
            BOOL encrypted = [enc[@"encrypted"] isEqual:@"YES"];
            BOOL swiftRuntime = PXIPIsSwiftRuntimeName(last);
            BOOL ignored = PXIPIsIgnoredCarrierName(last) || PXIPIsIgnoredCarrierName(path.stringByDeletingLastPathComponent.lastPathComponent);
            NSString *relativeKey = rel ?: @"";
            BOOL linked = [linkedPaths containsObject:PXIPCanonicalPathKey(path)] || [linkedRelativeKeys containsObject:relativeKey];
            NSString *skipReason = @"";
            if (encrypted) skipReason = @"encrypted";
            else if (ignored) skipReason = @"ignored-name";
            else if (encErr || loadErr) skipReason = @"unreadable";
            BOOL eligibleRow = (!encrypted && !ignored && !encErr && !loadErr);
            NSMutableDictionary *row = [@{
                @"path": path ?: @"",
                @"relativePath": rel ?: @"",
                @"relativeLoadKey": relativeKey ?: @"",
                @"name": last ?: @"",
                @"fileSize": attrs[NSFileSize] ?: @0,
                @"encrypted": encrypted ? @"YES" : @"NO",
                @"swiftRuntime": swiftRuntime ? @"YES" : @"NO",
                @"ignored": ignored ? @"YES" : @"NO",
                @"linkedFromMain": linked ? @"YES" : @"NO",
                @"dependencyOfLinkedCarrier": @"NO",
                @"eligible": eligibleRow ? @"YES" : @"NO",
                @"skipReason": skipReason ?: @"",
                @"category": PXIPCarrierCategory(linked, NO, swiftRuntime, NO, NO, eligibleRow),
                @"encryption": enc ?: @{},
                @"encryptionError": encErr.localizedDescription ?: @"",
                @"loadedDylibs": load[@"loadedDylibs"] ?: @[],
                @"loadCommands": load[@"loadCommands"] ?: @[],
                @"rpaths": load[@"rpaths"] ?: @[],
                @"loadCommandError": loadErr.localizedDescription ?: @"",
            } mutableCopy];
            [candidates addObject:row];
        }

        NSMutableDictionary<NSString *, NSMutableDictionary *> *candidateByPath = [NSMutableDictionary dictionary];
        for (NSMutableDictionary *row in candidates) {
            NSString *path = [row[@"path"] isKindOfClass:[NSString class]] ? row[@"path"] : @"";
            if (path.length) candidateByPath[PXIPCanonicalPathKey(path)] = row;
        }
        NSMutableSet<NSString *> *dependencyPaths = [NSMutableSet set];
        for (NSDictionary *row in candidates) {
            if (![row[@"linkedFromMain"] isEqual:@"YES"]) continue;
            NSString *loaderPath = [row[@"path"] isKindOfClass:[NSString class]] ? row[@"path"] : @"";
            for (NSString *loadName in row[@"loadedDylibs"] ?: @[]) {
                NSString *resolvedPath = PXIPResolveLoadCommandPathWithLoader(loadName, executablePath, frameworksPath, loaderPath);
                NSString *key = PXIPCanonicalPathKey(resolvedPath);
                if (key.length && candidateByPath[key]) [dependencyPaths addObject:key];
            }
        }
        for (NSString *key in dependencyPaths) {
            NSMutableDictionary *row = candidateByPath[key];
            if (!row || [row[@"linkedFromMain"] isEqual:@"YES"]) continue;
            BOOL swiftRuntime = [row[@"swiftRuntime"] isEqual:@"YES"];
            BOOL eligibleRow = [row[@"eligible"] isEqual:@"YES"];
            row[@"dependencyOfLinkedCarrier"] = @"YES";
            row[@"category"] = PXIPCarrierCategory(NO, YES, swiftRuntime, NO, NO, eligibleRow);
        }

        NSMutableArray<NSDictionary *> *eligible = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *linkedEligible = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *standardLinkedEligible = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *dependencyEligible = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *swiftRuntimeCandidates = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *fallbackEligible = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *rejectedCandidates = [NSMutableArray array];
        for (NSDictionary *row in candidates) {
            BOOL rowEligible = [row[@"eligible"] isEqual:@"YES"];
            BOOL swiftRuntime = [row[@"swiftRuntime"] isEqual:@"YES"];
            BOOL linked = [row[@"linkedFromMain"] isEqual:@"YES"];
            BOOL dependency = [row[@"dependencyOfLinkedCarrier"] isEqual:@"YES"];
            if (!rowEligible) {
                [rejectedCandidates addObject:row];
                continue;
            }
            [eligible addObject:row];
            if (linked) [linkedEligible addObject:row];
            if (linked && !swiftRuntime) [standardLinkedEligible addObject:row];
            else if (dependency && !swiftRuntime) [dependencyEligible addObject:row];
            else if (swiftRuntime) [swiftRuntimeCandidates addObject:row];
            else [fallbackEligible addObject:row];
        }
        NSDictionary *selected = standardLinkedEligible.firstObject ?: dependencyEligible.firstObject ?: fallbackEligible.firstObject ?: swiftRuntimeCandidates.firstObject ?: eligible.firstObject ?: @{};
        BOOL mainEncrypted = [mainEncryption[@"encrypted"] isEqual:@"YES"];
        NSString *selectionReason = @"no-eligible-carrier";
        NSString *recommendedAction = @"No carrier action available";
        NSString *recommendationReason = @"No eligible unencrypted bundled Mach-O carrier found.";
        if (standardLinkedEligible.count) {
            selectionReason = @"linked-from-main";
            recommendedAction = @"Patch Framework Carrier";
            recommendationReason = @"Found an unencrypted non-Swift bundled Mach-O loaded directly by the main executable.";
        } else if (dependencyEligible.count) {
            selectionReason = @"dependency-chain";
            recommendedAction = @"Patch Dependency Carrier";
            recommendationReason = @"Found an unencrypted bundled Mach-O loaded by a framework that is loaded by the main executable.";
        } else if (fallbackEligible.count) {
            selectionReason = @"fallback-unlinked";
            recommendedAction = @"Patch Framework Carrier can try fallback, but target may not load it";
            recommendationReason = @"Found an unencrypted bundled Mach-O, but scan did not prove it is loaded by the main executable.";
        } else if (swiftRuntimeCandidates.count) {
            selectionReason = @"swift-runtime";
            recommendedAction = @"Patch Swift Runtime Carrier (diagnostic)";
            recommendationReason = @"Only Swift runtime candidates were found; try manually by index if no app-owned carrier exists.";
        } else if (weakMissingLoads.count) {
            selectionReason = @"weak-missing-load";
            recommendedAction = @"Weak Missing Load Candidate";
            recommendationReason = @"Main executable has a weak non-system load command whose resolved file is missing; a synthetic carrier may be possible but is not implemented.";
        } else if (mainEncrypted) {
            recommendationReason = @"Main executable is encrypted and no linked unencrypted bundled Mach-O carrier was found; in-place carrier injection is blocked for this app.";
        }

        result[@"ok"] = @"YES";
        result[@"error"] = @"";
        result[@"frameworksExists"] = @"YES";
        result[@"linkedFrameworkPaths"] = linkedPaths.allObjects ?: @[];
        result[@"linkedFrameworkRelativeKeys"] = linkedRelativeKeys.allObjects ?: @[];
        result[@"candidateCount"] = @(candidates.count);
        result[@"eligibleCount"] = @(eligible.count);
        result[@"linkedEligibleCount"] = @(linkedEligible.count);
        result[@"standardLinkedEligibleCount"] = @(standardLinkedEligible.count);
        result[@"dependencyEligibleCount"] = @(dependencyEligible.count);
        result[@"swiftRuntimeCandidateCount"] = @(swiftRuntimeCandidates.count);
        result[@"fallbackEligibleCount"] = @(fallbackEligible.count);
        result[@"rejectedCandidateCount"] = @(rejectedCandidates.count);
        result[@"selectedCarrier"] = selected ?: @{};
        result[@"selectedCarrierPath"] = selected[@"path"] ?: @"";
        result[@"selectedCarrierRelativePath"] = selected[@"relativePath"] ?: @"";
        result[@"selectedCarrierLinkedFromMain"] = selected[@"linkedFromMain"] ?: @"NO";
        result[@"selectedCarrierCategory"] = selected[@"category"] ?: @"";
        result[@"selectionReason"] = selectionReason ?: @"";
        result[@"recommendedPatchAction"] = recommendedAction ?: @"";
        result[@"recommendationReason"] = recommendationReason ?: @"";
        result[@"linkedFrameworkCandidates"] = standardLinkedEligible ?: @[];
        result[@"dependencyChainCandidates"] = dependencyEligible ?: @[];
        result[@"swiftRuntimeCandidates"] = swiftRuntimeCandidates ?: @[];
        result[@"fallbackCandidates"] = fallbackEligible ?: @[];
        result[@"weakMissingLoadCandidates"] = weakMissingLoads ?: @[];
        result[@"extensionOnlyCandidates"] = extensionOnlyCandidates ?: @[];
        result[@"rejectedCandidates"] = rejectedCandidates ?: @[];
        result[@"candidates"] = candidates ?: @[];
        [PXDiagnostics log:@"[carrier] scan result=%@", result];
        return result;
    } @catch (NSException *ex) {
        result[@"ok"] = @"NO";
        result[@"error"] = [NSString stringWithFormat:@"Exception during carrier scan: %@ %@", ex.name ?: @"", ex.reason ?: @""];
        [PXDiagnostics log:@"[carrier] scan exception=%@", result[@"error"]];
        return result;
    }
}

+ (NSDictionary<NSString *,id> *)patchFrameworkCarrierBundleID:(NSString *)bundleID {
    return [self patchFrameworkCarrierBundleID:bundleID candidateIndex:NSNotFound];
}

+ (NSDictionary<NSString *,id> *)patchFrameworkCarrierBundleID:(NSString *)bundleID candidateIndex:(NSUInteger)candidateIndex {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[carrier] patch requested bundleID=%@", bundleID ?: @""];
    @try {
        NSDictionary *scan = [self scanFrameworkCarriersBundleID:bundleID];
        result[@"scan"] = scan ?: @{};
        if (![scan[@"ok"] isEqual:@"YES"]) {
            return PXIPCarrierFail(result, scan[@"error"] ?: @"Carrier scan failed");
        }
        NSDictionary *selected = scan[@"selectedCarrier"];
        if (candidateIndex != NSNotFound) {
            NSArray *candidates = [scan[@"candidates"] isKindOfClass:[NSArray class]] ? scan[@"candidates"] : @[];
            if (candidateIndex < candidates.count && [candidates[candidateIndex] isKindOfClass:[NSDictionary class]]) {
                selected = candidates[candidateIndex];
                result[@"selectedCandidateIndexOverride"] = @(candidateIndex);
            } else {
                return PXIPCarrierFail(result, @"Candidate index out of range");
            }
        }
        if (![selected isKindOfClass:[NSDictionary class]] || ![selected[@"path"] isKindOfClass:[NSString class]] || ![selected[@"path"] length]) {
            return PXIPCarrierFail(result, @"No eligible unencrypted framework/dylib carrier found");
        }
        if (![selected[@"eligible"] isEqual:@"YES"]) {
            NSString *reason = [selected[@"skipReason"] isKindOfClass:[NSString class]] ? selected[@"skipReason"] : @"not eligible";
            return PXIPCarrierFail(result, [NSString stringWithFormat:@"Selected carrier is not eligible: %@", reason.length ? reason : @"not eligible"]);
        }

        NSString *carrierPath = selected[@"path"];
        NSString *bundlePath = scan[@"bundlePath"] ?: @"";
        NSString *frameworksPath = scan[@"frameworksPath"] ?: @"";
        NSString *executableName = scan[@"executableName"] ?: @"";
        NSString *version = scan[@"version"] ?: @"";
        NSString *build = scan[@"build"] ?: @"";
        NSString *dylibLoadPath = @"@executable_path/Frameworks/ProjectXInject.dylib";
        NSString *targetDylib = [frameworksPath stringByAppendingPathComponent:@"ProjectXInject.dylib"];
        NSString *sourceDylib = [PXRuntimeSnapshot bundledInjectDylibPath];
        NSString *teamID = PXIPTeamIDFromExecutable(scan[@"executablePath"] ?: @"");
        NSFileManager *fm = [NSFileManager defaultManager];
        if (!carrierPath.length || ![fm fileExistsAtPath:carrierPath]) {
            return PXIPCarrierFail(result, @"Selected carrier no longer exists");
        }
        if (!sourceDylib.length || ![fm fileExistsAtPath:sourceDylib]) {
            return PXIPCarrierFail(result, @"Bundled ProjectXInject.dylib missing");
        }

        NSError *snapshotErr = nil;
        NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:bundleID
                                                               enableObjCHooks:YES
                                                                  enableCHooks:YES
                                                                  cHookOptions:PXIPSafeSysctlByNameOptions()
                                                                         error:&snapshotErr];
        result[@"snapshot"] = snapshot ?: @{};
        result[@"snapshotError"] = snapshotErr.localizedDescription ?: @"";
        result[@"snapshotMode"] = snapshot[@"CHookTestMode"] ?: @"";

        NSString *backupDir = [[[PXIPBackupRoot() stringByAppendingPathComponent:PXIPSafeName(bundleID)] stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-%@", version.length ? version : @"unknown", build.length ? build : @"unknown"]] stringByAppendingPathComponent:@"FrameworkCarriers"];
        NSString *safeCarrierName = PXIPSafeName(selected[@"relativePath"] ?: carrierPath.lastPathComponent ?: @"carrier");
        NSString *backupCarrier = [backupDir stringByAppendingPathComponent:safeCarrierName];
        NSString *patchedCarrier = [backupDir stringByAppendingPathComponent:[safeCarrierName stringByAppendingString:@".patched"]];
        result[@"backupDir"] = backupDir ?: @"";
        result[@"backupCarrier"] = backupCarrier ?: @"";
        result[@"patchedCarrier"] = patchedCarrier ?: @"";
        result[@"carrierPath"] = carrierPath ?: @"";
        result[@"targetDylib"] = targetDylib ?: @"";
        result[@"dylibLoadPath"] = dylibLoadPath ?: @"";
        result[@"teamID"] = teamID ?: @"";

        NSString *rootErr = nil;
        if (!PXIPRunRoot(@[@"mkdir", backupDir], &rootErr)) {
            return PXIPCarrierFail(result, rootErr ?: @"Failed to create carrier backup dir");
        }
        result[@"chownBackupDir"] = PXIPRunRootDetailed(@[@"chown", @"501", @"501", backupDir]);
        if (!PXIPRunRoot(@[@"cpfile", carrierPath, backupCarrier], &rootErr)) {
            return PXIPCarrierFail(result, rootErr ?: @"Failed to back up selected carrier");
        }
        result[@"chmodBackupCarrier"] = PXIPRunRootDetailed(@[@"chmod", @"0755", backupCarrier]);
        result[@"chownBackupCarrier"] = PXIPRunRootDetailed(@[@"chown", @"501", @"501", backupCarrier]);

        NSError *removePatchedErr = nil;
        [fm removeItemAtPath:patchedCarrier error:&removePatchedErr];
        if (removePatchedErr && [fm fileExistsAtPath:patchedCarrier]) {
            result[@"removeExistingPatchedCarrierError"] = removePatchedErr.localizedDescription ?: @"";
            result[@"removeExistingPatchedCarrierRoot"] = PXIPRunRootDetailed(@[@"rm", patchedCarrier]);
        }

        NSError *readCarrierErr = nil;
        NSData *carrierData = [NSData dataWithContentsOfFile:carrierPath options:0 error:&readCarrierErr];
        result[@"readCarrierForPatchBytes"] = carrierData ? @(carrierData.length) : @0;
        result[@"readCarrierForPatchError"] = readCarrierErr.localizedDescription ?: @"";
        if (!carrierData.length) {
            return PXIPCarrierFail(result, readCarrierErr.localizedDescription ?: @"Failed to read selected carrier for local patched copy");
        }

        NSError *writePatchedErr = nil;
        BOOL writePatchedOK = [carrierData writeToFile:patchedCarrier options:NSDataWritingAtomic error:&writePatchedErr];
        result[@"writePatchedCarrierOK"] = writePatchedOK ? @"YES" : @"NO";
        result[@"writePatchedCarrierError"] = writePatchedErr.localizedDescription ?: @"";
        if (!writePatchedOK) {
            NSDictionary *copyPatched = PXIPRunRootDetailed(@[@"cpfile", backupCarrier, patchedCarrier]);
            result[@"copyPatchedCarrierFallback"] = copyPatched ?: @{};
            if (![copyPatched[@"ok"] isEqual:@"YES"]) {
                return PXIPCarrierFail(result, writePatchedErr.localizedDescription ?: copyPatched[@"error"] ?: @"Failed to create patched carrier copy");
            }
        }
        result[@"chmodPatchedCarrier"] = PXIPRunRootDetailed(@[@"chmod", @"0755", patchedCarrier]);
        result[@"chownPatchedCarrier"] = PXIPRunRootDetailed(@[@"chown", @"501", @"501", patchedCarrier]);

        BOOL patchedCarrierVisible = [fm fileExistsAtPath:patchedCarrier];
        result[@"patchedCarrierVisibleBeforePatch"] = patchedCarrierVisible ? @"YES" : @"NO";
        if (!patchedCarrierVisible) {
            return PXIPCarrierFail(result, @"Patched carrier copy was created by helper but is not visible to app process");
        }

        [PXDiagnostics log:@"[carrier] patch insert load command carrierCopy=%@ loadPath=%@", patchedCarrier ?: @"", dylibLoadPath ?: @""];
        NSError *patchErr = nil;
        BOOL patched = [PXMachOInjector insertDylibLoadCommand:dylibLoadPath intoMachOAtPath:patchedCarrier error:&patchErr];
        result[@"patchCarrierOK"] = patched ? @"YES" : @"NO";
        result[@"patchCarrierError"] = patchErr.localizedDescription ?: @"";
        PXIPAddLoadCommandStatus(result, @"patchedCarrier", patchedCarrier, dylibLoadPath);
        if (!patched) {
            return PXIPCarrierFail(result, patchErr.localizedDescription ?: @"Failed to patch selected carrier");
        }

        NSDictionary *signCarrier = PXIPTrySignPath(patchedCarrier, nil);
        result[@"signPatchedCarrier"] = signCarrier ?: @{};
        result[@"ctBypassPatchedCarrier"] = PXIPTryCoreTrustBypass(patchedCarrier, teamID) ?: @{};
        NSDictionary *signDylibSource = PXIPTrySignPath(sourceDylib, [[NSBundle mainBundle] pathForResource:@"ProjectXInject" ofType:@"entitlements.plist"]);
        result[@"signBundledDylib"] = signDylibSource ?: @{};
        result[@"ctBypassBundledDylib"] = PXIPTryCoreTrustBypass(sourceDylib, teamID) ?: @{};
        result[@"rootSourceDylibInfoAfterSign"] = PXIPRunRootDetailed(@[@"fileinfo", sourceDylib]);

        if (executableName.length) {
            PXKillallTermThenKill(executableName, 0.5);
            PXWaitForProcessesToExit(@[executableName], 2.0);
        }

        NSDictionary *copyDylib = PXIPRunRootDetailed(@[@"cpfile", sourceDylib, targetDylib]);
        result[@"copyDylib"] = copyDylib ?: @{};
        if (![copyDylib[@"ok"] isEqual:@"YES"]) {
            NSDictionary *toolCopyDylib = PXIPRunRootDetailed(@[@"toolcpfile", sourceDylib, targetDylib]);
            result[@"toolCopyDylibAfterCpfileFailure"] = toolCopyDylib ?: @{};
            if (![toolCopyDylib[@"ok"] isEqual:@"YES"]) {
                return PXIPCarrierFail(result, toolCopyDylib[@"error"] ?: copyDylib[@"error"] ?: @"Failed to copy ProjectXInject.dylib into target Frameworks");
            }
        }
        result[@"rootTargetDylibInfoAfterCopy"] = PXIPRunRootDetailed(@[@"fileinfo", targetDylib]);
        if (![result[@"rootTargetDylibInfoAfterCopy"][@"ok"] isEqual:@"YES"]) {
            NSDictionary *toolCopyDylib = PXIPRunRootDetailed(@[@"toolcpfile", sourceDylib, targetDylib]);
            result[@"toolCopyDylibAfterMissingInfo"] = toolCopyDylib ?: @{};
            result[@"rootTargetDylibInfoAfterToolCopy"] = PXIPRunRootDetailed(@[@"fileinfo", targetDylib]);
        }
        unsigned long long sourceDylibSize = PXIPFileInfoSize(result[@"rootSourceDylibInfoAfterSign"] ?: @{});
        NSDictionary *targetInfoForMatch = result[@"rootTargetDylibInfoAfterToolCopy"] ?: result[@"rootTargetDylibInfoAfterCopy"] ?: @{};
        unsigned long long targetDylibSize = PXIPFileInfoSize(targetInfoForMatch);
        result[@"sourceDylibSize"] = @(sourceDylibSize);
        result[@"targetDylibSizeAfterCopy"] = @(targetDylibSize);
        if (sourceDylibSize > 0 && targetDylibSize != sourceDylibSize) {
            NSDictionary *toolCopyDylib = PXIPRunRootDetailed(@[@"toolcpfile", sourceDylib, targetDylib]);
            result[@"toolCopyDylibAfterSizeMismatch"] = toolCopyDylib ?: @{};
            result[@"rootTargetDylibInfoAfterSizeMismatchToolCopy"] = PXIPRunRootDetailed(@[@"fileinfo", targetDylib]);
        }
        NSDictionary *targetInfoAfterMatch = result[@"rootTargetDylibInfoAfterSizeMismatchToolCopy"] ?: result[@"rootTargetDylibInfoAfterToolCopy"] ?: result[@"rootTargetDylibInfoAfterCopy"] ?: @{};
        result[@"targetDylibSizeAfterMatch"] = @(PXIPFileInfoSize(targetInfoAfterMatch));
        result[@"targetDylibMatchesSource"] = (sourceDylibSize > 0 && PXIPFileInfoSize(targetInfoAfterMatch) == sourceDylibSize) ? @"YES" : @"NO";
        NSDictionary *signTargetDylib = PXIPTrySignPath(targetDylib, [[NSBundle mainBundle] pathForResource:@"ProjectXInject" ofType:@"entitlements.plist"]);
        result[@"signTargetDylib"] = signTargetDylib ?: @{};
        result[@"ctBypassTargetDylib"] = PXIPTryCoreTrustBypass(targetDylib, teamID) ?: @{};
        NSDictionary *installCarrier = PXIPRunRootDetailed(@[@"installfile", patchedCarrier, carrierPath]);
        result[@"installCarrier"] = installCarrier ?: @{};
        if (![installCarrier[@"ok"] isEqual:@"YES"]) {
            return PXIPCarrierFail(result, installCarrier[@"error"] ?: @"Failed to install patched carrier");
        }
        result[@"rootInstalledCarrierInfoAfterInstall"] = PXIPRunRootDetailed(@[@"fileinfo", carrierPath]);
        NSDictionary *rootContainsAfterInstall = PXIPRunRootDetailed(@[@"contains", carrierPath, dylibLoadPath]);
        result[@"rootInstalledCarrierContainsLoadPath"] = rootContainsAfterInstall ?: @{};
        BOOL appSeesInstalledLoadCommandAfterInstall = NO;
        NSError *appInstallCheckErr = nil;
        appSeesInstalledLoadCommandAfterInstall = [PXMachOInjector hasDylibLoadCommand:dylibLoadPath inMachOAtPath:carrierPath error:&appInstallCheckErr];
        result[@"appInstalledCarrierHasLoadCommandAfterInstall"] = appSeesInstalledLoadCommandAfterInstall ? @"YES" : @"NO";
        result[@"appInstalledCarrierLoadCommandAfterInstallError"] = appInstallCheckErr.localizedDescription ?: @"";
        if (![rootContainsAfterInstall[@"ok"] isEqual:@"YES"] || !appSeesInstalledLoadCommandAfterInstall) {
            NSDictionary *overwriteCarrier = PXIPRunRootDetailed(@[@"overwritefile", patchedCarrier, carrierPath]);
            result[@"overwriteCarrier"] = overwriteCarrier ?: @{};
            if ([overwriteCarrier[@"ok"] isEqual:@"YES"]) {
                result[@"rootInstalledCarrierInfoAfterOverwrite"] = PXIPRunRootDetailed(@[@"fileinfo", carrierPath]);
                result[@"rootInstalledCarrierContainsLoadPathAfterOverwrite"] = PXIPRunRootDetailed(@[@"contains", carrierPath, dylibLoadPath]);
            }
            NSDictionary *containsAfterOverwrite = result[@"rootInstalledCarrierContainsLoadPathAfterOverwrite"];
            if (![containsAfterOverwrite[@"ok"] isEqual:@"YES"]) {
                NSDictionary *toolCopyCarrier = PXIPRunRootDetailed(@[@"toolcpfile", patchedCarrier, carrierPath]);
                result[@"toolCopyCarrierAfterOverwriteFailure"] = toolCopyCarrier ?: @{};
                result[@"rootInstalledCarrierInfoAfterToolCopy"] = PXIPRunRootDetailed(@[@"fileinfo", carrierPath]);
                result[@"rootInstalledCarrierContainsLoadPathAfterToolCopy"] = PXIPRunRootDetailed(@[@"contains", carrierPath, dylibLoadPath]);
                result[@"ctBypassInstalledCarrierAfterToolCopy"] = PXIPTryCoreTrustBypass(carrierPath, teamID) ?: @{};
            }
        }
        NSDictionary *chownCarrier = PXIPRunRootDetailed(@[@"chown", @"33", @"33", carrierPath]);
        NSDictionary *chownDylib = PXIPRunRootDetailed(@[@"chown", @"33", @"33", targetDylib]);
        result[@"chownCarrier"] = chownCarrier ?: @{};
        result[@"chownDylib"] = chownDylib ?: @{};
        result[@"rootInstalledCarrierInfoAfterChown"] = PXIPRunRootDetailed(@[@"fileinfo", carrierPath]);
        result[@"rootTargetDylibInfoAfterChown"] = PXIPRunRootDetailed(@[@"fileinfo", targetDylib]);

        if (executableName.length) {
            [PXDiagnostics log:@"[carrier] killing target process after install name=%@", executableName];
            BOOL killAfterInstall = PXKillallTermThenKill(executableName, 0.5);
            BOOL exitedAfterInstall = PXWaitForProcessesToExit(@[executableName], 2.0);
            result[@"killAfterInstall"] = killAfterInstall ? @"YES" : @"NO";
            result[@"exitedAfterInstall"] = exitedAfterInstall ? @"YES" : @"NO";
        }

        NSDictionary *finalCarrierContains = result[@"rootInstalledCarrierContainsLoadPathAfterToolCopy"] ?: result[@"rootInstalledCarrierContainsLoadPathAfterOverwrite"] ?: result[@"rootInstalledCarrierContainsLoadPath"] ?: @{};
        NSDictionary *finalDylibInfo = result[@"rootTargetDylibInfoAfterChown"] ?: result[@"rootTargetDylibInfoAfterSizeMismatchToolCopy"] ?: result[@"rootTargetDylibInfoAfterToolCopy"] ?: result[@"rootTargetDylibInfoAfterCopy"] ?: @{};
        BOOL carrierVerified = [finalCarrierContains[@"ok"] isEqual:@"YES"];
        BOOL dylibVerified = [finalDylibInfo[@"ok"] isEqual:@"YES"] && [result[@"targetDylibMatchesSource"] isEqual:@"YES"];
        result[@"carrierInstallVerified"] = carrierVerified ? @"YES" : @"NO";
        result[@"targetDylibInstallVerified"] = dylibVerified ? @"YES" : @"NO";

        NSMutableDictionary *state = [NSMutableDictionary dictionaryWithDictionary:PXIPReadState(bundleID) ?: @{}];
        [state addEntriesFromDictionary:@{
            @"mode": (carrierVerified && dylibVerified) ? @"framework-carrier-installed" : @"framework-carrier-installed-unverified",
            @"bundleID": bundleID ?: @"",
            @"bundlePath": bundlePath ?: @"",
            @"executableName": executableName ?: @"",
            @"executablePath": scan[@"executablePath"] ?: @"",
            @"frameworksPath": frameworksPath ?: @"",
            @"version": version ?: @"",
            @"build": build ?: @"",
            @"carrierPath": carrierPath ?: @"",
            @"backupCarrier": backupCarrier ?: @"",
            @"patchedCarrier": patchedCarrier ?: @"",
            @"targetDylib": targetDylib ?: @"",
            @"dylibLoadPath": dylibLoadPath ?: @"",
            @"selectedCarrier": selected ?: @{},
            @"installedAt": @([[NSDate date] timeIntervalSince1970]),
            @"loadCommandInserted": carrierVerified ? @"YES" : @"NO",
            @"targetDylibInstalled": dylibVerified ? @"YES" : @"NO",
        }];
        PXIPWriteState(bundleID, state);
        result[@"state"] = state ?: @{};
        PXIPAddLoadCommandStatus(result, @"installedCarrier", carrierPath, dylibLoadPath);
        PXIPAddCodeSignatureOnlyStatus(result, @"targetDylib", targetDylib);
        result[@"ok"] = @"YES";
        result[@"error"] = @"";
        result[@"note"] = (carrierVerified && dylibVerified) ? @"Framework carrier injection verified root-side. Launch the target app and check Injection Marker Status." : @"Framework carrier patch attempted. Prefer rootInstalledCarrierContainsLoadPath/rootTargetDylibInfoAfterCopy over app-side status if app-side bundle view is stale. CoreTrust signing may still be required.";
        [PXDiagnostics log:@"[carrier] patch result=%@", result];
        return result;
    } @catch (NSException *ex) {
        result[@"ok"] = @"NO";
        result[@"error"] = [NSString stringWithFormat:@"Exception during carrier patch: %@ %@", ex.name ?: @"", ex.reason ?: @""];
        [PXDiagnostics log:@"[carrier] patch exception=%@", result[@"error"]];
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

+ (NSDictionary<NSString *,id> *)exportPatchedTIPABundleID:(NSString *)bundleID {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[patch] export patched TIPA requested bundleID=%@", bundleID ?: @""];
    @try {
        if (!bundleID.length) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"Missing bundleID";
            return result;
        }

        NSDictionary *resolved = PXIPResolve(bundleID);
        [result addEntriesFromDictionary:resolved];
        NSString *bundlePath = resolved[@"bundlePath"];
        NSString *executableName = resolved[@"executableName"];
        NSString *sourceExecutable = (bundlePath.length && executableName.length) ? [bundlePath stringByAppendingPathComponent:executableName] : @"";
        NSString *dylibLoadPath = @"@executable_path/Frameworks/ProjectXInject.dylib";
        NSFileManager *fm = [NSFileManager defaultManager];
        if (!bundlePath.length || !executableName.length || ![fm fileExistsAtPath:sourceExecutable]) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"Failed to resolve target app bundle/executable";
            return result;
        }

        NSError *encryptionErr = nil;
        NSDictionary *encryption = [PXMachOInjector encryptionSummaryForMachOAtPath:sourceExecutable error:&encryptionErr];
        result[@"sourceEncryption"] = encryption ?: @{};
        result[@"sourceEncryptionError"] = encryptionErr.localizedDescription ?: @"";
        if ([encryption[@"encrypted"] isEqual:@"YES"]) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"Target main executable is encrypted (cryptid != 0). TrollStore cannot install a patched encrypted App Store binary. Use a decrypted IPA/app bundle as input.";
            return result;
        }

        NSError *snapshotErr = nil;
        NSDictionary *snapshot = [PXRuntimeSnapshot exportSnapshotForBundleID:bundleID error:&snapshotErr];
        result[@"snapshotOK"] = snapshot ? @"YES" : @"NO";
        result[@"snapshotError"] = snapshotErr.localizedDescription ?: @"";

        NSString *safeVersion = PXIPSafeName([NSString stringWithFormat:@"%@-%@", resolved[@"version"] ?: @"", resolved[@"build"] ?: @""]);
        NSString *stagingBase = [[PXIPStagingRoot() stringByAppendingPathComponent:PXIPSafeName(bundleID)] stringByAppendingPathComponent:safeVersion];
        NSString *payloadDir = [stagingBase stringByAppendingPathComponent:@"Payload"];
        NSString *stagedApp = [payloadDir stringByAppendingPathComponent:bundlePath.lastPathComponent ?: @"Target.app"];
        NSString *stagedExecutable = [stagedApp stringByAppendingPathComponent:executableName];
        NSString *stagedFrameworks = [stagedApp stringByAppendingPathComponent:@"Frameworks"];
        NSString *stagedDylib = [stagedFrameworks stringByAppendingPathComponent:@"ProjectXInject.dylib"];
        NSString *tipaName = [NSString stringWithFormat:@"%@-%@-projectx.tipa", PXIPSafeName(bundleID), safeVersion.length ? safeVersion : @"unknown"];
        NSString *tipaPath = [PXIPPatchedAppsRoot() stringByAppendingPathComponent:tipaName];

        [fm removeItemAtPath:stagingBase error:nil];
        [fm createDirectoryAtPath:payloadDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSError *copyErr = nil;
        [PXDiagnostics log:@"[patch] export copying app bundle source=%@ staged=%@", bundlePath ?: @"", stagedApp ?: @""];
        if (![fm copyItemAtPath:bundlePath toPath:stagedApp error:&copyErr]) {
            result[@"ok"] = @"NO";
            result[@"error"] = copyErr.localizedDescription ?: @"Failed to copy app bundle to staging";
            return result;
        }

        NSError *mkErr = nil;
        [fm createDirectoryAtPath:stagedFrameworks withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0755} error:&mkErr];
        if (mkErr) {
            result[@"ok"] = @"NO";
            result[@"error"] = mkErr.localizedDescription ?: @"Failed to create staged Frameworks directory";
            return result;
        }
        NSString *injectSource = [PXRuntimeSnapshot bundledInjectDylibPath];
        NSError *dylibErr = nil;
        [fm removeItemAtPath:stagedDylib error:nil];
        if (![fm copyItemAtPath:injectSource toPath:stagedDylib error:&dylibErr]) {
            result[@"ok"] = @"NO";
            result[@"error"] = dylibErr.localizedDescription ?: @"Failed to copy ProjectXInject.dylib into staged app";
            return result;
        }
        [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:stagedDylib error:nil];

        NSError *patchErr = nil;
        BOOL patched = [PXMachOInjector insertDylibLoadCommand:dylibLoadPath intoMachOAtPath:stagedExecutable error:&patchErr];
        if (!patched) {
            result[@"ok"] = @"NO";
            result[@"error"] = patchErr.localizedDescription ?: @"Failed to patch staged executable";
            return result;
        }
        [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:stagedExecutable error:nil];

        PXIPAddLoadCommandStatus(result, @"stagedExecutable", stagedExecutable, dylibLoadPath);
        PXIPAddCodeSignatureOnlyStatus(result, @"stagedDylib", stagedDylib);
        if (![result[@"stagedExecutableHasLoadCommand"] isEqual:@"YES"]) {
            result[@"ok"] = @"NO";
            result[@"error"] = @"Staged executable patch verification failed";
            return result;
        }

        NSError *zipErr = nil;
        [fm removeItemAtPath:tipaPath error:nil];
        [PXDiagnostics log:@"[patch] export packaging sourceRoot=%@ tipa=%@", stagingBase ?: @"", tipaPath ?: @""];
        if (!PXIPCreateStoredZip(stagingBase, tipaPath, &zipErr)) {
            result[@"ok"] = @"NO";
            result[@"error"] = zipErr.localizedDescription ?: @"Failed to package patched TIPA";
            return result;
        }
        NSDictionary *tipaAttrs = [fm attributesOfItemAtPath:tipaPath error:nil] ?: @{};
        result[@"ok"] = @"YES";
        result[@"error"] = @"";
        result[@"stagingBase"] = stagingBase ?: @"";
        result[@"payloadDir"] = payloadDir ?: @"";
        result[@"stagedApp"] = stagedApp ?: @"";
        result[@"stagedExecutable"] = stagedExecutable ?: @"";
        result[@"stagedDylib"] = stagedDylib ?: @"";
        result[@"tipaPath"] = tipaPath ?: @"";
        result[@"tipaSize"] = tipaAttrs[NSFileSize] ?: @0;
        result[@"signingStatus"] = @"not-signed-on-device";
        result[@"note"] = @"Patched TIPA exported. Install with TrollStore; signing/install automation is a later phase.";
        [PXDiagnostics log:@"[patch] export patched TIPA result=%@", result];
        return result;
    } @catch (NSException *ex) {
        result[@"ok"] = @"NO";
        result[@"error"] = [NSString stringWithFormat:@"Exception during export patched TIPA: %@ %@", ex.name ?: @"", ex.reason ?: @""];
        [PXDiagnostics log:@"[patch] export patched TIPA exception=%@", result[@"error"]];
        return result;
    }
}

+ (NSDictionary<NSString *,id> *)installPatchedCopyBundleID:(NSString *)bundleID {
    return [self installPatchedCopyBundleID:bundleID launchAfterInstall:YES];
}

+ (NSDictionary<NSString *,id> *)installPatchedCopyWithoutLaunchBundleID:(NSString *)bundleID {
    return [self installPatchedCopyBundleID:bundleID launchAfterInstall:NO];
}

+ (NSDictionary<NSString *,id> *)installPatchedCopyBundleID:(NSString *)bundleID launchAfterInstall:(BOOL)launchAfterInstall {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"bundleID"] = bundleID ?: @"";
    [PXDiagnostics log:@"[patch] install patched copy requested bundleID=%@ launch=%@", bundleID ?: @"", launchAfterInstall ? @"YES" : @"NO"];
    @try {
        NSDictionary *state = PXIPReadState(bundleID);
        result[@"state"] = state ?: @{};
        NSString *patchedCopy = state[@"patchedCopy"];
        NSString *executablePath = state[@"executablePath"];
        NSString *executableName = state[@"executableName"];
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

        [PXDiagnostics log:@"[patch] installing patched copy source=%@ executable=%@", patchedCopy ?: @"", executablePath ?: @""];
        NSDictionary *replaceExecutable = PXIPRunRootDetailed(@[@"installfile", patchedCopy, executablePath]);
        result[@"replaceExecutable"] = replaceExecutable ?: @{};
        if (![replaceExecutable[@"ok"] isEqual:@"YES"]) {
            result[@"ok"] = @"NO";
            result[@"error"] = replaceExecutable[@"error"] ?: @"Failed to install patched executable";
            return result;
        }

        NSMutableDictionary *newState = [NSMutableDictionary dictionaryWithDictionary:state ?: @{}];
        newState[@"mode"] = @"inplace-installed-unverified";
        newState[@"installedPatchedCopy"] = @"YES";
        newState[@"installedExecutableHasLoadCommand"] = @"UNKNOWN";
        newState[@"installedExecutableFingerprint"] = @"";
        newState[@"signatureStatus"] = @"not-checked";
        newState[@"installedAt"] = @([[NSDate date] timeIntervalSince1970]);
        PXIPWriteState(bundleID, newState);
        result[@"state"] = newState ?: @{};
        result[@"verificationDeferred"] = @"YES";
        result[@"signatureStatus"] = @"not-checked";
        result[@"launchAfterInstall"] = launchAfterInstall ? @"YES" : @"NO";
        result[@"note"] = @"Executable installed; run In-Place Status separately to verify load command.";

        if (!launchAfterInstall) {
            NSDictionary *status = [self statusForBundleID:bundleID];
            result[@"immediateStatus"] = status ?: @{};
            result[@"ok"] = @"YES";
            result[@"error"] = @"";
            [PXDiagnostics log:@"[patch] install without launch result=%@", result];
            return result;
        }

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
    NSString *carrierPath = state[@"carrierPath"];
    NSString *backupCarrier = state[@"backupCarrier"];
    NSString *targetDylib = state[@"targetDylib"];
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL carrierMode = carrierPath.length && backupCarrier.length;
    if (carrierMode && [fm fileExistsAtPath:backupCarrier]) {
        NSDictionary *replaceCarrier = PXIPRunRootDetailed(@[@"installfile", backupCarrier, carrierPath]);
        result[@"replaceCarrier"] = replaceCarrier ?: @{};
        if (![replaceCarrier[@"ok"] isEqual:@"YES"]) {
            result[@"ok"] = @"NO";
            result[@"error"] = replaceCarrier[@"error"] ?: @"Failed to restore carrier";
            return result;
        }
        result[@"chownRestoredCarrier"] = PXIPRunRootDetailed(@[@"chown", @"33", @"33", carrierPath]);
    } else if (!executablePath.length || !backupExecutable.length || ![fm fileExistsAtPath:backupExecutable]) {
        result[@"ok"] = @"NO";
        result[@"error"] = @"No backup executable or carrier found for this bundle";
        return result;
    } else {
        NSDictionary *replaceExecutable = PXIPRunRootDetailed(@[@"installfile", backupExecutable, executablePath]);
        result[@"replaceExecutable"] = replaceExecutable ?: @{};
        if (![replaceExecutable[@"ok"] isEqual:@"YES"]) {
            result[@"ok"] = @"NO";
            result[@"error"] = replaceExecutable[@"error"] ?: @"Failed to restore executable";
            return result;
        }
    }
    NSString *rootErr = nil;
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
    NSString *carrierPath = state[@"carrierPath"];
    NSString *backupCarrier = state[@"backupCarrier"];
    NSString *patchedCarrier = state[@"patchedCarrier"];
    result[@"carrierPath"] = carrierPath ?: @"";
    result[@"backupCarrierExists"] = (backupCarrier.length && [fm fileExistsAtPath:backupCarrier]) ? @"YES" : @"NO";
    result[@"patchedCarrierExists"] = (patchedCarrier.length && [fm fileExistsAtPath:patchedCarrier]) ? @"YES" : @"NO";
    PXIPAddLoadCommandStatus(result, @"backupCarrier", backupCarrier, dylibLoadPath);
    PXIPAddLoadCommandStatus(result, @"patchedCarrier", patchedCarrier, dylibLoadPath);
    PXIPAddLoadCommandStatus(result, @"installedCarrier", carrierPath, dylibLoadPath);
    if (carrierPath.length) {
        result[@"rootInstalledCarrierInfo"] = PXIPRunRootDetailed(@[@"fileinfo", carrierPath]);
        result[@"rootInstalledCarrierContainsLoadPath"] = PXIPRunRootDetailed(@[@"contains", carrierPath, dylibLoadPath]);
    }
    if (targetDylib.length) {
        result[@"rootTargetDylibInfo"] = PXIPRunRootDetailed(@[@"fileinfo", targetDylib]);
    }
    return result;
}

@end
