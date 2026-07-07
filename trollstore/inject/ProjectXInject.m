// ProjectXInject.m - substrate-free injected dylib bootstrap for TrollStore modes.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <string.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

static NSString *const PXInjectBaseDir = @"/var/mobile/Library/ProjectXTroll";
static NSString *const PXInjectDylibVersion = @"0.1.0";

static NSDictionary *gSnapshot = nil;
static NSString *gBundleID = nil;
static BOOL gCHooksReady = NO;
static BOOL gEnableSysctlByNameHook = NO;
static BOOL gEnableSysctlHook = NO;
static BOOL gEnableUnameHook = NO;
static BOOL gEnableDlsymHook = NO;
static BOOL gEnableDeviceMetricsHook = NO;
static BOOL gEnableMobileGestaltHook = NO;
static NSMutableDictionary *gHookStats = nil;
static __thread BOOL gRecordingStats = NO;
static NSUInteger gMobileGestaltImagesScanned = 0;
static NSUInteger gMobileGestaltSymbolsPatched = 0;
static NSUInteger gSysctlImagesScanned = 0;
static NSUInteger gSysctlSymbolsPatched = 0;
static NSUInteger gUnameImagesScanned = 0;
static NSUInteger gUnameSymbolsPatched = 0;
static NSUInteger gDlsymImagesScanned = 0;
static NSUInteger gDlsymSymbolsPatched = 0;

static id PXSnapshotObject(NSString *key) {
    id value = gSnapshot[key];
    return value == [NSNull null] ? nil : value;
}

static NSString *PXSnapshotString(NSString *key) {
    id value = PXSnapshotObject(key);
    if ([value isKindOfClass:[NSString class]] && [(NSString *)value length] > 0) return value;
    if ([value isKindOfClass:[NSNumber class]]) return [(NSNumber *)value stringValue];
    return nil;
}

static BOOL PXSnapshotBool(NSString *key, BOOL defaultValue) {
    id value = PXSnapshotObject(key);
    if ([value isKindOfClass:[NSNumber class]]) return [value boolValue];
    if ([value isKindOfClass:[NSString class]]) {
        NSString *lower = [(NSString *)value lowercaseString];
        if ([lower isEqualToString:@"yes"] || [lower isEqualToString:@"true"] || [lower isEqualToString:@"1"]) return YES;
        if ([lower isEqualToString:@"no"] || [lower isEqualToString:@"false"] || [lower isEqualToString:@"0"]) return NO;
    }
    return defaultValue;
}

static NSUInteger PXSnapshotUnsignedInteger(NSString *key);

static NSOperatingSystemVersion PXSnapshotOSVersion(void) {
    NSOperatingSystemVersion fallback = {0, 0, 0};
    NSString *version = PXSnapshotString(@"IOSVersion");
    NSArray<NSString *> *parts = [version componentsSeparatedByString:@"."];
    if (parts.count < 1) return fallback;
    NSOperatingSystemVersion osVersion = {0, 0, 0};
    osVersion.majorVersion = parts.count > 0 ? parts[0].integerValue : 0;
    osVersion.minorVersion = parts.count > 1 ? parts[1].integerValue : 0;
    osVersion.patchVersion = parts.count > 2 ? parts[2].integerValue : 0;
    return osVersion;
}

static NSString *PXHookBackendName(void) {
    BOOL objcHooks = PXSnapshotBool(@"EnableObjCHooks", NO);
    BOOL cHooks = PXSnapshotBool(@"EnableCHooks", NO);
    if (objcHooks && cHooks) return @"objc-runtime+c-hooks";
    if (objcHooks) return @"objc-runtime";
    if (cHooks) return @"c-hooks";
    return @"marker-only";
}

static BOOL PXSysctlNameEnabled(NSString *name) {
    if (!name.length) return NO;
    NSString *flag = [@"EnableSysctlName_" stringByAppendingString:name];
    return PXSnapshotBool(flag, NO);
}

static BOOL PXCopyCStringToSysctlBuffer(NSString *value, void *oldp, size_t *oldlenp) {
    if (!value.length || !oldlenp) return NO;
    const char *bytes = [value UTF8String];
    if (!bytes) return NO;
    size_t required = strlen(bytes) + 1;
    if (!oldp) {
        *oldlenp = required;
        return YES;
    }
    if (*oldlenp < required) {
        *oldlenp = required;
        errno = ENOMEM;
        return NO;
    }
    memcpy(oldp, bytes, required);
    *oldlenp = required;
    return YES;
}

static BOOL PXCopyBytesToSysctlBuffer(const void *bytes, size_t length, void *oldp, size_t *oldlenp) {
    if (!bytes || length == 0 || !oldlenp) return NO;
    if (!oldp) {
        *oldlenp = length;
        return YES;
    }
    if (*oldlenp < length) {
        *oldlenp = length;
        errno = ENOMEM;
        return NO;
    }
    memcpy(oldp, bytes, length);
    *oldlenp = length;
    return YES;
}

static BOOL PXCopyUInt32ToSysctlBuffer(uint32_t value, void *oldp, size_t *oldlenp) {
    return PXCopyBytesToSysctlBuffer(&value, sizeof(value), oldp, oldlenp);
}

static BOOL PXCopyUInt64ToSysctlBuffer(uint64_t value, void *oldp, size_t *oldlenp) {
    return PXCopyBytesToSysctlBuffer(&value, sizeof(value), oldp, oldlenp);
}

static NSString *PXMetricsValueForSysctlName(const char *name, BOOL *isUInt64Out) {
    if (isUInt64Out) *isUInt64Out = NO;
    if (!gEnableDeviceMetricsHook || !name) return nil;
    if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.activecpu") == 0) {
        NSUInteger cores = PXSnapshotUnsignedInteger(@"CPUCoreCount");
        return cores > 0 ? [@(cores) stringValue] : nil;
    }
    if (strcmp(name, "hw.memsize") == 0) {
        NSUInteger gb = PXSnapshotUnsignedInteger(@"DeviceMemory");
        if (isUInt64Out) *isUInt64Out = YES;
        return gb > 0 ? [@((uint64_t)gb * 1024ULL * 1024ULL * 1024ULL) stringValue] : nil;
    }
    return nil;
}

static NSString *PXValueForSysctlName(const char *name) {
    if (!name) return nil;
    if (strcmp(name, "hw.machine") == 0 && PXSysctlNameEnabled(@"hw.machine")) return PXSnapshotString(@"DeviceModel");
    if (strcmp(name, "hw.model") == 0 && PXSysctlNameEnabled(@"hw.model")) return PXSnapshotString(@"HwModel") ?: PXSnapshotString(@"BoardID");
    if (strcmp(name, "kern.osversion") == 0 && PXSysctlNameEnabled(@"kern.osversion")) return PXSnapshotString(@"IOSBuild");
    if (strcmp(name, "kern.version") == 0 && PXSysctlNameEnabled(@"kern.version")) return PXSnapshotString(@"KernelVersion");
    return nil;
}

static NSString *PXValueForSysctlMIB(const int *name, u_int namelen, NSString **nameOut) {
    if (!name || namelen < 2) return nil;
    NSString *sysctlName = nil;
    NSString *value = nil;

    if (name[0] == CTL_HW && name[1] == HW_MACHINE) {
        sysctlName = @"hw.machine";
        value = PXSysctlNameEnabled(sysctlName) ? PXSnapshotString(@"DeviceModel") : nil;
    } else if (name[0] == CTL_HW && name[1] == HW_MODEL) {
        sysctlName = @"hw.model";
        value = PXSysctlNameEnabled(sysctlName) ? (PXSnapshotString(@"HwModel") ?: PXSnapshotString(@"BoardID")) : nil;
    } else if (name[0] == CTL_KERN && name[1] == KERN_OSVERSION) {
        sysctlName = @"kern.osversion";
        value = PXSysctlNameEnabled(sysctlName) ? PXSnapshotString(@"IOSBuild") : nil;
    } else if (name[0] == CTL_KERN && name[1] == KERN_VERSION) {
        sysctlName = @"kern.version";
        value = PXSysctlNameEnabled(sysctlName) ? PXSnapshotString(@"KernelVersion") : nil;
#ifdef HW_NCPU
    } else if (gEnableDeviceMetricsHook && name[0] == CTL_HW && name[1] == HW_NCPU) {
        sysctlName = @"hw.ncpu";
        NSUInteger cores = PXSnapshotUnsignedInteger(@"CPUCoreCount");
        value = cores > 0 ? [@(cores) stringValue] : nil;
#endif
#ifdef HW_ACTIVECPU
    } else if (gEnableDeviceMetricsHook && name[0] == CTL_HW && name[1] == HW_ACTIVECPU) {
        sysctlName = @"hw.activecpu";
        NSUInteger cores = PXSnapshotUnsignedInteger(@"CPUCoreCount");
        value = cores > 0 ? [@(cores) stringValue] : nil;
#endif
#ifdef HW_MEMSIZE
    } else if (gEnableDeviceMetricsHook && name[0] == CTL_HW && name[1] == HW_MEMSIZE) {
        sysctlName = @"hw.memsize";
        NSUInteger gb = PXSnapshotUnsignedInteger(@"DeviceMemory");
        value = gb > 0 ? [@((uint64_t)gb * 1024ULL * 1024ULL * 1024ULL) stringValue] : nil;
#endif
    }

    if (nameOut) *nameOut = sysctlName;
    return value;
}

static CGSize PXSnapshotSize(NSString *key) {
    NSString *value = PXSnapshotString(key);
    if (!value.length) return CGSizeZero;
    NSArray<NSString *> *parts = [value componentsSeparatedByString:@"x"];
    if (parts.count != 2) parts = [value componentsSeparatedByString:@"X"];
    if (parts.count != 2) return CGSizeZero;
    CGFloat width = parts[0].doubleValue;
    CGFloat height = parts[1].doubleValue;
    return (width > 0 && height > 0) ? CGSizeMake(width, height) : CGSizeZero;
}

static double PXSnapshotDouble(NSString *key) {
    id value = PXSnapshotObject(key);
    if ([value isKindOfClass:[NSNumber class]]) return [(NSNumber *)value doubleValue];
    if ([value isKindOfClass:[NSString class]]) return [(NSString *)value doubleValue];
    return 0;
}

static NSUInteger PXSnapshotUnsignedInteger(NSString *key) {
    id value = PXSnapshotObject(key);
    if ([value isKindOfClass:[NSNumber class]]) return [(NSNumber *)value unsignedIntegerValue];
    if ([value isKindOfClass:[NSString class]]) return (NSUInteger)[(NSString *)value longLongValue];
    return 0;
}

static NSString *PXSafeBundleID(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    return bid.length ? bid : [[NSProcessInfo processInfo] processName];
}

static NSString *PXNormalizePath(NSString *path) {
    if ([path hasPrefix:@"/private/var/"]) return [path stringByReplacingOccurrencesOfString:@"/private/var/" withString:@"/var/" options:0 range:NSMakeRange(0, @"/private/var/".length)];
    return path ?: @"";
}

static BOOL PXShouldRebindImagePath(NSString *path, NSString *bundlePath) {
    if (!path.length) return NO;
    if (bundlePath.length && ![path hasPrefix:bundlePath]) return NO;
    if ([path.lastPathComponent isEqualToString:@"ProjectXInject.dylib"]) return NO;
    return YES;
}

static NSString *PXSnapshotPathForBundleID(NSString *bundleID) {
    NSString *name = bundleID.length ? bundleID : @"unknown";
    return [[[PXInjectBaseDir stringByAppendingPathComponent:@"RuntimeSnapshots"] stringByAppendingPathComponent:name] stringByAppendingPathExtension:@"plist"];
}

static NSString *PXLocalProjectXDirectory(void) {
    return [[NSHomeDirectory() stringByAppendingPathComponent:@"Library"] stringByAppendingPathComponent:@"ProjectX"];
}

static NSString *PXLocalSnapshotPath(void) {
    return [PXLocalProjectXDirectory() stringByAppendingPathComponent:@"runtime_snapshot.plist"];
}

static NSString *PXLocalMarkerPath(void) {
    return [PXLocalProjectXDirectory() stringByAppendingPathComponent:@"loaded_marker.plist"];
}

static NSString *PXLocalHookStatsPath(void) {
    return [PXLocalProjectXDirectory() stringByAppendingPathComponent:@"hook_stats.plist"];
}

static NSString *PXMarkerPathForBundleID(NSString *bundleID) {
    NSString *name = bundleID.length ? bundleID : @"unknown";
    return [[[PXInjectBaseDir stringByAppendingPathComponent:@"InjectionLogs"] stringByAppendingPathComponent:name] stringByAppendingPathExtension:@"loaded.plist"];
}

static void PXInjectLog(NSString *format, ...) {
    if (!format.length) return;
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSString *dir = [PXInjectBaseDir stringByAppendingPathComponent:@"InjectionLogs"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:PXLocalProjectXDirectory() withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *path = [[dir stringByAppendingPathComponent:gBundleID ?: @"unknown"] stringByAppendingPathExtension:@"log"];
    NSString *localPath = [PXLocalProjectXDirectory() stringByAppendingPathComponent:@"inject.log"];
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], message ?: @""];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    if (data) {
        if (![[NSFileManager defaultManager] fileExistsAtPath:localPath]) {
            [data writeToFile:localPath atomically:YES];
        } else {
            NSFileHandle *lfh = [NSFileHandle fileHandleForWritingAtPath:localPath];
            [lfh seekToEndOfFile];
            [lfh writeData:data];
            [lfh closeFile];
        }
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [data writeToFile:path atomically:YES];
        return;
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    [fh seekToEndOfFile];
    [fh writeData:data];
    [fh closeFile];
}

static void PXRecordHookCall(NSString *category, NSString *name, NSString *value, BOOL spoofed, BOOL copied) {
    if (!category.length || !name.length) return;
    if (gRecordingStats) return;
    gRecordingStats = YES;
    @autoreleasepool {
        [[NSFileManager defaultManager] createDirectoryAtPath:PXLocalProjectXDirectory() withIntermediateDirectories:YES attributes:nil error:nil];
        if (!gHookStats) {
            gHookStats = [@{@"bundleID": gBundleID ?: @"",
                            @"processName": [[NSProcessInfo processInfo] processName] ?: @"",
                            @"processID": @([[NSProcessInfo processInfo] processIdentifier]),
                            @"CHookTestMode": PXSnapshotString(@"CHookTestMode") ?: @"",
                            @"createdAt": @([[NSDate date] timeIntervalSince1970]),
                            @"totalCalls": @0,
                            @"categories": [NSMutableDictionary dictionary]} mutableCopy];
        }

        NSUInteger total = [gHookStats[@"totalCalls"] unsignedIntegerValue] + 1;
        gHookStats[@"totalCalls"] = @(total);
        gHookStats[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
        gHookStats[@"lastCategory"] = category;
        gHookStats[@"lastName"] = name;

        NSMutableDictionary *categories = gHookStats[@"categories"];
        if (![categories isKindOfClass:[NSMutableDictionary class]]) {
            categories = [NSMutableDictionary dictionary];
            gHookStats[@"categories"] = categories;
        }
        NSMutableDictionary *entries = categories[category];
        if (![entries isKindOfClass:[NSMutableDictionary class]]) {
            entries = [NSMutableDictionary dictionary];
            categories[category] = entries;
        }
        NSMutableDictionary *entry = entries[name];
        if (![entry isKindOfClass:[NSMutableDictionary class]]) {
            entry = [NSMutableDictionary dictionary];
            entries[name] = entry;
        }
        entry[@"calls"] = @([entry[@"calls"] unsignedIntegerValue] + 1);
        entry[@"spoofed"] = @([entry[@"spoofed"] unsignedIntegerValue] + (spoofed ? 1 : 0));
        entry[@"copied"] = @([entry[@"copied"] unsignedIntegerValue] + (copied ? 1 : 0));
        entry[@"lastValue"] = value ?: @"";
        entry[@"lastAt"] = @([[NSDate date] timeIntervalSince1970]);

        if (total <= 120 || total % 25 == 0) {
            [gHookStats writeToFile:PXLocalHookStatsPath() atomically:YES];
        }
    }
    gRecordingStats = NO;
}

static void PXLoadSnapshot(void) {
    gBundleID = PXSafeBundleID();
    NSString *localPath = PXLocalSnapshotPath();
    NSString *path = [[NSFileManager defaultManager] fileExistsAtPath:localPath] ? localPath : PXSnapshotPathForBundleID(gBundleID);
    NSDictionary *snapshot = [NSDictionary dictionaryWithContentsOfFile:path];
    if ([snapshot isKindOfClass:[NSDictionary class]]) {
        gSnapshot = [snapshot copy];
        PXInjectLog(@"loaded snapshot path=%@ keys=%lu", path, (unsigned long)gSnapshot.count);
    } else {
        gSnapshot = @{};
        PXInjectLog(@"snapshot missing path=%@", path);
    }
}

static void PXWriteLoadedMarker(void) {
    [[NSFileManager defaultManager] createDirectoryAtPath:PXLocalProjectXDirectory() withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *dir = [PXInjectBaseDir stringByAppendingPathComponent:@"InjectionLogs"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSDictionary *marker = @{
        @"bundleID": gBundleID ?: @"",
        @"processName": [[NSProcessInfo processInfo] processName] ?: @"",
        @"dylibVersion": PXInjectDylibVersion,
        @"profileId": PXSnapshotString(@"profileId") ?: @"",
        @"generation": PXSnapshotObject(@"generation") ?: @0,
        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
        @"hookBackend": PXHookBackendName(),
        @"EnableObjCHooks": @(PXSnapshotBool(@"EnableObjCHooks", NO)),
        @"EnableCHooks": @(PXSnapshotBool(@"EnableCHooks", NO)),
        @"CHookTestMode": PXSnapshotString(@"CHookTestMode") ?: @"",
        @"EnableSysctlByNameHook": @(PXSnapshotBool(@"EnableSysctlByNameHook", NO)),
        @"EnableSysctlHook": @(PXSnapshotBool(@"EnableSysctlHook", NO)),
        @"EnableUnameHook": @(PXSnapshotBool(@"EnableUnameHook", NO)),
        @"EnableDlsymHook": @(PXSnapshotBool(@"EnableDlsymHook", NO)),
        @"EnableDeviceMetricsHook": @(PXSnapshotBool(@"EnableDeviceMetricsHook", NO)),
        @"EnableMobileGestaltHook": @(PXSnapshotBool(@"EnableMobileGestaltHook", NO)),
        @"processID": @([[NSProcessInfo processInfo] processIdentifier]),
        @"hookStatsPath": PXLocalHookStatsPath(),
        @"snapshotPath": PXSnapshotPathForBundleID(gBundleID ?: @""),
    };
    [marker writeToFile:PXLocalMarkerPath() atomically:YES];
    NSString *path = PXMarkerPathForBundleID(gBundleID);
    [marker writeToFile:path atomically:YES];
    PXInjectLog(@"wrote loaded marker path=%@", path);
}

static void PXReplaceInstanceMethod(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls || !sel || !newImp) return;
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) return;
    IMP old = method_setImplementation(method, newImp);
    if (origOut) *origOut = old;
    PXInjectLog(@"hooked %@ %@", NSStringFromClass(cls), NSStringFromSelector(sel));
}

static NSString *(*orig_UIDevice_name)(id, SEL) = NULL;
static NSString *(*orig_UIDevice_model)(id, SEL) = NULL;
static NSString *(*orig_UIDevice_localizedModel)(id, SEL) = NULL;
static NSString *(*orig_UIDevice_systemName)(id, SEL) = NULL;
static NSString *(*orig_UIDevice_systemVersion)(id, SEL) = NULL;
static NSUUID *(*orig_UIDevice_identifierForVendor)(id, SEL) = NULL;
static NSString *(*orig_NSProcessInfo_operatingSystemVersionString)(id, SEL) = NULL;
static NSOperatingSystemVersion (*orig_NSProcessInfo_operatingSystemVersion)(id, SEL) = NULL;
static NSUInteger (*orig_NSProcessInfo_processorCount)(id, SEL) = NULL;
static NSUInteger (*orig_NSProcessInfo_activeProcessorCount)(id, SEL) = NULL;
static unsigned long long (*orig_NSProcessInfo_physicalMemory)(id, SEL) = NULL;
static CGRect (*orig_UIScreen_bounds)(id, SEL) = NULL;
static CGRect (*orig_UIScreen_nativeBounds)(id, SEL) = NULL;
static CGFloat (*orig_UIScreen_scale)(id, SEL) = NULL;
static CGFloat (*orig_UIScreen_nativeScale)(id, SEL) = NULL;

static NSString *px_UIDevice_name(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"DeviceName");
    PXRecordHookCall(@"objc", @"UIDevice.name", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_UIDevice_name ? orig_UIDevice_name(self, _cmd) : @"iPhone");
}

static NSString *px_UIDevice_model(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"DeviceModelName") ?: PXSnapshotString(@"DeviceModel");
    PXRecordHookCall(@"objc", @"UIDevice.model", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_UIDevice_model ? orig_UIDevice_model(self, _cmd) : @"iPhone");
}

static NSString *px_UIDevice_localizedModel(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"DeviceModelName") ?: PXSnapshotString(@"DeviceModel");
    PXRecordHookCall(@"objc", @"UIDevice.localizedModel", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_UIDevice_localizedModel ? orig_UIDevice_localizedModel(self, _cmd) : @"iPhone");
}

static NSString *px_UIDevice_systemName(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"SystemName");
    PXRecordHookCall(@"objc", @"UIDevice.systemName", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_UIDevice_systemName ? orig_UIDevice_systemName(self, _cmd) : @"iOS");
}

static NSString *px_UIDevice_systemVersion(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"IOSVersion");
    PXRecordHookCall(@"objc", @"UIDevice.systemVersion", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_UIDevice_systemVersion ? orig_UIDevice_systemVersion(self, _cmd) : @"");
}

static NSUUID *px_UIDevice_identifierForVendor(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"IDFV");
    NSUUID *uuid = value.length ? [[NSUUID alloc] initWithUUIDString:value] : nil;
    PXRecordHookCall(@"objc", @"UIDevice.identifierForVendor", value ?: @"", uuid != nil, uuid != nil);
    return uuid ?: (orig_UIDevice_identifierForVendor ? orig_UIDevice_identifierForVendor(self, _cmd) : nil);
}

static NSString *px_NSProcessInfo_operatingSystemVersionString(id self, SEL _cmd) {
    NSString *version = PXSnapshotString(@"IOSVersion");
    NSString *build = PXSnapshotString(@"IOSBuild");
    PXRecordHookCall(@"objc", @"NSProcessInfo.operatingSystemVersionString", version ?: @"", version.length > 0, version.length > 0);
    if (version.length && build.length) return [NSString stringWithFormat:@"Version %@ (Build %@)", version, build];
    if (version.length) return [NSString stringWithFormat:@"Version %@", version];
    return orig_NSProcessInfo_operatingSystemVersionString ? orig_NSProcessInfo_operatingSystemVersionString(self, _cmd) : @"";
}

static NSOperatingSystemVersion px_NSProcessInfo_operatingSystemVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion version = PXSnapshotOSVersion();
    PXRecordHookCall(@"objc", @"NSProcessInfo.operatingSystemVersion", PXSnapshotString(@"IOSVersion") ?: @"", version.majorVersion > 0, version.majorVersion > 0);
    if (version.majorVersion > 0) return version;
    return orig_NSProcessInfo_operatingSystemVersion ? orig_NSProcessInfo_operatingSystemVersion(self, _cmd) : version;
}

static NSUInteger px_NSProcessInfo_processorCount(id self, SEL _cmd) {
    NSUInteger value = gEnableDeviceMetricsHook ? PXSnapshotUnsignedInteger(@"CPUCoreCount") : 0;
    PXRecordHookCall(@"metrics", @"NSProcessInfo.processorCount", value ? [@(value) stringValue] : @"", value > 0, value > 0);
    return value > 0 ? value : (orig_NSProcessInfo_processorCount ? orig_NSProcessInfo_processorCount(self, _cmd) : 1);
}

static NSUInteger px_NSProcessInfo_activeProcessorCount(id self, SEL _cmd) {
    NSUInteger value = gEnableDeviceMetricsHook ? PXSnapshotUnsignedInteger(@"CPUCoreCount") : 0;
    PXRecordHookCall(@"metrics", @"NSProcessInfo.activeProcessorCount", value ? [@(value) stringValue] : @"", value > 0, value > 0);
    return value > 0 ? value : (orig_NSProcessInfo_activeProcessorCount ? orig_NSProcessInfo_activeProcessorCount(self, _cmd) : 1);
}

static unsigned long long px_NSProcessInfo_physicalMemory(id self, SEL _cmd) {
    NSUInteger gb = gEnableDeviceMetricsHook ? PXSnapshotUnsignedInteger(@"DeviceMemory") : 0;
    unsigned long long value = gb > 0 ? (unsigned long long)gb * 1024ULL * 1024ULL * 1024ULL : 0;
    PXRecordHookCall(@"metrics", @"NSProcessInfo.physicalMemory", value ? [@(value) stringValue] : @"", value > 0, value > 0);
    return value > 0 ? value : (orig_NSProcessInfo_physicalMemory ? orig_NSProcessInfo_physicalMemory(self, _cmd) : 0);
}

static CGRect px_UIScreen_bounds(id self, SEL _cmd) {
    CGSize viewport = gEnableDeviceMetricsHook ? PXSnapshotSize(@"ViewportResolution") : CGSizeZero;
    if (viewport.width > 0 && viewport.height > 0) {
        CGRect rect = CGRectMake(0, 0, viewport.width, viewport.height);
        PXRecordHookCall(@"metrics", @"UIScreen.bounds", NSStringFromCGSize(viewport), YES, YES);
        return rect;
    }
    return orig_UIScreen_bounds ? orig_UIScreen_bounds(self, _cmd) : CGRectZero;
}

static CGRect px_UIScreen_nativeBounds(id self, SEL _cmd) {
    CGSize screen = gEnableDeviceMetricsHook ? PXSnapshotSize(@"ScreenResolution") : CGSizeZero;
    if (screen.width > 0 && screen.height > 0) {
        CGRect rect = CGRectMake(0, 0, screen.width, screen.height);
        PXRecordHookCall(@"metrics", @"UIScreen.nativeBounds", NSStringFromCGSize(screen), YES, YES);
        return rect;
    }
    return orig_UIScreen_nativeBounds ? orig_UIScreen_nativeBounds(self, _cmd) : CGRectZero;
}

static CGFloat px_UIScreen_scale(id self, SEL _cmd) {
    double value = gEnableDeviceMetricsHook ? PXSnapshotDouble(@"DevicePixelRatio") : 0;
    PXRecordHookCall(@"metrics", @"UIScreen.scale", value > 0 ? [@(value) stringValue] : @"", value > 0, value > 0);
    return value > 0 ? (CGFloat)value : (orig_UIScreen_scale ? orig_UIScreen_scale(self, _cmd) : 1.0);
}

static CGFloat px_UIScreen_nativeScale(id self, SEL _cmd) {
    double value = gEnableDeviceMetricsHook ? PXSnapshotDouble(@"DevicePixelRatio") : 0;
    PXRecordHookCall(@"metrics", @"UIScreen.nativeScale", value > 0 ? [@(value) stringValue] : @"", value > 0, value > 0);
    return value > 0 ? (CGFloat)value : (orig_UIScreen_nativeScale ? orig_UIScreen_nativeScale(self, _cmd) : 1.0);
}

static void PXInstallObjCHooks(void) {
    Class device = objc_getClass("UIDevice");
    PXReplaceInstanceMethod(device, @selector(name), (IMP)px_UIDevice_name, (IMP *)&orig_UIDevice_name);
    PXReplaceInstanceMethod(device, @selector(model), (IMP)px_UIDevice_model, (IMP *)&orig_UIDevice_model);
    PXReplaceInstanceMethod(device, @selector(localizedModel), (IMP)px_UIDevice_localizedModel, (IMP *)&orig_UIDevice_localizedModel);
    PXReplaceInstanceMethod(device, @selector(systemName), (IMP)px_UIDevice_systemName, (IMP *)&orig_UIDevice_systemName);
    PXReplaceInstanceMethod(device, @selector(systemVersion), (IMP)px_UIDevice_systemVersion, (IMP *)&orig_UIDevice_systemVersion);
    PXReplaceInstanceMethod(device, @selector(identifierForVendor), (IMP)px_UIDevice_identifierForVendor, (IMP *)&orig_UIDevice_identifierForVendor);

    Class processInfo = objc_getClass("NSProcessInfo");
    PXReplaceInstanceMethod(processInfo, @selector(operatingSystemVersionString), (IMP)px_NSProcessInfo_operatingSystemVersionString, (IMP *)&orig_NSProcessInfo_operatingSystemVersionString);
    PXReplaceInstanceMethod(processInfo, @selector(operatingSystemVersion), (IMP)px_NSProcessInfo_operatingSystemVersion, (IMP *)&orig_NSProcessInfo_operatingSystemVersion);

    if (gEnableDeviceMetricsHook) {
        PXReplaceInstanceMethod(processInfo, @selector(processorCount), (IMP)px_NSProcessInfo_processorCount, (IMP *)&orig_NSProcessInfo_processorCount);
        PXReplaceInstanceMethod(processInfo, @selector(activeProcessorCount), (IMP)px_NSProcessInfo_activeProcessorCount, (IMP *)&orig_NSProcessInfo_activeProcessorCount);
        PXReplaceInstanceMethod(processInfo, @selector(physicalMemory), (IMP)px_NSProcessInfo_physicalMemory, (IMP *)&orig_NSProcessInfo_physicalMemory);

        Class screen = objc_getClass("UIScreen");
        PXReplaceInstanceMethod(screen, @selector(bounds), (IMP)px_UIScreen_bounds, (IMP *)&orig_UIScreen_bounds);
        PXReplaceInstanceMethod(screen, @selector(nativeBounds), (IMP)px_UIScreen_nativeBounds, (IMP *)&orig_UIScreen_nativeBounds);
        PXReplaceInstanceMethod(screen, @selector(scale), (IMP)px_UIScreen_scale, (IMP *)&orig_UIScreen_scale);
        PXReplaceInstanceMethod(screen, @selector(nativeScale), (IMP)px_UIScreen_nativeScale, (IMP *)&orig_UIScreen_nativeScale);
    }
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;
static void *(*orig_dlsym)(void *, const char *) = NULL;
static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef) = NULL;
static CFTypeRef (*orig_MGCopyAnswerWithError)(CFStringRef, int *) = NULL;

static int px_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int px_uname(struct utsname *value);
static void *px_dlsym(void *handle, const char *symbol);

static CFTypeRef PXCopyRetainedString(NSString *value) {
    return value.length ? CFBridgingRetain(value) : NULL;
}

static CFTypeRef PXMobileGestaltSpoofValue(CFStringRef property) {
    if (!property) return NULL;
    NSString *key = (__bridge NSString *)property;
    if (![key isKindOfClass:[NSString class]] || !key.length) return NULL;

    if ([key isEqualToString:@"ProductType"] || [key isEqualToString:@"DeviceClassNumber"] || [key isEqualToString:@"HardwarePlatform"] || [key isEqualToString:@"HWModelStr"]) {
        return PXCopyRetainedString(PXSnapshotString(@"DeviceModel") ?: PXSnapshotString(@"HwModel") ?: PXSnapshotString(@"BoardID"));
    }
    if ([key isEqualToString:@"ProductName"]) {
        return PXCopyRetainedString(PXSnapshotString(@"SystemName") ?: @"iOS");
    }
    if ([key isEqualToString:@"ProductVersion"]) {
        return PXCopyRetainedString(PXSnapshotString(@"IOSVersion"));
    }
    if ([key isEqualToString:@"BuildVersion"] || [key isEqualToString:@"ReleaseType"]) {
        return PXCopyRetainedString(PXSnapshotString(@"IOSBuild"));
    }
    if ([key isEqualToString:@"UserAssignedDeviceName"]) {
        return PXCopyRetainedString(PXSnapshotString(@"DeviceName"));
    }
    if ([key isEqualToString:@"MarketingProductName"] || [key isEqualToString:@"DeviceVariant"]) {
        return PXCopyRetainedString(PXSnapshotString(@"DeviceModelName") ?: PXSnapshotString(@"DeviceModel"));
    }
    if ([key isEqualToString:@"BoardId"] || [key isEqualToString:@"BoardID"]) {
        return PXCopyRetainedString(PXSnapshotString(@"BoardID") ?: PXSnapshotString(@"HwModel"));
    }
    return NULL;
}

static CFTypeRef px_MGCopyAnswer(CFStringRef property) {
    if (gCHooksReady && gEnableMobileGestaltHook) {
        CFTypeRef value = PXMobileGestaltSpoofValue(property);
        NSString *key = property ? (__bridge NSString *)property : @"";
        if (value) {
            PXRecordHookCall(@"MobileGestalt", key ?: @"", [(__bridge id)value description] ?: @"", YES, YES);
            return value;
        }
        PXRecordHookCall(@"MobileGestalt", key ?: @"", @"", NO, NO);
    }
    return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
}

static CFTypeRef px_MGCopyAnswerWithError(CFStringRef property, int *error) {
    if (gCHooksReady && gEnableMobileGestaltHook) {
        CFTypeRef value = PXMobileGestaltSpoofValue(property);
        NSString *key = property ? (__bridge NSString *)property : @"";
        if (value) {
            if (error) *error = 0;
            PXRecordHookCall(@"MobileGestaltWithError", key ?: @"", [(__bridge id)value description] ?: @"", YES, YES);
            return value;
        }
        PXRecordHookCall(@"MobileGestaltWithError", key ?: @"", @"", NO, NO);
    }
    return orig_MGCopyAnswerWithError ? orig_MGCopyAnswerWithError(property, error) : NULL;
}

static uintptr_t PXSlideForHeader(const struct mach_header_64 *header) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if ((const struct mach_header_64 *)_dyld_get_image_header(i) == header) {
            return (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        }
    }
    return 0;
}

static NSUInteger PXRebindSymbolInImage(const struct mach_header_64 *header, const char *symbolName, const void *replacement, void **originalOut) {
    if (!header || header->magic != MH_MAGIC_64 || !symbolName || !replacement) return 0;

    uintptr_t slide = PXSlideForHeader(header);
    const struct load_command *cmd = (const struct load_command *)((const uint8_t *)header + sizeof(struct mach_header_64));
    const struct segment_command_64 *linkedit = NULL;
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) linkedit = seg;
        } else if (cmd->cmd == LC_SYMTAB) {
            symtab = (const struct symtab_command *)cmd;
        } else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtab = (const struct dysymtab_command *)cmd;
        }
        cmd = (const struct load_command *)((const uint8_t *)cmd + cmd->cmdsize);
    }
    if (!linkedit || !symtab || !dysymtab) return 0;

    uintptr_t linkeditBase = slide + linkedit->vmaddr - linkedit->fileoff;
    const struct nlist_64 *symbols = (const struct nlist_64 *)(linkeditBase + symtab->symoff);
    const char *strings = (const char *)(linkeditBase + symtab->stroff);
    const uint32_t *indirectSymbols = (const uint32_t *)(linkeditBase + dysymtab->indirectsymoff);

    NSUInteger patched = 0;
    cmd = (const struct load_command *)((const uint8_t *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            const struct section_64 *section = (const struct section_64 *)((const uint8_t *)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                uint32_t sectionType = section[j].flags & SECTION_TYPE;
                if (sectionType != S_LAZY_SYMBOL_POINTERS && sectionType != S_NON_LAZY_SYMBOL_POINTERS) continue;
                uint32_t indirectIndex = section[j].reserved1;
                uint32_t pointerCount = (uint32_t)(section[j].size / sizeof(void *));
                void **pointers = (void **)(slide + section[j].addr);
                for (uint32_t k = 0; k < pointerCount; k++) {
                    uint32_t symIndex = indirectSymbols[indirectIndex + k];
                    if (symIndex == INDIRECT_SYMBOL_ABS || symIndex == INDIRECT_SYMBOL_LOCAL || symIndex == (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) continue;
                    const char *name = strings + symbols[symIndex].n_un.n_strx;
                    if (!name || strcmp(name, symbolName) != 0) continue;
                    if (originalOut && !*originalOut) *originalOut = pointers[k];
                    vm_address_t page = (vm_address_t)((uintptr_t)&pointers[k] & ~(uintptr_t)(vm_page_size - 1));
                    vm_protect(mach_task_self(), page, vm_page_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                    pointers[k] = (void *)replacement;
                    patched++;
                    PXRecordHookCall(@"rebind", [NSString stringWithUTF8String:symbolName] ?: @"", @"patched", YES, YES);
                }
            }
        }
        cmd = (const struct load_command *)((const uint8_t *)cmd + cmd->cmdsize);
    }
    return patched;
}

static void PXRebindMobileGestalt(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (!PXShouldRebindImagePath(path, bundlePath)) continue;
        gMobileGestaltImagesScanned++;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        gMobileGestaltSymbolsPatched += PXRebindSymbolInImage(header, "_MGCopyAnswer", (const void *)px_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        gMobileGestaltSymbolsPatched += PXRebindSymbolInImage(header, "_MGCopyAnswerWithError", (const void *)px_MGCopyAnswerWithError, (void **)&orig_MGCopyAnswerWithError);
    }
    PXRecordHookCall(@"rebind-summary", @"MobileGestalt", [NSString stringWithFormat:@"images=%lu patched=%lu", (unsigned long)gMobileGestaltImagesScanned, (unsigned long)gMobileGestaltSymbolsPatched], gMobileGestaltSymbolsPatched > 0, gMobileGestaltSymbolsPatched > 0);
}

static void PXRebindSysctl(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (!PXShouldRebindImagePath(path, bundlePath)) continue;
        gSysctlImagesScanned++;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        gSysctlSymbolsPatched += PXRebindSymbolInImage(header, "_sysctl", (const void *)px_sysctl, (void **)&orig_sysctl);
    }
    PXRecordHookCall(@"rebind-summary", @"sysctl", [NSString stringWithFormat:@"images=%lu patched=%lu", (unsigned long)gSysctlImagesScanned, (unsigned long)gSysctlSymbolsPatched], gSysctlSymbolsPatched > 0, gSysctlSymbolsPatched > 0);
}

static void PXRebindUname(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (!PXShouldRebindImagePath(path, bundlePath)) continue;
        gUnameImagesScanned++;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        gUnameSymbolsPatched += PXRebindSymbolInImage(header, "_uname", (const void *)px_uname, (void **)&orig_uname);
    }
    PXRecordHookCall(@"rebind-summary", @"uname", [NSString stringWithFormat:@"images=%lu patched=%lu", (unsigned long)gUnameImagesScanned, (unsigned long)gUnameSymbolsPatched], gUnameSymbolsPatched > 0, gUnameSymbolsPatched > 0);
}

static void PXRebindDlsym(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (!PXShouldRebindImagePath(path, bundlePath)) continue;
        gDlsymImagesScanned++;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        gDlsymSymbolsPatched += PXRebindSymbolInImage(header, "_dlsym", (const void *)px_dlsym, (void **)&orig_dlsym);
    }
    PXRecordHookCall(@"rebind-summary", @"dlsym", [NSString stringWithFormat:@"images=%lu patched=%lu", (unsigned long)gDlsymImagesScanned, (unsigned long)gDlsymSymbolsPatched], gDlsymSymbolsPatched > 0, gDlsymSymbolsPatched > 0);
}

static int PXCallOrigSysctlByName(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctlbyname) orig_sysctlbyname = dlsym(RTLD_NEXT, "sysctlbyname");
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

static int PXCallOrigSysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctl) orig_sysctl = dlsym(RTLD_NEXT, "sysctl");
    return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
}

static int PXCallOrigUname(struct utsname *value) {
    if (!orig_uname) orig_uname = dlsym(RTLD_NEXT, "uname");
    return orig_uname ? orig_uname(value) : -1;
}

static void *PXCallOrigDlsym(void *handle, const char *symbol) {
    if (!orig_dlsym) orig_dlsym = dlsym(RTLD_NEXT, "dlsym");
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int px_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (gCHooksReady && gEnableSysctlByNameHook && name && !newp && newlen == 0) {
        BOOL isUInt64 = NO;
        NSString *metricsValue = PXMetricsValueForSysctlName(name, &isUInt64);
        if (metricsValue.length) {
            BOOL copied = NO;
            if (isUInt64) {
                copied = PXCopyUInt64ToSysctlBuffer((uint64_t)metricsValue.longLongValue, oldp, oldlenp);
            } else {
                copied = PXCopyUInt32ToSysctlBuffer((uint32_t)metricsValue.longLongValue, oldp, oldlenp);
            }
            PXRecordHookCall(@"sysctlbyname-metrics", [NSString stringWithUTF8String:name] ?: @"", metricsValue, YES, copied);
            PXInjectLog(@"c-hook mode=%@ sysctlbyname metrics %s -> %@ copied=%@", PXSnapshotString(@"CHookTestMode") ?: @"", name, metricsValue, copied ? @"YES" : @"NO");
            return copied ? 0 : -1;
        }
        NSString *value = PXValueForSysctlName(name);
        if (value.length) {
            BOOL copied = PXCopyCStringToSysctlBuffer(value, oldp, oldlenp);
            PXRecordHookCall(@"sysctlbyname", [NSString stringWithUTF8String:name] ?: @"", value, YES, copied);
            PXInjectLog(@"c-hook mode=%@ sysctlbyname %s -> %@ copied=%@", PXSnapshotString(@"CHookTestMode") ?: @"", name, value, copied ? @"YES" : @"NO");
            return copied ? 0 : -1;
        }
        PXRecordHookCall(@"sysctlbyname", [NSString stringWithUTF8String:name] ?: @"", @"", NO, NO);
    }
    return PXCallOrigSysctlByName(name, oldp, oldlenp, newp, newlen);
}

static int px_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (gCHooksReady && gEnableSysctlHook && name && !newp && newlen == 0) {
        NSString *sysctlName = nil;
        NSString *value = PXValueForSysctlMIB(name, namelen, &sysctlName);
        if (sysctlName.length) {
            if (value.length) {
                BOOL copied = NO;
                BOOL metricsInteger = [sysctlName isEqualToString:@"hw.ncpu"] || [sysctlName isEqualToString:@"hw.activecpu"] || [sysctlName isEqualToString:@"hw.memsize"];
                if ([sysctlName isEqualToString:@"hw.memsize"]) {
                    copied = PXCopyUInt64ToSysctlBuffer((uint64_t)value.longLongValue, oldp, oldlenp);
                } else if (metricsInteger) {
                    copied = PXCopyUInt32ToSysctlBuffer((uint32_t)value.longLongValue, oldp, oldlenp);
                } else {
                    copied = PXCopyCStringToSysctlBuffer(value, oldp, oldlenp);
                }
                PXRecordHookCall(@"sysctl", sysctlName, value, YES, copied);
                PXInjectLog(@"c-hook mode=%@ sysctl %@ -> %@ copied=%@", PXSnapshotString(@"CHookTestMode") ?: @"", sysctlName, value, copied ? @"YES" : @"NO");
                return copied ? 0 : -1;
            }
            PXRecordHookCall(@"sysctl", sysctlName, @"", NO, NO);
        }
    }
    return PXCallOrigSysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int px_uname(struct utsname *value) {
    int result = PXCallOrigUname(value);
    if (gCHooksReady && gEnableUnameHook && result == 0 && value) {
        NSString *machine = PXSnapshotString(@"DeviceModel");
        if (machine.length) {
            strlcpy(value->machine, machine.UTF8String, sizeof(value->machine));
            PXRecordHookCall(@"uname", @"machine", machine, YES, YES);
            PXInjectLog(@"c-hook mode=%@ uname machine -> %@", PXSnapshotString(@"CHookTestMode") ?: @"", machine);
        } else {
            PXRecordHookCall(@"uname", @"machine", @"", NO, NO);
        }
    }
    return result;
}

static void *px_dlsym(void *handle, const char *symbol) {
    if (gCHooksReady && gEnableDlsymHook && symbol) {
        NSString *name = [NSString stringWithUTF8String:symbol] ?: @"";
        if ([name isEqualToString:@"MGCopyAnswer"] && gEnableMobileGestaltHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_MGCopyAnswer;
        }
        if ([name isEqualToString:@"MGCopyAnswerWithError"] && gEnableMobileGestaltHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_MGCopyAnswerWithError;
        }
        if ([name isEqualToString:@"uname"] && gEnableUnameHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_uname;
        }
        if ([name isEqualToString:@"sysctl"] && gEnableSysctlHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_sysctl;
        }
        if ([name isEqualToString:@"sysctlbyname"] && gEnableSysctlByNameHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_sysctlbyname;
        }
    }
    return PXCallOrigDlsym(handle, symbol);
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } PXInterposes[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)px_sysctlbyname, (const void *)sysctlbyname },
};

static void PXInstallCHooks(void) {
    gCHooksReady = NO;
    orig_sysctlbyname = dlsym(RTLD_NEXT, "sysctlbyname");
    orig_sysctl = dlsym(RTLD_NEXT, "sysctl");
    orig_uname = dlsym(RTLD_NEXT, "uname");
    orig_dlsym = dlsym(RTLD_NEXT, "dlsym");
    orig_MGCopyAnswer = dlsym(RTLD_NEXT, "MGCopyAnswer");
    if (!orig_MGCopyAnswer) orig_MGCopyAnswer = dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    orig_MGCopyAnswerWithError = dlsym(RTLD_NEXT, "MGCopyAnswerWithError");
    if (!orig_MGCopyAnswerWithError) orig_MGCopyAnswerWithError = dlsym(RTLD_DEFAULT, "MGCopyAnswerWithError");
    gEnableSysctlByNameHook = PXSnapshotBool(@"EnableSysctlByNameHook", YES);
    gEnableSysctlHook = PXSnapshotBool(@"EnableSysctlHook", NO);
    gEnableUnameHook = PXSnapshotBool(@"EnableUnameHook", NO);
    gEnableDlsymHook = PXSnapshotBool(@"EnableDlsymHook", NO);
    gEnableDeviceMetricsHook = PXSnapshotBool(@"EnableDeviceMetricsHook", gEnableDeviceMetricsHook);
    gEnableMobileGestaltHook = PXSnapshotBool(@"EnableMobileGestaltHook", NO);
    gCHooksReady = YES;
    if (gEnableSysctlHook) {
        PXRebindSysctl();
    }
    if (gEnableUnameHook) {
        PXRebindUname();
    }
    if (gEnableDlsymHook) {
        PXRebindDlsym();
    }
    if (gEnableMobileGestaltHook) {
        PXRebindMobileGestalt();
    }
    PXInjectLog(@"C hooks enabled mode=%@ sysctlbyname=%p enabled=%@ sysctl=%p enabled=%@ uname=%p enabled=%@ dlsym=%p enabled=%@ metrics=%@ MGCopyAnswer=%p MGCopyAnswerWithError=%p MobileGestalt enabled=%@",
                PXSnapshotString(@"CHookTestMode") ?: @"",
                orig_sysctlbyname,
                gEnableSysctlByNameHook ? @"YES" : @"NO",
                orig_sysctl,
                gEnableSysctlHook ? @"YES" : @"NO",
                orig_uname,
                gEnableUnameHook ? @"YES" : @"NO",
                orig_dlsym,
                gEnableDlsymHook ? @"YES" : @"NO",
                gEnableDeviceMetricsHook ? @"YES" : @"NO",
                orig_MGCopyAnswer,
                orig_MGCopyAnswerWithError,
                gEnableMobileGestaltHook ? @"YES" : @"NO");
}

__attribute__((constructor))
static void ProjectXInjectInit(void) {
    @autoreleasepool {
        PXLoadSnapshot();
        gEnableDeviceMetricsHook = PXSnapshotBool(@"EnableDeviceMetricsHook", NO);
        PXWriteLoadedMarker();
        if (PXSnapshotBool(@"EnableObjCHooks", NO)) {
            PXInstallObjCHooks();
        } else {
            PXInjectLog(@"ObjC hooks disabled; marker-only safe mode");
        }
        if (PXSnapshotBool(@"EnableCHooks", NO)) {
            PXInstallCHooks();
        } else {
            PXInjectLog(@"C hooks disabled");
        }
        PXInjectLog(@"ProjectXInject initialized bundle=%@", gBundleID ?: @"");
    }
}
