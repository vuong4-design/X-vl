// ProjectXInject.m - substrate-free injected dylib bootstrap for TrollStore modes.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <errno.h>
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

static NSString *PXValueForSysctlName(const char *name) {
    if (!name) return nil;
    if (strcmp(name, "hw.machine") == 0 && PXSysctlNameEnabled(@"hw.machine")) return PXSnapshotString(@"DeviceModel");
    if (strcmp(name, "hw.model") == 0 && PXSysctlNameEnabled(@"hw.model")) return PXSnapshotString(@"HwModel") ?: PXSnapshotString(@"BoardID");
    if (strcmp(name, "kern.osversion") == 0 && PXSysctlNameEnabled(@"kern.osversion")) return PXSnapshotString(@"IOSBuild");
    if (strcmp(name, "kern.version") == 0 && PXSysctlNameEnabled(@"kern.version")) return PXSnapshotString(@"KernelVersion");
    return nil;
}

static NSString *PXSysctlNameForMIB(const int *name, u_int namelen) {
    if (!name || namelen < 2) return nil;
    if (name[0] == CTL_HW && name[1] == HW_MACHINE) return @"hw.machine";
    if (name[0] == CTL_HW && name[1] == HW_MODEL) return @"hw.model";
    if (name[0] == CTL_KERN && name[1] == KERN_OSVERSION) return @"kern.osversion";
    if (name[0] == CTL_KERN && name[1] == KERN_VERSION) return @"kern.version";
    return nil;
}

static NSString *PXValueForSysctlMIB(const int *name, u_int namelen) {
    NSString *sysctlName = PXSysctlNameForMIB(name, namelen);
    return sysctlName.length ? PXValueForSysctlName(sysctlName.UTF8String) : nil;
}

static NSString *PXSafeBundleID(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    return bid.length ? bid : [[NSProcessInfo processInfo] processName];
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

static NSString *px_UIDevice_name(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"DeviceName");
    return value ?: (orig_UIDevice_name ? orig_UIDevice_name(self, _cmd) : @"iPhone");
}

static NSString *px_UIDevice_model(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"DeviceModelName") ?: PXSnapshotString(@"DeviceModel");
    return value ?: (orig_UIDevice_model ? orig_UIDevice_model(self, _cmd) : @"iPhone");
}

static NSString *px_UIDevice_localizedModel(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"DeviceModelName") ?: PXSnapshotString(@"DeviceModel");
    return value ?: (orig_UIDevice_localizedModel ? orig_UIDevice_localizedModel(self, _cmd) : @"iPhone");
}

static NSString *px_UIDevice_systemName(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"SystemName");
    return value ?: (orig_UIDevice_systemName ? orig_UIDevice_systemName(self, _cmd) : @"iOS");
}

static NSString *px_UIDevice_systemVersion(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"IOSVersion");
    return value ?: (orig_UIDevice_systemVersion ? orig_UIDevice_systemVersion(self, _cmd) : @"");
}

static NSUUID *px_UIDevice_identifierForVendor(id self, SEL _cmd) {
    NSString *value = PXSnapshotString(@"IDFV");
    NSUUID *uuid = value.length ? [[NSUUID alloc] initWithUUIDString:value] : nil;
    return uuid ?: (orig_UIDevice_identifierForVendor ? orig_UIDevice_identifierForVendor(self, _cmd) : nil);
}

static NSString *px_NSProcessInfo_operatingSystemVersionString(id self, SEL _cmd) {
    NSString *version = PXSnapshotString(@"IOSVersion");
    NSString *build = PXSnapshotString(@"IOSBuild");
    if (version.length && build.length) return [NSString stringWithFormat:@"Version %@ (Build %@)", version, build];
    if (version.length) return [NSString stringWithFormat:@"Version %@", version];
    return orig_NSProcessInfo_operatingSystemVersionString ? orig_NSProcessInfo_operatingSystemVersionString(self, _cmd) : @"";
}

static NSOperatingSystemVersion px_NSProcessInfo_operatingSystemVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion version = PXSnapshotOSVersion();
    if (version.majorVersion > 0) return version;
    return orig_NSProcessInfo_operatingSystemVersion ? orig_NSProcessInfo_operatingSystemVersion(self, _cmd) : version;
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
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;
static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef) = NULL;

static int PXCallOrigSysctlByName(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctlbyname) orig_sysctlbyname = dlsym(RTLD_NEXT, "sysctlbyname");
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

static int PXCallOrigSysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctl) orig_sysctl = dlsym(RTLD_NEXT, "sysctl");
    return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
}

static int PXCallOrigUname(struct utsname *buf) {
    if (!orig_uname) orig_uname = dlsym(RTLD_NEXT, "uname");
    return orig_uname ? orig_uname(buf) : -1;
}

static int px_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (gCHooksReady && gEnableSysctlByNameHook && name && !newp && newlen == 0) {
        NSString *value = PXValueForSysctlName(name);
        if (value.length) {
            BOOL copied = PXCopyCStringToSysctlBuffer(value, oldp, oldlenp);
            PXInjectLog(@"c-hook mode=%@ sysctlbyname %s -> %@ copied=%@", PXSnapshotString(@"CHookTestMode") ?: @"", name, value, copied ? @"YES" : @"NO");
            return copied ? 0 : -1;
        }
    }
    return PXCallOrigSysctlByName(name, oldp, oldlenp, newp, newlen);
}

static int px_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (gCHooksReady && gEnableSysctlHook && !newp && newlen == 0) {
        NSString *value = PXValueForSysctlMIB(name, namelen);
        if (value.length) {
            BOOL copied = PXCopyCStringToSysctlBuffer(value, oldp, oldlenp);
            NSString *sysctlName = PXSysctlNameForMIB(name, namelen) ?: @"unknown";
            PXInjectLog(@"c-hook mode=%@ sysctl %@ mib=%d.%d -> %@ copied=%@", PXSnapshotString(@"CHookTestMode") ?: @"", sysctlName, namelen > 0 ? name[0] : -1, namelen > 1 ? name[1] : -1, value, copied ? @"YES" : @"NO");
            return copied ? 0 : -1;
        }
    }
    return PXCallOrigSysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int px_uname(struct utsname *buf) {
    int result = PXCallOrigUname(buf);
    if (result == 0 && gCHooksReady && gEnableUnameHook && buf && PXSysctlNameEnabled(@"hw.machine")) {
        NSString *machine = PXSnapshotString(@"DeviceModel");
        if (machine.length) {
            memset(buf->machine, 0, sizeof(buf->machine));
            strlcpy(buf->machine, machine.UTF8String, sizeof(buf->machine));
            PXInjectLog(@"c-hook mode=%@ uname machine -> %@", PXSnapshotString(@"CHookTestMode") ?: @"", machine);
        }
    }
    return result;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } PXInterposes[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)px_sysctlbyname, (const void *)sysctlbyname },
    { (const void *)px_sysctl, (const void *)sysctl },
    { (const void *)px_uname, (const void *)uname },
};

static void PXInstallCHooks(void) {
    gCHooksReady = NO;
    orig_sysctlbyname = dlsym(RTLD_NEXT, "sysctlbyname");
    orig_sysctl = dlsym(RTLD_NEXT, "sysctl");
    orig_uname = dlsym(RTLD_NEXT, "uname");
    orig_MGCopyAnswer = dlsym(RTLD_NEXT, "MGCopyAnswer");
    if (!orig_MGCopyAnswer) orig_MGCopyAnswer = dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    gEnableSysctlByNameHook = PXSnapshotBool(@"EnableSysctlByNameHook", YES);
    gEnableSysctlHook = PXSnapshotBool(@"EnableSysctlHook", NO);
    gEnableUnameHook = PXSnapshotBool(@"EnableUnameHook", NO);
    gCHooksReady = YES;
    PXInjectLog(@"C hooks enabled mode=%@ sysctlbyname=%p enabled=%@ sysctl=%p enabled=%@ uname=%p enabled=%@ MGCopyAnswer=%p MGCopyAnswerInterpose=disabled",
                PXSnapshotString(@"CHookTestMode") ?: @"",
                orig_sysctlbyname,
                gEnableSysctlByNameHook ? @"YES" : @"NO",
                orig_sysctl,
                gEnableSysctlHook ? @"YES" : @"NO",
                orig_uname,
                gEnableUnameHook ? @"YES" : @"NO",
                orig_MGCopyAnswer);
}

__attribute__((constructor))
static void ProjectXInjectInit(void) {
    @autoreleasepool {
        PXLoadSnapshot();
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
