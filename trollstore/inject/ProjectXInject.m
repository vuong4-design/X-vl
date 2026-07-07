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

static NSString *const PXInjectBaseDir = @"/var/mobile/Library/ProjectXTroll";
static NSString *const PXInjectDylibVersion = @"0.1.0";

static NSDictionary *gSnapshot = nil;
static NSString *gBundleID = nil;
static BOOL gCHooksReady = NO;
static BOOL gEnableSysctlByNameHook = NO;
static BOOL gEnableMobileGestaltHook = NO;
static NSMutableDictionary *gHookStats = nil;
static __thread BOOL gRecordingStats = NO;

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

static NSString *PXSafeBundleID(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    return bid.length ? bid : [[NSProcessInfo processInfo] processName];
}

static NSString *PXNormalizePath(NSString *path) {
    if ([path hasPrefix:@"/private/var/"]) return [path stringByReplacingOccurrencesOfString:@"/private/var/" withString:@"/var/" options:0 range:NSMakeRange(0, @"/private/var/".length)];
    return path ?: @"";
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
static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef) = NULL;
static CFTypeRef (*orig_MGCopyAnswerWithError)(CFStringRef, int *) = NULL;

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

static void PXRebindSymbolInImage(const struct mach_header_64 *header, const char *symbolName, const void *replacement, void **originalOut) {
    if (!header || header->magic != MH_MAGIC_64 || !symbolName || !replacement) return;

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
    if (!linkedit || !symtab || !dysymtab) return;

    uintptr_t linkeditBase = slide + linkedit->vmaddr - linkedit->fileoff;
    const struct nlist_64 *symbols = (const struct nlist_64 *)(linkeditBase + symtab->symoff);
    const char *strings = (const char *)(linkeditBase + symtab->stroff);
    const uint32_t *indirectSymbols = (const uint32_t *)(linkeditBase + dysymtab->indirectsymoff);

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
                    PXRecordHookCall(@"rebind", [NSString stringWithUTF8String:symbolName] ?: @"", @"patched", YES, YES);
                }
            }
        }
        cmd = (const struct load_command *)((const uint8_t *)cmd + cmd->cmdsize);
    }
}

static void PXRebindMobileGestalt(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (bundlePath.length && ![path hasPrefix:bundlePath]) continue;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        PXRebindSymbolInImage(header, "_MGCopyAnswer", (const void *)px_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        PXRebindSymbolInImage(header, "_MGCopyAnswerWithError", (const void *)px_MGCopyAnswerWithError, (void **)&orig_MGCopyAnswerWithError);
    }
}

static int PXCallOrigSysctlByName(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctlbyname) orig_sysctlbyname = dlsym(RTLD_NEXT, "sysctlbyname");
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

static int px_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (gCHooksReady && gEnableSysctlByNameHook && name && !newp && newlen == 0) {
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

__attribute__((used)) static struct { const void *replacement; const void *replacee; } PXInterposes[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)px_sysctlbyname, (const void *)sysctlbyname },
};

static void PXInstallCHooks(void) {
    gCHooksReady = NO;
    orig_sysctlbyname = dlsym(RTLD_NEXT, "sysctlbyname");
    orig_MGCopyAnswer = dlsym(RTLD_NEXT, "MGCopyAnswer");
    if (!orig_MGCopyAnswer) orig_MGCopyAnswer = dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    orig_MGCopyAnswerWithError = dlsym(RTLD_NEXT, "MGCopyAnswerWithError");
    if (!orig_MGCopyAnswerWithError) orig_MGCopyAnswerWithError = dlsym(RTLD_DEFAULT, "MGCopyAnswerWithError");
    gEnableSysctlByNameHook = PXSnapshotBool(@"EnableSysctlByNameHook", YES);
    gEnableMobileGestaltHook = PXSnapshotBool(@"EnableMobileGestaltHook", NO);
    gCHooksReady = YES;
    if (gEnableMobileGestaltHook) {
        PXRebindMobileGestalt();
    }
    PXInjectLog(@"C hooks enabled mode=%@ sysctlbyname=%p enabled=%@ MGCopyAnswer=%p MGCopyAnswerWithError=%p MobileGestalt enabled=%@",
                PXSnapshotString(@"CHookTestMode") ?: @"",
                orig_sysctlbyname,
                gEnableSysctlByNameHook ? @"YES" : @"NO",
                orig_MGCopyAnswer,
                orig_MGCopyAnswerWithError,
                gEnableMobileGestaltHook ? @"YES" : @"NO");
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
