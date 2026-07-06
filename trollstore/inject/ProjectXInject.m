// ProjectXInject.m - substrate-free injected dylib bootstrap for TrollStore modes.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <stdarg.h>

static NSString *const PXInjectBaseDir = @"/var/mobile/Library/ProjectXTroll";
static NSString *const PXInjectDylibVersion = @"0.1.0";

static NSDictionary *gSnapshot = nil;
static NSString *gBundleID = nil;

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
        @"hookBackend": PXSnapshotBool(@"EnableObjCHooks", NO) ? @"objc-runtime" : @"marker-only",
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
static NSString *(*orig_NSProcessInfo_operatingSystemVersionString)(id, SEL) = NULL;

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

static NSString *px_NSProcessInfo_operatingSystemVersionString(id self, SEL _cmd) {
    NSString *version = PXSnapshotString(@"IOSVersion");
    NSString *build = PXSnapshotString(@"IOSBuild");
    if (version.length && build.length) return [NSString stringWithFormat:@"Version %@ (Build %@)", version, build];
    if (version.length) return [NSString stringWithFormat:@"Version %@", version];
    return orig_NSProcessInfo_operatingSystemVersionString ? orig_NSProcessInfo_operatingSystemVersionString(self, _cmd) : @"";
}

static void PXInstallObjCHooks(void) {
    Class device = objc_getClass("UIDevice");
    PXReplaceInstanceMethod(device, @selector(name), (IMP)px_UIDevice_name, (IMP *)&orig_UIDevice_name);
    PXReplaceInstanceMethod(device, @selector(model), (IMP)px_UIDevice_model, (IMP *)&orig_UIDevice_model);
    PXReplaceInstanceMethod(device, @selector(localizedModel), (IMP)px_UIDevice_localizedModel, (IMP *)&orig_UIDevice_localizedModel);
    PXReplaceInstanceMethod(device, @selector(systemName), (IMP)px_UIDevice_systemName, (IMP *)&orig_UIDevice_systemName);
    PXReplaceInstanceMethod(device, @selector(systemVersion), (IMP)px_UIDevice_systemVersion, (IMP *)&orig_UIDevice_systemVersion);

    Class processInfo = objc_getClass("NSProcessInfo");
    PXReplaceInstanceMethod(processInfo, @selector(operatingSystemVersionString), (IMP)px_NSProcessInfo_operatingSystemVersionString, (IMP *)&orig_NSProcessInfo_operatingSystemVersionString);
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
        PXInjectLog(@"ProjectXInject initialized bundle=%@", gBundleID ?: @"");
    }
}
