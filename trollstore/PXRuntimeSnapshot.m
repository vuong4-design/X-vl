// PXRuntimeSnapshot.m - runtime config snapshot for injected ProjectXInject.dylib.

#import "PXRuntimeSnapshot.h"
#import "PXDiagnostics.h"

#import <objc/message.h>

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(NSString *)identifier;
@end

NSString * const PXRuntimeSnapshotErrorDomain = @"PXRuntimeSnapshotErrorDomain";

static NSString *PXRTProfilesBase(void) {
    return @"/var/mobile/Library/WeaponX/Profiles";
}

static NSError *PXRTError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:PXRuntimeSnapshotErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"Runtime snapshot error"}];
}

static NSString *PXRTActiveProfileId(void) {
    NSArray<NSString *> *paths = @[
        [PXRTProfilesBase() stringByAppendingPathComponent:@"current_profile_info.plist"],
        @"/private/var/mobile/Library/WeaponX/Profiles/current_profile_info.plist",
        @"/var/mobile/Library/WeaponX/active_profile_info.plist",
        @"/private/var/mobile/Library/WeaponX/active_profile_info.plist"
    ];
    for (NSString *path in paths) {
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:path];
        id value = info[@"ProfileId"] ?: info[@"profileId"] ?: info[@"id"];
        if ([value isKindOfClass:[NSString class]] && [(NSString *)value length]) return value;
        if ([value isKindOfClass:[NSNumber class]]) return [(NSNumber *)value stringValue];
    }
    return nil;
}

static NSDictionary *PXRTDeviceIdsForProfile(NSString *profileId) {
    if (!profileId.length) return nil;
    NSArray<NSString *> *bases = @[PXRTProfilesBase(), @"/private/var/mobile/Library/WeaponX/Profiles"];
    for (NSString *base in bases) {
        NSString *path = [[[base stringByAppendingPathComponent:profileId] stringByAppendingPathComponent:@"identity"] stringByAppendingPathComponent:@"device_ids.plist"];
        NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
        if ([dict isKindOfClass:[NSDictionary class]] && dict.count) return dict;
    }
    return nil;
}

static NSDictionary *PXRTProfilePlist(NSString *profileId, NSString *name) {
    if (!profileId.length || !name.length) return nil;
    NSArray<NSString *> *bases = @[PXRTProfilesBase(), @"/private/var/mobile/Library/WeaponX/Profiles"];
    for (NSString *base in bases) {
        NSString *path = [[base stringByAppendingPathComponent:profileId] stringByAppendingPathComponent:name];
        NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
        if ([dict isKindOfClass:[NSDictionary class]] && dict.count) return dict;
    }
    return nil;
}

static id PXRTValue(NSDictionary *dict, NSString *key, id fallback) {
    id value = dict[key];
    return value ?: fallback ?: @"";
}

static NSString *PXRTDataContainerPathForBundleID(NSString *bundleID) {
    if (!bundleID.length) return nil;
    @try {
        Class proxyCls = NSClassFromString(@"LSApplicationProxy");
        SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
        id proxy = (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
        if (proxy) {
            id dataURL = nil;
            @try { dataURL = [proxy valueForKey:@"dataContainerURL"]; } @catch (__unused NSException *e) {}
            if ([dataURL isKindOfClass:[NSURL class]]) return [(NSURL *)dataURL path];
            if ([dataURL isKindOfClass:[NSString class]]) return dataURL;
        }
    } @catch (__unused NSException *e) {
    }
    return nil;
}

static NSString *PXRTTargetLocalDirectory(NSString *bundleID) {
    NSString *dataPath = PXRTDataContainerPathForBundleID(bundleID);
    if (!dataPath.length) return nil;
    return [[dataPath stringByAppendingPathComponent:@"Library"] stringByAppendingPathComponent:@"ProjectX"];
}

static NSString *PXRTTargetLocalSnapshotPath(NSString *bundleID) {
    NSString *dir = PXRTTargetLocalDirectory(bundleID);
    return dir.length ? [dir stringByAppendingPathComponent:@"runtime_snapshot.plist"] : nil;
}

static NSString *PXRTTargetLocalMarkerPath(NSString *bundleID) {
    NSString *dir = PXRTTargetLocalDirectory(bundleID);
    return dir.length ? [dir stringByAppendingPathComponent:@"loaded_marker.plist"] : nil;
}

static NSString *PXRTTargetLocalHookStatsPath(NSString *bundleID) {
    NSString *dir = PXRTTargetLocalDirectory(bundleID);
    return dir.length ? [dir stringByAppendingPathComponent:@"hook_stats.plist"] : nil;
}

@implementation PXRuntimeSnapshot

+ (NSString *)baseDirectory {
    return @"/var/mobile/Library/ProjectXTroll";
}

+ (NSString *)snapshotPathForBundleID:(NSString *)bundleID {
    NSString *name = bundleID.length ? bundleID : @"unknown";
    return [[[[self baseDirectory] stringByAppendingPathComponent:@"RuntimeSnapshots"] stringByAppendingPathComponent:name] stringByAppendingPathExtension:@"plist"];
}

+ (NSString *)loadedMarkerPathForBundleID:(NSString *)bundleID {
    NSString *name = bundleID.length ? bundleID : @"unknown";
    return [[[[self baseDirectory] stringByAppendingPathComponent:@"InjectionLogs"] stringByAppendingPathComponent:name] stringByAppendingPathExtension:@"loaded.plist"];
}

+ (NSString *)bundledInjectDylibPath {
    NSString *path = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"ProjectXInject.dylib"];
    return path;
}

+ (nullable NSDictionary<NSString *, id> *)exportSnapshotForBundleID:(NSString *)bundleID
                                                               error:(NSError **)error {
    return [self exportSnapshotForBundleID:bundleID enableObjCHooks:NO error:error];
}

+ (nullable NSDictionary<NSString *, id> *)exportSnapshotForBundleID:(NSString *)bundleID
                                                     enableObjCHooks:(BOOL)enableObjCHooks
                                                               error:(NSError **)error {
    return [self exportSnapshotForBundleID:bundleID enableObjCHooks:enableObjCHooks enableCHooks:NO error:error];
}

+ (nullable NSDictionary<NSString *, id> *)exportSnapshotForBundleID:(NSString *)bundleID
                                                      enableObjCHooks:(BOOL)enableObjCHooks
                                                         enableCHooks:(BOOL)enableCHooks
                                                                error:(NSError **)error {
    return [self exportSnapshotForBundleID:bundleID enableObjCHooks:enableObjCHooks enableCHooks:enableCHooks cHookOptions:nil error:error];
}

+ (nullable NSDictionary<NSString *, id> *)exportSnapshotForBundleID:(NSString *)bundleID
                                                      enableObjCHooks:(BOOL)enableObjCHooks
                                                         enableCHooks:(BOOL)enableCHooks
                                                         cHookOptions:(nullable NSDictionary<NSString *, id> *)cHookOptions
                                                                error:(NSError **)error {
    if (!bundleID.length) {
        if (error) *error = PXRTError(1, @"Missing bundleID");
        return nil;
    }

    NSString *profileId = PXRTActiveProfileId();
    NSDictionary *deviceIds = PXRTDeviceIdsForProfile(profileId) ?: @{};
    if (!profileId.length || !deviceIds.count) {
        [PXDiagnostics log:@"[inject] snapshot export warning bundleID=%@ profile=%@ deviceIds=%lu", bundleID ?: @"", profileId ?: @"", (unsigned long)deviceIds.count];
    }

    NSNumber *generation = deviceIds[@"GenerationCounter"] ?: @((NSInteger)[[NSDate date] timeIntervalSince1970]);
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary];
    snapshot[@"bundleID"] = bundleID;
    snapshot[@"profileId"] = profileId ?: @"";
    snapshot[@"generation"] = generation;
    snapshot[@"exportedAt"] = @([[NSDate date] timeIntervalSince1970]);
    snapshot[@"SystemName"] = @"iOS";
    snapshot[@"EnableObjCHooks"] = @(enableObjCHooks);
    snapshot[@"EnableCHooks"] = @(enableCHooks);
    if (cHookOptions.count) {
        for (NSString *key in cHookOptions) {
            id value = cHookOptions[key];
            if (key.length && value) snapshot[key] = value;
        }
    }

    NSArray<NSString *> *keys = @[
        @"DeviceName",
        @"DeviceModel",
        @"DeviceModelName",
        @"HwModel",
        @"BoardID",
        @"ModelNumber",
        @"IOSVersion",
        @"IOSBuild",
        @"Darwin",
        @"KernelVersion",
        @"ScreenResolution",
        @"ViewportResolution",
        @"DevicePixelRatio",
        @"CPUArchitecture",
        @"DeviceMemory",
        @"CPUCoreCount",
        @"SSID",
        @"BSSID",
        @"CarrierName",
        @"CarrierMCC",
        @"CarrierMNC",
        @"IDFV"
    ];
    for (NSString *key in keys) {
        snapshot[key] = PXRTValue(deviceIds, key, @"");
    }

    NSDictionary *storage = PXRTProfilePlist(profileId, @"storage.plist");
    if (storage[@"TotalStorage"]) snapshot[@"TotalStorage"] = storage[@"TotalStorage"];
    if (storage[@"FreeStorage"]) snapshot[@"FreeStorage"] = storage[@"FreeStorage"];

    NSDictionary *battery = PXRTProfilePlist(profileId, @"battery_info.plist");
    id batteryLevel = battery[@"BatteryLevel"] ?: deviceIds[@"BatteryLevel"];
    if (batteryLevel) snapshot[@"BatteryLevel"] = batteryLevel;

    NSDictionary *uptime = PXRTProfilePlist(profileId, @"system_uptime.plist");
    id uptimeValue = uptime[@"value"] ?: deviceIds[@"SystemUptime"];
    if (uptimeValue) snapshot[@"SystemUptime"] = uptimeValue;

    NSDictionary *bootTime = PXRTProfilePlist(profileId, @"boot_time.plist");
    id bootValue = bootTime[@"value"] ?: deviceIds[@"BootTime"];
    if ([bootValue isKindOfClass:[NSDate class]]) {
        snapshot[@"BootTime"] = @([(NSDate *)bootValue timeIntervalSince1970]);
    } else if (bootValue) {
        snapshot[@"BootTime"] = bootValue;
    }

    NSString *path = [self snapshotPathForBundleID:bundleID];
    NSString *dir = [path stringByDeletingLastPathComponent];
    NSError *mkErr = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&mkErr];
    if (mkErr) {
        if (error) *error = mkErr;
        return nil;
    }
    if (![snapshot writeToFile:path atomically:YES]) {
        if (error) *error = PXRTError(2, @"Failed to write runtime snapshot");
        return nil;
    }
    NSString *targetSnapshotPath = PXRTTargetLocalSnapshotPath(bundleID);
    if (targetSnapshotPath.length) {
        NSString *targetDir = [targetSnapshotPath stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:targetDir withIntermediateDirectories:YES attributes:nil error:nil];
        BOOL wroteTarget = [snapshot writeToFile:targetSnapshotPath atomically:YES];
        [PXDiagnostics log:@"[inject] target-local snapshot write bundleID=%@ ok=%@ path=%@", bundleID ?: @"", wroteTarget ? @"YES" : @"NO", targetSnapshotPath ?: @""];
    } else {
        [PXDiagnostics log:@"[inject] target-local snapshot skipped bundleID=%@ data container not found", bundleID ?: @""];
    }
    [PXDiagnostics log:@"[inject] snapshot exported bundleID=%@ path=%@ profile=%@ keys=%lu", bundleID ?: @"", path ?: @"", profileId ?: @"", (unsigned long)snapshot.count];
    return snapshot;
}

+ (NSDictionary<NSString *, id> *)statusForBundleID:(NSString *)bundleID {
    NSString *snapshotPath = [self snapshotPathForBundleID:bundleID ?: @""];
    NSString *markerPath = [self loadedMarkerPathForBundleID:bundleID ?: @""];
    NSString *targetSnapshotPath = PXRTTargetLocalSnapshotPath(bundleID ?: @"") ?: @"";
    NSString *targetMarkerPath = PXRTTargetLocalMarkerPath(bundleID ?: @"") ?: @"";
    NSString *targetHookStatsPath = PXRTTargetLocalHookStatsPath(bundleID ?: @"") ?: @"";
    NSString *dylibPath = [self bundledInjectDylibPath];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *snapshot = [NSDictionary dictionaryWithContentsOfFile:snapshotPath] ?: @{};
    NSDictionary *marker = [NSDictionary dictionaryWithContentsOfFile:markerPath] ?: @{};
    NSDictionary *targetSnapshot = [NSDictionary dictionaryWithContentsOfFile:targetSnapshotPath] ?: @{};
    NSDictionary *targetMarker = [NSDictionary dictionaryWithContentsOfFile:targetMarkerPath] ?: @{};
    NSDictionary *targetHookStats = [NSDictionary dictionaryWithContentsOfFile:targetHookStatsPath] ?: @{};
    NSDictionary *dylibAttrs = [fm attributesOfItemAtPath:dylibPath error:nil] ?: @{};
    return @{
        @"bundleID": bundleID ?: @"",
        @"dylibPath": dylibPath ?: @"",
        @"dylibExists": [fm fileExistsAtPath:dylibPath] ? @"YES" : @"NO",
        @"dylibSize": dylibAttrs[NSFileSize] ?: @0,
        @"snapshotPath": snapshotPath ?: @"",
        @"snapshotExists": [fm fileExistsAtPath:snapshotPath] ? @"YES" : @"NO",
        @"snapshot": snapshot,
        @"targetSnapshotPath": targetSnapshotPath ?: @"",
        @"targetSnapshotExists": [fm fileExistsAtPath:targetSnapshotPath] ? @"YES" : @"NO",
        @"targetSnapshot": targetSnapshot,
        @"markerPath": markerPath ?: @"",
        @"markerExists": [fm fileExistsAtPath:markerPath] ? @"YES" : @"NO",
        @"marker": marker,
        @"targetMarkerPath": targetMarkerPath ?: @"",
        @"targetMarkerExists": [fm fileExistsAtPath:targetMarkerPath] ? @"YES" : @"NO",
        @"targetMarker": targetMarker,
        @"targetHookStatsPath": targetHookStatsPath ?: @"",
        @"targetHookStatsExists": [fm fileExistsAtPath:targetHookStatsPath] ? @"YES" : @"NO",
        @"targetHookStats": targetHookStats,
    };
}

@end
