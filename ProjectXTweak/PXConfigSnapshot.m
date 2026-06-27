#import "PXConfigSnapshot.h"
#import "ProjectXLogging.h"
#import <CoreFoundation/CoreFoundation.h>

// Profile resolution paths (verified against existing hook conventions).
static NSString *const kPXProfilesBase     = @"/var/mobile/Library/WeaponX/Profiles";
static NSString *const kPXCurrentInfoPlist = @"/var/mobile/Library/WeaponX/Profiles/current_profile_info.plist";
static NSString *const kPXCurrentInfoAlt   = @"/private/var/mobile/Library/WeaponX/Profiles/current_profile_info.plist";
static NSString *const kPXProfileIdKey     = @"ProfileId";
static NSString *const kPXIdentitySubpath  = @"identity/device_ids.plist";

@interface PXConfigSnapshot ()
@property (nonatomic, copy, readwrite) NSDictionary<NSString *, id> *deviceIds;
@property (nonatomic, copy, readwrite, nullable) NSString *profileId;
@property (nonatomic, readwrite) uint64_t generation;
@property (nonatomic, readwrite) PXSnapshotGroups groups;
@end

@implementation PXConfigSnapshot {
    // Concurrent queue: readers run concurrently, swaps use a barrier.
    dispatch_queue_t _swapQueue;
}

+ (instancetype)shared {
    static PXConfigSnapshot *s_shared = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s_shared = [[PXConfigSnapshot alloc] init];
    });
    return s_shared;
}

- (instancetype)init {
    if ((self = [super init])) {
        _swapQueue = dispatch_queue_create("com.projectx.pxconfigsnapshot.swap", DISPATCH_QUEUE_CONCURRENT);
        _deviceIds = @{};
        _profileId = nil;
        _generation = 0;
        _groups = (PXSnapshotGroups){0};
        [self reload]; // best-effort initial load; failure keeps empty/invalid snapshot
    }
    return self;
}

#pragma mark - Profile resolution

- (nullable NSString *)resolveCurrentProfileId {
    for (NSString *p in @[kPXCurrentInfoPlist, kPXCurrentInfoAlt]) {
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:p];
        id pid = info[kPXProfileIdKey];
        if ([pid isKindOfClass:[NSString class]] && [(NSString *)pid length] > 0) return (NSString *)pid;
        if ([pid isKindOfClass:[NSNumber class]]) return [(NSNumber *)pid stringValue];
    }
    return nil;
}

- (nullable NSDictionary *)loadDeviceIdsForProfile:(NSString *)profileId {
    if (profileId.length == 0) return nil;
    for (NSString *base in @[kPXProfilesBase, [@"/private" stringByAppendingString:kPXProfilesBase]]) {
        NSString *path = [[base stringByAppendingPathComponent:profileId] stringByAppendingPathComponent:kPXIdentitySubpath];
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:path];
        if ([d isKindOfClass:[NSDictionary class]] && d.count > 0) return d;
    }
    PXLog(@"[PXConfigSnapshot] Failed to load device_ids for profile %@", profileId);
    return nil;
}

#pragma mark - Validation helpers

static BOOL PXHasString(NSDictionary *d, NSString *key) {
    id v = d[key];
    return [v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0;
}

static BOOL PXHasNumber(NSDictionary *d, NSString *key) {
    id v = d[key];
    if ([v isKindOfClass:[NSNumber class]]) return YES;
    if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
        NSScanner *s = [NSScanner scannerWithString:(NSString *)v];
        double tmp; return [s scanDouble:&tmp] && [s isAtEnd];
    }
    return NO;
}

- (PXSnapshotGroups)validateGroups:(NSDictionary *)d {
    PXSnapshotGroups g = (PXSnapshotGroups){0};
    if (!d) return g;

    g.identity = PXHasString(d, @"DeviceModel")
              && PXHasString(d, @"DeviceModelName")
              && PXHasString(d, @"HwModel")
              && PXHasString(d, @"BoardID")
              && PXHasString(d, @"ModelNumber")
              && PXHasString(d, @"DeviceName");

    g.iosVersion = PXHasString(d, @"IOSVersion")
                && PXHasString(d, @"IOSBuild")
                && PXHasString(d, @"Darwin")
                && PXHasString(d, @"KernelVersion");

    g.screen = PXHasString(d, @"ScreenResolution")
            && PXHasString(d, @"ViewportResolution")
            && PXHasNumber(d, @"DevicePixelRatio");

    g.hardware = PXHasString(d, @"CPUArchitecture")
              && PXHasNumber(d, @"DeviceMemory")
              && PXHasNumber(d, @"CPUCoreCount");

    g.wifi = PXHasString(d, @"SSID") && PXHasString(d, @"BSSID");

    g.carrier = PXHasString(d, @"CarrierName")
             && PXHasString(d, @"CarrierMCC")
             && PXHasString(d, @"CarrierMNC");

    return g;
}

// Core snapshot is valid only when identity + iosVersion are present.
static BOOL PXCoreSnapshotValid(PXSnapshotGroups g) {
    return g.identity && g.iosVersion;
}

#pragma mark - Reload / atomic swap

- (BOOL)reload {
    NSString *pid = [self resolveCurrentProfileId];
    NSDictionary *fresh = [self loadDeviceIdsForProfile:pid];
    if (!fresh) {
        PXLog(@"[PXConfigSnapshot] reload: load failed, keeping generation %llu", (unsigned long long)_generation);
        return NO;
    }

    PXSnapshotGroups g = [self validateGroups:fresh];
    if (!PXCoreSnapshotValid(g)) {
        PXLog(@"[PXConfigSnapshot] reload: core invalid (identity=%d ios=%d), keeping generation %llu",
              g.identity, g.iosVersion, (unsigned long long)_generation);
        return NO;
    }

    NSDictionary *frozen = [fresh copy];
    NSString *pidCopy = [pid copy];
    dispatch_barrier_sync(_swapQueue, ^{
        self.deviceIds = frozen;
        self.profileId = pidCopy;
        self.groups = g;
        self.generation = self.generation + 1;
    });
    PXLog(@"[PXConfigSnapshot] reload: swapped to generation %llu (profile=%@ screen=%d hw=%d wifi=%d carrier=%d)",
          (unsigned long long)self.generation, pidCopy, g.screen, g.hardware, g.wifi, g.carrier);
    return YES;
}

#pragma mark - Accessors

- (nullable NSString *)stringForKey:(NSString *)key {
    __block id v = nil;
    dispatch_sync(_swapQueue, ^{ v = self.deviceIds[key]; });
    return [v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0 ? (NSString *)v : nil;
}

- (nullable NSNumber *)numberForKey:(NSString *)key {
    __block id v = nil;
    dispatch_sync(_swapQueue, ^{ v = self.deviceIds[key]; });
    if ([v isKindOfClass:[NSNumber class]]) return (NSNumber *)v;
    if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
        NSScanner *s = [NSScanner scannerWithString:(NSString *)v];
        double tmp;
        if ([s scanDouble:&tmp] && [s isAtEnd]) return @(tmp);
    }
    return nil;
}

- (PXSnapshotGroups)liveGroups {
    __block PXSnapshotGroups g;
    dispatch_sync(_swapQueue, ^{ g = self.groups; });
    return g;
}

- (BOOL)isIdentityValid   { return [self liveGroups].identity; }
- (BOOL)isIOSVersionValid { return [self liveGroups].iosVersion; }
- (BOOL)isScreenValid     { return [self liveGroups].screen; }
- (BOOL)isHardwareValid   { return [self liveGroups].hardware; }
- (BOOL)isWiFiValid       { return [self liveGroups].wifi; }
- (BOOL)isCarrierValid    { return [self liveGroups].carrier; }

#pragma mark - Darwin notification refresh

static void PXConfigSnapshotNotify(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    [[PXConfigSnapshot shared] reload];
}

__attribute__((constructor))
static void PXConfigSnapshotInit(void) {
    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
    if (!center) return;
    CFNotificationCenterAddObserver(center, NULL, PXConfigSnapshotNotify, CFSTR("com.hydra.projectx.profileChanged"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(center, NULL, PXConfigSnapshotNotify, CFSTR("com.hydra.projectx.settings.changed"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
}
