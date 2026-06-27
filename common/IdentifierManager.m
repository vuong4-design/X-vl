#import "IdentifierManager.h"
#import "PXRoot.h"
#import "DeviceModelManager.h"
#import "IDFAManager.h"
#import "IDFVManager.h"
#import "DeviceNameManager.h"
#import "SerialNumberManager.h"
#import "IOSVersionInfo.h"
#import "IOSBuildDB.h"
#import "IPhoneModelDB.h"
#import "DBDebugLogger.h"
#import "ProjectXLogging.h"
#import "VersionCompare.h"
#import "WiFiManager.h"
#import "StorageManager.h"
#import "BatteryManager.h"
#import "SystemUUIDManager.h"
#import "DyldCacheUUIDManager.h"
#import "PasteboardUUIDManager.h"
#import "KeychainUUIDManager.h"
#import "UserDefaultsUUIDManager.h"
#import "AppGroupUUIDManager.h"
#import "UptimeManager.h"
#import "CoreDataUUIDManager.h"
#import "AppInstallUUIDManager.h"
#import "AppContainerUUIDManager.h"
#import <Security/Security.h>

@interface LSApplicationWorkspace
+ (id)defaultWorkspace;
- (NSArray *)allInstalledApplications;
@end

@interface LSApplicationProxy
+ (id)applicationProxyForIdentifier:(id)identifier;
@property(readonly) NSString *applicationIdentifier;
@property(readonly) NSString *localizedName;
@property(readonly) NSString *shortVersionString;
@property(readonly) NSString *bundleVersion;
@end

// Forward declare what we need from Profile
@interface Profile : NSObject
@property (nonatomic, strong, readonly) NSString *profileId;
@property (nonatomic, strong) NSString *name;
@end

@interface IdentifierManager ()
@property (nonatomic, strong) NSMutableDictionary *settings;
@property (nonatomic, strong) NSMutableDictionary *scopedApps;
@property (nonatomic, strong) NSError *error;
@property (nonatomic, strong) NSMutableDictionary *spoofCache;
@end

@implementation IdentifierManager

static BOOL PXWebCompatIOSRangeEnabled(void) {
    NSUserDefaults *securitySettings = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
    return [securitySettings boolForKey:@"webCompatIOSRangeEnabled"];
}

static NSString *PXWebCompatMaxIOSForDeviceMaxIOS(NSString *deviceMaxIOS) {
    NSString *cap = @"16.3.1";
    if (![deviceMaxIOS isKindOfClass:[NSString class]] || deviceMaxIOS.length == 0) {
        return cap;
    }
    return (PXCompareVersions(deviceMaxIOS, cap) == NSOrderedAscending) ? deviceMaxIOS : cap;
}

static NSDictionary *PXPickFallbackIOSVersionInfoMax(NSString *maxIOSVersion) {
    IOSVersionInfo *mgr = [IOSVersionInfo sharedManager];
    NSArray *pairs = [mgr availableIOSVersions];
    if (![pairs isKindOfClass:[NSArray class]] || pairs.count == 0) return nil;

    NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
    for (id item in pairs) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSString *v = item[@"version"];
        if (![v isKindOfClass:[NSString class]] || v.length == 0) continue;
        if (PXCompareVersions(v, maxIOSVersion) != NSOrderedDescending) {
            [candidates addObject:(NSDictionary *)item];
        }
    }

    if (candidates.count == 0) return nil;

    uint32_t r = 0;
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(r), (uint8_t *)&r) != errSecSuccess) {
        r = arc4random_uniform((uint32_t)candidates.count);
    }
    return candidates[(NSUInteger)(r % (uint32_t)candidates.count)];
}

#pragma mark - Device Model

static NSDictionary *PXScreenDictFromModelSpec(NSDictionary *modelSpec) {
    NSDictionary *screen = [modelSpec[@"screen"] isKindOfClass:[NSDictionary class]] ? modelSpec[@"screen"] : nil;
    return screen ?: @{};
}

static NSDictionary *PXWebGLInfoFromModelSpec(NSDictionary *modelSpec) {
    NSDictionary *webgl = [modelSpec[@"webgl"] isKindOfClass:[NSDictionary class]] ? modelSpec[@"webgl"] : nil;
    NSString *vendor = [webgl[@"vendor"] isKindOfClass:[NSString class]] ? webgl[@"vendor"] : @"Apple";
    NSString *renderer = [webgl[@"renderer"] isKindOfClass:[NSString class]] ? webgl[@"renderer"] : nil;
    if (!renderer.length) {
        renderer = [modelSpec[@"gpuFamily"] isKindOfClass:[NSString class]] ? modelSpec[@"gpuFamily"] : @"Apple GPU";
    }
    return @{
        @"webglVendor": vendor ?: @"Apple",
        @"webglRenderer": renderer ?: @"Apple GPU",
        @"unmaskedVendor": @"Apple Inc.",
        @"unmaskedRenderer": renderer ?: @"Apple GPU",
        @"webglVersion": @"WebGL 2.0"
    };
}

static NSUInteger PXRandomIndex3(NSUInteger upperBoundExclusive) {
    if (upperBoundExclusive == 0) return 0;
    uint32_t r = 0;
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(r), (uint8_t *)&r) == errSecSuccess) {
        return (NSUInteger)(r % (uint32_t)upperBoundExclusive);
    }
    return (NSUInteger)arc4random_uniform((uint32_t)upperBoundExclusive);
}

static NSDictionary *PXPickHardwareVariantFromModelSpec(NSDictionary *modelSpec) {
    // Schema: variants: [ { boardID: "N71AP", hwModel: "N71AP" }, ... ]
    NSArray *variants = [modelSpec[@"variants"] isKindOfClass:[NSArray class]] ? modelSpec[@"variants"] : nil;
    if (!variants.count) return @{};

    NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
    for (id v in variants) {
        if (![v isKindOfClass:[NSDictionary class]]) continue;
        NSString *boardID = [v[@"boardID"] isKindOfClass:[NSString class]] ? v[@"boardID"] : nil;
        NSString *hwModel = [v[@"hwModel"] isKindOfClass:[NSString class]] ? v[@"hwModel"] : nil;
        if (!boardID.length && !hwModel.length) continue;
        [candidates addObject:(NSDictionary *)v];
    }

    if (!candidates.count) return @{};
    return candidates[PXRandomIndex3(candidates.count)];
}

static NSString *PXPickModelNumberFromModelSpec(NSDictionary *modelSpec) {
    // Optional schema: modelNumbers: ["A1633", ...]
    NSArray *nums = [modelSpec[@"modelNumbers"] isKindOfClass:[NSArray class]] ? modelSpec[@"modelNumbers"] : nil;
    if (!nums.count) return nil;

    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    for (id n in nums) {
        if ([n isKindOfClass:[NSString class]] && ((NSString *)n).length > 0) {
            [candidates addObject:(NSString *)n];
        }
    }
    if (!candidates.count) return nil;
    return candidates[PXRandomIndex3(candidates.count)];
}

- (NSString *)regenerateDeviceProfileGroup {
    self.error = nil;

    NSString *identityDir = [self profileIdentityPath];
    if (!identityDir.length) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" code:6001 userInfo:@{NSLocalizedDescriptionKey: @"Could not resolve profile identity path"}];
        return nil;
    }

    NSError *dbErr = nil;
    IPhoneModelDB *modelDB = [IPhoneModelDB sharedManager];
    IOSBuildDB *buildDB = [IOSBuildDB sharedManager];
    if (![modelDB loadIfNeeded:&dbErr] || ![buildDB loadIfNeeded:&dbErr]) {
        self.error = dbErr;
        PXLog(@"[WeaponX] ⚠️ DeviceProfileGroup: DB not available (%@)", dbErr.localizedDescription ?: @"unknown");
        PXDBLog(@"DeviceProfileGroup: DB not available err=%@", dbErr.localizedDescription ?: @"nil");
        return nil;
    }

    BOOL webCompat = PXWebCompatIOSRangeEnabled();

    // Pick a random iPhone model that supports min iOS 13.0.
    // In WebCompat mode, we also require an iOS build <= 16.3.1 to exist for the chosen device.
    NSDictionary *modelSpec = nil;
    NSDictionary *iosMeta = nil;
    NSString *productType = nil;
    NSString *modelName = nil;
    NSString *maxIOS = nil;
    NSString *effectiveMaxIOS = nil;
    for (NSInteger attempt = 0; attempt < (webCompat ? 60 : 1); attempt++) {
        modelSpec = [modelDB randomModelMinIOS:@"13.0" error:&dbErr];
        if (!modelSpec) break;

        productType = [modelSpec[@"productType"] isKindOfClass:[NSString class]] ? modelSpec[@"productType"] : nil;
        modelName = [modelSpec[@"name"] isKindOfClass:[NSString class]] ? modelSpec[@"name"] : @"";
        maxIOS = [modelSpec[@"maxIOS"] isKindOfClass:[NSString class]] ? modelSpec[@"maxIOS"] : nil;
        if (!productType.length || !maxIOS.length) {
            continue;
        }

        effectiveMaxIOS = webCompat ? PXWebCompatMaxIOSForDeviceMaxIOS(maxIOS) : maxIOS;
        iosMeta = [buildDB randomMetaForDevice:productType min:@"13.0" max:effectiveMaxIOS error:&dbErr];
        if (iosMeta) break;
    }

    if (!modelSpec) {
        self.error = dbErr;
        PXLog(@"[WeaponX] ❌ DeviceProfileGroup: failed to pick model (%@)", dbErr.localizedDescription ?: @"unknown");
        PXDBLog(@"DeviceProfileGroup: failed to pick model err=%@", dbErr.localizedDescription ?: @"nil");
        return nil;
    }

    if (!productType.length || !maxIOS.length) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" code:6002 userInfo:@{NSLocalizedDescriptionKey: @"Invalid model spec (missing productType/maxIOS)"}];
        PXDBLog(@"DeviceProfileGroup: invalid modelSpec missing productType/maxIOS spec=%@", modelSpec);
        return nil;
    }

    if (!iosMeta) {
        self.error = dbErr ?: [NSError errorWithDomain:@"com.hydra.projectx" code:6005 userInfo:@{NSLocalizedDescriptionKey: @"No compatible iOS build found for chosen model"}];
        PXLog(@"[WeaponX] ❌ DeviceProfileGroup: no compatible build for %@ (maxIOS=%@ effectiveMax=%@ webCompat=%@)", productType, maxIOS, effectiveMaxIOS ?: @"<nil>", webCompat ? @"YES" : @"NO");
        PXDBLog(@"DeviceProfileGroup: no compatible build device=%@ maxIOS=%@ effectiveMax=%@ webCompat=%@ err=%@", productType, maxIOS, effectiveMaxIOS ?: @"<nil>", webCompat ? @"YES" : @"NO", dbErr.localizedDescription ?: @"nil");
        return nil;
    }

    NSString *iosVersion = [iosMeta[@"version"] isKindOfClass:[NSString class]] ? iosMeta[@"version"] : nil;
    NSString *iosBuild = [iosMeta[@"build"] isKindOfClass:[NSString class]] ? iosMeta[@"build"] : nil;
    NSString *darwin = [iosMeta[@"darwin"] isKindOfClass:[NSString class]] ? iosMeta[@"darwin"] : nil;
    NSString *xnu = [iosMeta[@"xnu"] isKindOfClass:[NSString class]] ? iosMeta[@"xnu"] : nil;
    NSString *kernel = [iosMeta[@"kernel_version"] isKindOfClass:[NSString class]] ? iosMeta[@"kernel_version"] : nil;
    if (!iosVersion.length || !iosBuild.length || !darwin.length || !xnu.length || !kernel.length) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" code:6003 userInfo:@{NSLocalizedDescriptionKey: @"Invalid iOS meta (missing required fields)"}];
        PXDBLog(@"DeviceProfileGroup: invalid iosMeta device=%@ meta=%@", productType, iosMeta);
        return nil;
    }

    NSDictionary *screen = PXScreenDictFromModelSpec(modelSpec);
    NSString *screenResolution = [screen[@"resolution"] isKindOfClass:[NSString class]] ? screen[@"resolution"] : @"";
    NSString *viewportResolution = [screen[@"viewport"] isKindOfClass:[NSString class]] ? screen[@"viewport"] : screenResolution;
    NSNumber *scale = [screen[@"scale"] isKindOfClass:[NSNumber class]] ? screen[@"scale"] : nil;
    NSNumber *ppi = [screen[@"ppi"] isKindOfClass:[NSNumber class]] ? screen[@"ppi"] : nil;

    NSString *cpuArchitecture = [modelSpec[@"cpuArchitecture"] isKindOfClass:[NSString class]] ? modelSpec[@"cpuArchitecture"] : @"";
    NSNumber *deviceMemoryGB = [modelSpec[@"deviceMemoryGB"] isKindOfClass:[NSNumber class]] ? modelSpec[@"deviceMemoryGB"] : nil;
    NSString *gpuFamily = [modelSpec[@"gpuFamily"] isKindOfClass:[NSString class]] ? modelSpec[@"gpuFamily"] : @"";
    NSNumber *cpuCores = [modelSpec[@"cpuCores"] isKindOfClass:[NSNumber class]] ? modelSpec[@"cpuCores"] : nil;
    NSString *metalFeatureSet = [modelSpec[@"metalFeatureSet"] isKindOfClass:[NSString class]] ? modelSpec[@"metalFeatureSet"] : @"Unknown";

    // Hardware variant selection (boardID/hwModel)
    NSDictionary *pickedVariant = PXPickHardwareVariantFromModelSpec(modelSpec);
    NSString *boardID = [pickedVariant[@"boardID"] isKindOfClass:[NSString class]] ? pickedVariant[@"boardID"] : nil;
    NSString *hwModel = [pickedVariant[@"hwModel"] isKindOfClass:[NSString class]] ? pickedVariant[@"hwModel"] : nil;
    if (!boardID.length) {
        boardID = [modelSpec[@"boardID"] isKindOfClass:[NSString class]] ? modelSpec[@"boardID"] : @"Unknown";
    }
    if (!hwModel.length) {
        hwModel = [modelSpec[@"hwModel"] isKindOfClass:[NSString class]] ? modelSpec[@"hwModel"] : boardID;
    }

    // Optional model number (Axxxx)
    NSString *modelNumber = PXPickModelNumberFromModelSpec(modelSpec);

    NSDictionary *webGLInfo = PXWebGLInfoFromModelSpec(modelSpec);

    NSDate *now = [NSDate date];

    // Update device_ids.plist (source of truth)
    NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
    NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: [NSMutableDictionary dictionary];
    NSInteger gen = [deviceIds[@"GenerationCounter"] respondsToSelector:@selector(integerValue)] ? [deviceIds[@"GenerationCounter"] integerValue] : 0;
    gen += 1;

    // Clear fields managed by the Device Profile group to avoid stale values.
    NSArray<NSString *> *managedKeys = @[
        @"DeviceModel", @"DeviceModelName",
        @"ScreenResolution", @"ViewportResolution", @"DevicePixelRatio", @"ScreenDensityPPI",
        @"CPUArchitecture", @"DeviceMemory", @"CPUCoreCount", @"MetalFeatureSet", @"GPUFamily",
        @"WebGLVendor", @"WebGLRenderer",
        @"BoardID", @"HwModel", @"ModelNumber",
        @"IOSVersion", @"IOSBuild", @"Darwin", @"XNU", @"KernelVersion"
    ];
    for (NSString *k in managedKeys) {
        [deviceIds removeObjectForKey:k];
    }

    deviceIds[@"DeviceModel"] = productType;
    deviceIds[@"DeviceModelName"] = modelName ?: @"";
    deviceIds[@"ScreenResolution"] = screenResolution ?: @"";
    deviceIds[@"ViewportResolution"] = viewportResolution ?: @"";
    if (scale) deviceIds[@"DevicePixelRatio"] = scale;
    if (ppi) deviceIds[@"ScreenDensityPPI"] = ppi;
    deviceIds[@"CPUArchitecture"] = cpuArchitecture ?: @"";
    if (deviceMemoryGB) deviceIds[@"DeviceMemory"] = deviceMemoryGB;
    if (cpuCores) deviceIds[@"CPUCoreCount"] = cpuCores;
    deviceIds[@"MetalFeatureSet"] = metalFeatureSet ?: @"Unknown";
    deviceIds[@"GPUFamily"] = gpuFamily ?: @"";
    deviceIds[@"WebGLVendor"] = webGLInfo[@"webglVendor"] ?: @"Apple";
    deviceIds[@"WebGLRenderer"] = webGLInfo[@"webglRenderer"] ?: @"Apple GPU";
    deviceIds[@"BoardID"] = boardID ?: @"Unknown";
    deviceIds[@"HwModel"] = hwModel ?: @"Unknown";

    if (modelNumber.length) deviceIds[@"ModelNumber"] = modelNumber;

    // iOS fields (store normalized components)
    deviceIds[@"IOSVersion"] = iosVersion;
    deviceIds[@"IOSBuild"] = iosBuild;
    deviceIds[@"Darwin"] = darwin;
    deviceIds[@"XNU"] = xnu;
    deviceIds[@"KernelVersion"] = kernel;

    deviceIds[@"GenerationCounter"] = @(gen);
    deviceIds[@"CommittedAt"] = now;

    BOOL wrote = [deviceIds writeToFile:deviceIdsPath atomically:YES];
    if (!wrote) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" code:6004 userInfo:@{NSLocalizedDescriptionKey: @"Failed to write device_ids.plist"}];
        return nil;
    }

    // Keep IOSVersionInfo in sync for processes that fall back to it.
    @try {
        NSDictionary *versionDict = @{
            @"version": iosVersion,
            @"build": iosBuild,
            @"darwin": darwin,
            @"xnu": xnu,
            @"kernel_version": kernel,
            @"lastUpdated": now
        };
        [[IOSVersionInfo sharedManager] setCurrentIOSVersionInfo:versionDict];
    } @catch (__unused NSException *e) {
    }

    // Keep DeviceModelManager in sync if present.
    @try {
        [[DeviceModelManager sharedManager] setCurrentDeviceModel:productType];
    } @catch (__unused NSException *e) {
    }

    PXLog(@"[WeaponX] ✅ DeviceProfileGroup: %@ (%@) iOS %@ (%@)", productType, modelName ?: @"", iosVersion, iosBuild);
    PXDBLog(@"DeviceProfileGroup: picked device=%@ modelNumber=%@ boardID=%@ hwModel=%@", productType, modelNumber ?: @"<nil>", boardID ?: @"<nil>", hwModel ?: @"<nil>");
    return productType;
}

- (NSString *)generateDeviceModel {
    NSString *deviceModel = [[DeviceModelManager sharedManager] generateDeviceModel];
    if (!deviceModel) {
        self.error = [[DeviceModelManager sharedManager] lastError];
        return nil;
    }
    
    // Get all device specifications from DeviceModelManager
    DeviceModelManager *deviceManager = [DeviceModelManager sharedManager];
    NSString *deviceModelName = [deviceManager deviceModelNameForString:deviceModel];
    NSString *screenResolution = [deviceManager screenResolutionForModel:deviceModel];
    NSString *viewportResolution = [deviceManager viewportResolutionForModel:deviceModel];
    CGFloat devicePixelRatio = [deviceManager devicePixelRatioForModel:deviceModel];
    NSInteger screenDensity = [deviceManager screenDensityForModel:deviceModel];
    NSString *cpuArchitecture = [deviceManager cpuArchitectureForModel:deviceModel];
    
    // New device specifications
    NSInteger deviceMemory = [deviceManager deviceMemoryForModel:deviceModel];
    NSString *gpuFamily = [deviceManager gpuFamilyForModel:deviceModel];
    NSDictionary *webGLInfo = [deviceManager webGLInfoForModel:deviceModel];
    NSInteger cpuCoreCount = [deviceManager cpuCoreCountForModel:deviceModel];
    NSString *metalFeatureSet = [deviceManager metalFeatureSetForModel:deviceModel];
    
    // Get Board ID and hw.model
    NSString *boardID = [deviceManager boardIDForModel:deviceModel];
    NSString *hwModel = [deviceManager hwModelForModel:deviceModel];
    
    // Save to profile-specific path (device_ids.plist only)
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: [NSMutableDictionary dictionary];
        
        // Add all device specs to the device_ids.plist file
        deviceIds[@"DeviceModel"] = deviceModel ?: @"";
        deviceIds[@"DeviceModelName"] = deviceModelName ?: @"";
        deviceIds[@"ScreenResolution"] = screenResolution ?: @"";
        deviceIds[@"ViewportResolution"] = viewportResolution ?: @"";
        deviceIds[@"DevicePixelRatio"] = @(devicePixelRatio);
        deviceIds[@"ScreenDensityPPI"] = @(screenDensity);
        deviceIds[@"CPUArchitecture"] = cpuArchitecture ?: @"";
        deviceIds[@"DeviceMemory"] = @(deviceMemory);
        deviceIds[@"CPUCoreCount"] = @(cpuCoreCount);
        deviceIds[@"MetalFeatureSet"] = metalFeatureSet ?: @"Unknown";
        deviceIds[@"GPUFamily"] = gpuFamily ?: @"";
        // Simplified WebGL info for combined file
        deviceIds[@"WebGLVendor"] = webGLInfo[@"webglVendor"] ?: @"Apple";
        deviceIds[@"WebGLRenderer"] = webGLInfo[@"webglRenderer"] ?: @"Apple GPU";
        deviceIds[@"BoardID"] = boardID ?: @"Unknown";
        deviceIds[@"HwModel"] = hwModel ?: @"Unknown";
        
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
    }
    return deviceModel;
}

- (BOOL)setCustomDeviceModel:(NSString *)value {
    BOOL valid = [[DeviceModelManager sharedManager] isValidDeviceModel:value];
    if (!valid) {
        // Allow models present in external DB (device profile group)
        valid = [[IPhoneModelDB sharedManager] containsProductType:value];
    }
    if (!valid) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" code:2003 userInfo:@{NSLocalizedDescriptionKey: @"Invalid Device Model"}];
        return NO;
    }
    NSString *identityDir = [self profileIdentityPath];
    BOOL success = NO;
    
    // Get all device specifications
    DeviceModelManager *deviceManager = [DeviceModelManager sharedManager];
    NSString *deviceModelName = [deviceManager deviceModelNameForString:value];
    NSString *screenResolution = [deviceManager screenResolutionForModel:value];
    NSString *viewportResolution = [deviceManager viewportResolutionForModel:value];
    CGFloat devicePixelRatio = [deviceManager devicePixelRatioForModel:value];
    NSInteger screenDensity = [deviceManager screenDensityForModel:value];
    NSString *cpuArchitecture = [deviceManager cpuArchitectureForModel:value];
    
    // New device specifications
    NSInteger deviceMemory = [deviceManager deviceMemoryForModel:value];
    NSString *gpuFamily = [deviceManager gpuFamilyForModel:value];
    NSDictionary *webGLInfo = [deviceManager webGLInfoForModel:value];
    NSInteger cpuCoreCount = [deviceManager cpuCoreCountForModel:value];
    NSString *metalFeatureSet = [deviceManager metalFeatureSetForModel:value];
    
    // Get Board ID and hw.model
    NSString *boardID = [deviceManager boardIDForModel:value];
    NSString *hwModel = [deviceManager hwModelForModel:value];
    
    if (identityDir) {
        // Update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: [NSMutableDictionary dictionary];
        
        // Add all device specifications to the device_ids.plist
        deviceIds[@"DeviceModel"] = value ?: @"";
        deviceIds[@"DeviceModelName"] = deviceModelName ?: @"";
        deviceIds[@"ScreenResolution"] = screenResolution ?: @"";
        deviceIds[@"ViewportResolution"] = viewportResolution ?: @"";
        deviceIds[@"DevicePixelRatio"] = @(devicePixelRatio);
        deviceIds[@"ScreenDensityPPI"] = @(screenDensity);
        deviceIds[@"CPUArchitecture"] = cpuArchitecture ?: @"";
        deviceIds[@"DeviceMemory"] = @(deviceMemory);
        deviceIds[@"CPUCoreCount"] = @(cpuCoreCount);
        deviceIds[@"MetalFeatureSet"] = metalFeatureSet ?: @"Unknown";
        deviceIds[@"GPUFamily"] = gpuFamily ?: @"";
        // Simplified WebGL info for combined file
        deviceIds[@"WebGLVendor"] = webGLInfo[@"webglVendor"] ?: @"Apple";
        deviceIds[@"WebGLRenderer"] = webGLInfo[@"webglRenderer"] ?: @"Apple GPU";
        deviceIds[@"BoardID"] = boardID ?: @"Unknown";
        deviceIds[@"HwModel"] = hwModel ?: @"Unknown";
        
        success = [deviceIds writeToFile:deviceIdsPath atomically:YES];
    }
    if (success) {
        [[DeviceModelManager sharedManager] setCurrentDeviceModel:value];
    }
    return success;
}


+ (instancetype)sharedManager {
    static IdentifierManager *sharedManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedManager = [[self alloc] init];
        [sharedManager loadSettings];
    });
    return sharedManager;
}

- (instancetype)init {
    if (self = [super init]) {
        _settings = [NSMutableDictionary dictionary];
        _scopedApps = [NSMutableDictionary dictionary];
        _spoofCache = [NSMutableDictionary dictionary];
    }
    return self;
}

#pragma mark - Profile Integration

- (NSString *)getActiveProfileId {
    // First check the primary profile info file
    NSString *centralInfoPath = PXRootPath(@"/var/mobile/Library/WeaponX/Profiles/current_profile_info.plist");
    NSDictionary *centralInfo = [NSDictionary dictionaryWithContentsOfFile:centralInfoPath];
    
    NSString *profileId = centralInfo[@"ProfileId"];
    if (!profileId) {
        // If not found, check the legacy active_profile_info.plist
        NSString *activeInfoPath = PXRootPath(@"/var/mobile/Library/WeaponX/active_profile_info.plist");
        NSDictionary *activeInfo = [NSDictionary dictionaryWithContentsOfFile:activeInfoPath];
        profileId = activeInfo[@"ProfileId"];
        
        NSLog(@"[WeaponX] 🔍 CRITICAL CHECK - Primary profile info not found, checked backup: %@", profileId ? @"✅ found" : @"❌ not found");
    }
    
    if (!profileId) {
        NSLog(@"[WeaponX] Warning: No active profile ID found, using default");
        // Try to find any profile directory as a fallback
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSString *profilesDir = PXRootPath(@"/var/mobile/Library/WeaponX/Profiles");
        NSError *error = nil;
        NSArray *contents = [fileManager contentsOfDirectoryAtPath:profilesDir error:&error];
        
        if (!error && contents.count > 0) {
            // Use the first directory found as a fallback
            for (NSString *item in contents) {
                BOOL isDir = NO;
                NSString *fullPath = [profilesDir stringByAppendingPathComponent:item];
                [fileManager fileExistsAtPath:fullPath isDirectory:&isDir];
                
                if (isDir) {
                    profileId = item;
                    NSLog(@"[WeaponX] Using fallback profile ID: %@", profileId);
                    break;
                }
            }
        }
        
        // If we still don't have a profile ID, give up
        if (!profileId) {
            NSLog(@"[WeaponX] Error: Could not find any profile");
            return nil;
        }
    }
    
    return profileId;
}

- (NSString *)profileIdentityPath {
    // Get current profile ID without directly using ProfileManager
    NSString *profileId = [self getActiveProfileId];
    if (!profileId) {
        NSLog(@"[WeaponX] Error: No active profile when getting identity path");
        return nil;
    }
    
    // Build the path to this profile's identity directory
    NSString *profileDir = PXRootPath([NSString stringWithFormat:@"/var/mobile/Library/WeaponX/Profiles/%@", profileId]);
    NSString *identityDir = [profileDir stringByAppendingPathComponent:@"identity"];
    
    // Create the directory if it doesn't exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:identityDir]) {
        NSDictionary *attributes = @{NSFilePosixPermissions: @0755,
                                    NSFileOwnerAccountName: @"mobile"};
        
        NSError *dirError = nil;
        if (![fileManager createDirectoryAtPath:identityDir 
                    withIntermediateDirectories:YES 
                                     attributes:attributes
                                          error:&dirError]) {
            NSLog(@"[WeaponX] Error creating identity directory: %@", dirError);
            return nil;
        }
    }
    
    return identityDir;
}

#pragma mark - Identifier Management

- (NSString *)generateIDFA {
    NSString *idfa = [[IDFAManager sharedManager] generateIDFA];
    if (!idfa) {
        self.error = [[IDFAManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *idfaDict = @{@"value": idfa, @"lastUpdated": [NSDate date]};
        NSString *idfaPath = [identityDir stringByAppendingPathComponent:@"advertising_id.plist"];
        [idfaDict writeToFile:idfaPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"IDFA"] = idfa;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
    }
    
    return idfa;
}

- (NSString *)generateIDFV {
    NSString *idfv = [[IDFVManager sharedManager] generateIDFV];
    if (!idfv) {
        self.error = [[IDFVManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *idfvDict = @{@"value": idfv, @"lastUpdated": [NSDate date]};
        NSString *idfvPath = [identityDir stringByAppendingPathComponent:@"vendor_id.plist"];
        [idfvDict writeToFile:idfvPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"IDFV"] = idfv;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
    }
    
    return idfv;
}

- (NSString *)generateDeviceName {
    NSString *deviceName = [[DeviceNameManager sharedManager] generateDeviceName];
    if (!deviceName) {
        self.error = [[DeviceNameManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *deviceNameDict = @{@"value": deviceName, @"lastUpdated": [NSDate date]};
        NSString *deviceNamePath = [identityDir stringByAppendingPathComponent:@"device_name.plist"];
        [deviceNameDict writeToFile:deviceNamePath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"DeviceName"] = deviceName;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
    }
    
    return deviceName;
}

- (NSString *)generateSerialNumber {
    self.error = nil;
    
    NSString *serialNumber = [[SerialNumberManager sharedManager] generateSerialNumber];
    if (!serialNumber) {
        self.error = [[SerialNumberManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *serialDict = @{@"value": serialNumber, @"lastUpdated": [NSDate date]};
        NSString *serialPath = [identityDir stringByAppendingPathComponent:@"serial_number.plist"];
        [serialDict writeToFile:serialPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"SerialNumber"] = serialNumber;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
    }
    
    return serialNumber;
}

- (NSDictionary *)generateIOSVersion {
    self.error = nil;

    BOOL webCompat = PXWebCompatIOSRangeEnabled();
    NSString *webCompatMax = @"16.3.1";

    // Prefer external DB if available and current device model is known.
    @try {
        NSString *identityDir = [self profileIdentityPath];
        NSString *deviceModel = [self currentValueForIdentifier:@"DeviceModel"];
        if (identityDir.length && deviceModel.length) {
            NSError *dbErr = nil;
            IPhoneModelDB *modelDB = [IPhoneModelDB sharedManager];
            IOSBuildDB *buildDB = [IOSBuildDB sharedManager];
            if ([modelDB loadIfNeeded:&dbErr] && [buildDB loadIfNeeded:&dbErr]) {
                NSDictionary *spec = [modelDB specForProductType:deviceModel];
                NSString *maxIOS = [spec[@"maxIOS"] isKindOfClass:[NSString class]] ? spec[@"maxIOS"] : nil;
                NSString *effectiveMaxIOS = (webCompat ? PXWebCompatMaxIOSForDeviceMaxIOS(maxIOS) : maxIOS);
                if (effectiveMaxIOS.length) {
                    NSDictionary *meta = [buildDB randomMetaForDevice:deviceModel min:@"13.0" max:effectiveMaxIOS error:&dbErr];
                    if (meta) {
                        NSString *iosVersion = meta[@"version"];
                        NSString *iosBuild = meta[@"build"];
                        NSString *darwin = meta[@"darwin"];
                        NSString *xnu = meta[@"xnu"];
                        NSString *kernel = meta[@"kernel_version"];

                        NSMutableDictionary *versionDict = [@{
                            @"version": iosVersion ?: @"",
                            @"build": iosBuild ?: @"",
                            @"darwin": darwin ?: @"",
                            @"xnu": xnu ?: @"",
                            @"kernel_version": kernel ?: @"",
                            @"lastUpdated": [NSDate date]
                        } mutableCopy];

                        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
                        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: [NSMutableDictionary dictionary];
                        deviceIds[@"IOSVersion"] = iosVersion;
                        deviceIds[@"IOSBuild"] = iosBuild;
                        deviceIds[@"Darwin"] = darwin;
                        deviceIds[@"XNU"] = xnu;
                        deviceIds[@"KernelVersion"] = kernel;
                        [deviceIds writeToFile:deviceIdsPath atomically:YES];

                        [[IOSVersionInfo sharedManager] setCurrentIOSVersionInfo:versionDict];
                        PXLog(@"[WeaponX] ✅ Generated iOS version from DB: %@ (%@)", iosVersion, iosBuild);
                        return versionDict;
                    }
                }
            }
        }
    } @catch (__unused NSException *e) {
    }

    NSDictionary *versionInfo = nil;
    if (webCompat) {
        NSDictionary *picked = PXPickFallbackIOSVersionInfoMax(webCompatMax);
        if (picked) {
            versionInfo = @{
                @"version": picked[@"version"] ?: @"",
                @"build": picked[@"build"] ?: @"",
                @"darwin": picked[@"darwin"] ?: @"",
                @"xnu": picked[@"xnu"] ?: @"",
                @"kernel_version": picked[@"kernel_version"] ?: @"",
                @"lastUpdated": [NSDate date]
            };
        }
    }

    if (!versionInfo) {
        versionInfo = [[IOSVersionInfo sharedManager] generateIOSVersionInfo];
    }
    if (!versionInfo) {
        self.error = [[IOSVersionInfo sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path (device_ids.plist only)
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        
        // Store normalized components in device_ids.plist
        deviceIds[@"IOSVersion"] = versionInfo[@"version"];
        deviceIds[@"IOSBuild"] = versionInfo[@"build"];  // Keep this for compatibility
        if (versionInfo[@"darwin"]) deviceIds[@"Darwin"] = versionInfo[@"darwin"];
        if (versionInfo[@"xnu"]) deviceIds[@"XNU"] = versionInfo[@"xnu"];
        if (versionInfo[@"kernel_version"]) deviceIds[@"KernelVersion"] = versionInfo[@"kernel_version"];
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] Stored iOS version: %@ with build: %@", versionInfo[@"version"], versionInfo[@"build"]);
    }
    
    return versionInfo;
}

- (NSDictionary *)generateiOSVersion {
    return [self generateIOSVersion];
}

- (NSString *)generateSystemBootUUID {
    NSString *bootUUID = [[SystemUUIDManager sharedManager] generateBootUUID];
    if (!bootUUID) {
        self.error = [[SystemUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": bootUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"system_boot_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"SystemBootUUID"] = bootUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 🆔 Generated System Boot UUID: %@", bootUUID);
    }
    
    return bootUUID;
}

- (NSString *)generateDyldCacheUUID {
    NSString *dyldUUID = [[DyldCacheUUIDManager sharedManager] generateDyldCacheUUID];
    if (!dyldUUID) {
        self.error = [[DyldCacheUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": dyldUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"dyld_cache_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"DyldCacheUUID"] = dyldUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 🆔 Generated Dyld Cache UUID: %@", dyldUUID);
    }
    
    return dyldUUID;
}

- (NSString *)generatePasteboardUUID {
    NSString *pasteboardUUID = [[PasteboardUUIDManager sharedManager] generatePasteboardUUID];
    if (!pasteboardUUID) {
        self.error = [[PasteboardUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": pasteboardUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"pasteboard_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"PasteboardUUID"] = pasteboardUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 🆔 Generated Pasteboard UUID: %@", pasteboardUUID);
    }
    
    return pasteboardUUID;
}

- (NSString *)generateKeychainUUID {
    NSString *keychainUUID = [[KeychainUUIDManager sharedManager] generateKeychainUUID];
    if (!keychainUUID) {
        self.error = [[KeychainUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": keychainUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"keychain_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"KeychainUUID"] = keychainUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 🔑 Generated Keychain UUID: %@", keychainUUID);
    }
    
    return keychainUUID;
}

- (NSString *)generateUserDefaultsUUID {
    NSString *userDefaultsUUID = [[UserDefaultsUUIDManager sharedManager] generateUserDefaultsUUID];
    if (!userDefaultsUUID) {
        self.error = [[UserDefaultsUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": userDefaultsUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"userdefaults_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"UserDefaultsUUID"] = userDefaultsUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 🔄 Generated UserDefaults UUID: %@", userDefaultsUUID);
    }
    
    return userDefaultsUUID;
}

- (NSString *)generateAppGroupUUID {
    NSString *appGroupUUID = [[AppGroupUUIDManager sharedManager] generateAppGroupUUID];
    if (!appGroupUUID) {
        self.error = [[AppGroupUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": appGroupUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"appgroup_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"AppGroupUUID"] = appGroupUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 👥 Generated App Group UUID: %@", appGroupUUID);
    }
    
    return appGroupUUID;
}

- (NSString *)generateCoreDataUUID {
    NSString *coreDataUUID = [[CoreDataUUIDManager sharedManager] generateCoreDataUUID];
    if (!coreDataUUID) {
        self.error = [[CoreDataUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": coreDataUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"coredata_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"CoreDataUUID"] = coreDataUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 📦 Generated Core Data UUID: %@", coreDataUUID);
    }
    
    return coreDataUUID;
}

- (NSString *)generateSystemUptime {
    NSString *profilePath = [self profileIdentityPath];
NSTimeInterval uptime = [[UptimeManager sharedManager] currentUptimeForProfile:profilePath];
    if (uptime <= 0) {
        self.error = [[UptimeManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        // Format uptime as string (in seconds)
        NSString *uptimeString = [NSString stringWithFormat:@"%.0f", uptime];
        NSDictionary *uptimeDict = @{@"value": uptimeString, @"lastUpdated": [NSDate date]};
        NSString *uptimePath = [identityDir stringByAppendingPathComponent:@"system_uptime.plist"];
        [uptimeDict writeToFile:uptimePath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"SystemUptime"] = uptimeString;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 🕒 Generated System Uptime: %.2f hours", uptime / 3600.0);
    }
    
    // Return formatted uptime string (in hours for display)
    return [NSString stringWithFormat:@"%.2f hours", uptime / 3600.0];
}

- (NSString *)generateBootTime {
    NSString *profilePath = [self profileIdentityPath];
NSDate *bootTime = [[UptimeManager sharedManager] currentBootTimeForProfile:profilePath];
    if (!bootTime) {
        self.error = [[UptimeManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *bootTimeDict = @{@"value": bootTime, @"lastUpdated": [NSDate date]};
        NSString *bootTimePath = [identityDir stringByAppendingPathComponent:@"boot_time.plist"];
        [bootTimeDict writeToFile:bootTimePath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        
        // Store timestamp as a string for consistency
        NSString *bootTimeString = [NSString stringWithFormat:@"%.0f", [bootTime timeIntervalSince1970]];
        deviceIds[@"BootTime"] = bootTimeString;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 🕒 Generated Boot Time: %@", bootTime);
    }
    
    // Return formatted date for display
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateStyle = NSDateFormatterMediumStyle;
    formatter.timeStyle = NSDateFormatterMediumStyle;
    return [formatter stringFromDate:bootTime];
}

- (NSString *)generateAppInstallUUID {
    NSString *appInstallUUID = [[AppInstallUUIDManager sharedManager] generateAppInstallUUID];
    if (!appInstallUUID) {
        self.error = [[AppInstallUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": appInstallUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"appinstall_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"AppInstallUUID"] = appInstallUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 📱 Generated App Install UUID: %@", appInstallUUID);
    }
    
    return appInstallUUID;
}

- (NSString *)generateAppContainerUUID {
    NSString *appContainerUUID = [[AppContainerUUIDManager sharedManager] generateAppContainerUUID];
    if (!appContainerUUID) {
        self.error = [[AppContainerUUIDManager sharedManager] lastError];
        return nil;
    }
    
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSDictionary *uuidDict = @{@"value": appContainerUUID, @"lastUpdated": [NSDate date]};
        NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"appcontainer_uuid.plist"];
        [uuidDict writeToFile:uuidPath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[@"AppContainerUUID"] = appContainerUUID;
        [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] 📦 Generated App Container UUID: %@", appContainerUUID);
    }
    
    return appContainerUUID;
}

- (void)regenerateAllEnabledIdentifiers {
        // For WiFi info: Use the WiFiManager to generate
    Class wifiManagerClass = NSClassFromString(@"WiFiManager");
    if (wifiManagerClass && [wifiManagerClass respondsToSelector:@selector(sharedManager)]) {
        id wifiManager = [wifiManagerClass sharedManager];
        if (wifiManager && [wifiManager respondsToSelector:@selector(generateWiFiInfo)]) {
            // Generate WiFi info
            [wifiManager generateWiFiInfo];
            PXLog(@"[WeaponX] 📶 Generated WiFi information for current profile");
        }
    }
    
    // Continue with other identifiers
    if ([self isIdentifierEnabled:@"IDFA"]) {
        [self generateIDFA];
    }
    if ([self isIdentifierEnabled:@"IDFV"]) {
        [self generateIDFV];
    }
    if ([self isIdentifierEnabled:@"DeviceName"]) {
        [self generateDeviceName];
    }
    if ([self isIdentifierEnabled:@"SerialNumber"]) {
        [self generateSerialNumber];
    }
    if ([self isIdentifierEnabled:@"IMEI"]) {
        NSString *imei = [self generateIMEI];
        if (imei) [self setCustomIMEI:imei];
    }
    if ([self isIdentifierEnabled:@"MEID"]) {
        NSString *meid = [self generateMEID];
        if (meid) [self setCustomMEID:meid];
    }
    
    // Device profile group: DeviceModel + dependent specs + iOS version/build.
    // Only regenerate when at least one of the dependent identifiers is enabled.
    BOOL wantsDeviceProfileGroup = [self isIdentifierEnabled:@"DeviceModel"] || [self isIdentifierEnabled:@"IOSVersion"];
    if (wantsDeviceProfileGroup) {
        NSString *newModel = [self regenerateDeviceProfileGroup];
        if (!newModel) {
            // Fallback to legacy generation paths if DB-based generation is unavailable.
            NSString *deviceModel = [self generateDeviceModel];
            if (deviceModel) {
                // Use legacy setter for existing model DB.
                [self setCustomDeviceModel:deviceModel];
            }
            if ([self isIdentifierEnabled:@"IOSVersion"]) {
                [self generateIOSVersion];
            }
        }
    } else {
        // Ensure we still have a model stored for spec-dependent UI.
        if (![self currentValueForIdentifier:@"DeviceModel"]) {
            NSString *deviceModel = [self generateDeviceModel];
            if (deviceModel) {
                [self setCustomDeviceModel:deviceModel];
            }
        }
    }
    
    // Always generate device theme if it doesn't exist
    if (![self currentValueForIdentifier:@"DeviceTheme"]) {
        NSString *deviceTheme = [self generateDeviceTheme];
        if (deviceTheme) {
            [self setCustomDeviceTheme:deviceTheme];
            PXLog(@"[WeaponX] 🎨 Generated device theme: %@", deviceTheme);
        }
    }
    
    // IOSVersion is handled by regenerateDeviceProfileGroup when enabled.
    if ([self isIdentifierEnabled:@"SystemBootUUID"]) {
        [self generateSystemBootUUID];
    }
    if ([self isIdentifierEnabled:@"DyldCacheUUID"]) {
        [self generateDyldCacheUUID];
    }
    if ([self isIdentifierEnabled:@"PasteboardUUID"]) {
        [self generatePasteboardUUID];
    }

    if ([self isIdentifierEnabled:@"KeychainUUID"]) {
        [self generateKeychainUUID];
    }
    if ([self isIdentifierEnabled:@"UserDefaultsUUID"]) {
        [self generateUserDefaultsUUID];
    }
    if ([self isIdentifierEnabled:@"AppGroupUUID"]) {
        [self generateAppGroupUUID];
    }
    if ([self isIdentifierEnabled:@"CoreDataUUID"]) {
        [self generateCoreDataUUID];
    }
    if ([self isIdentifierEnabled:@"SystemUptime"]) {
        NSString *profilePath = [self profileIdentityPath];
[[UptimeManager sharedManager] generateUptimeForProfile:profilePath];
    }
    if ([self isIdentifierEnabled:@"BootTime"]) {
        NSString *profilePath = [self profileIdentityPath];
[[UptimeManager sharedManager] generateBootTimeForProfile:profilePath];
    }
    // Even though we already generated WiFi info above, check if it's specifically enabled
    if ([self isIdentifierEnabled:@"WiFi"]) {
        // Use WiFiManager to generate new WiFi info
        id wifiManager = NSClassFromString(@"WiFiManager");
        if (wifiManager && [wifiManager respondsToSelector:@selector(sharedManager)]) {
            id sharedManager = [wifiManager sharedManager];
            if (sharedManager && [sharedManager respondsToSelector:@selector(generateWiFiInfo)]) {
                [sharedManager generateWiFiInfo];
                PXLog(@"Generated new WiFi information");
            }
        }
    }
    if ([self isIdentifierEnabled:@"StorageSystem"]) {
        // Use StorageManager to generate new storage info
        id storageManager = NSClassFromString(@"StorageManager");
        if (storageManager && [storageManager respondsToSelector:@selector(sharedManager)]) {
            id sharedManager = [storageManager sharedManager];
            if (sharedManager && [sharedManager respondsToSelector:@selector(generateStorageForCapacity:)]) {
                // Randomly choose between 64GB and 128GB
                NSString *capacity = [sharedManager respondsToSelector:@selector(randomizeStorageCapacity)] ? 
                                       [sharedManager randomizeStorageCapacity] : @"64";
                
                NSDictionary *storageInfo = [sharedManager generateStorageForCapacity:capacity];
                if (storageInfo) {
                    [sharedManager setTotalStorageCapacity:storageInfo[@"TotalStorage"]];
                    [sharedManager setFreeStorageSpace:storageInfo[@"FreeStorage"]];
                    [sharedManager setFilesystemType:storageInfo[@"FilesystemType"]];
                    PXLog(@"[WeaponX] 💾 Generated new storage information: %@ GB", storageInfo[@"TotalStorage"]);
                }
            }
        }
    }
    if ([self isIdentifierEnabled:@"Battery"]) {
        // Use BatteryManager to generate new battery info
        id batteryManager = NSClassFromString(@"BatteryManager");
        if (batteryManager && [batteryManager respondsToSelector:@selector(sharedManager)]) {
            id sharedManager = [batteryManager sharedManager];
            if (sharedManager && [sharedManager respondsToSelector:@selector(generateBatteryInfo)]) {
                NSDictionary *batteryInfo = [sharedManager generateBatteryInfo];
                if (batteryInfo) {
                    PXLog(@"[WeaponX] 🔋 Generated new battery information: %@%%", 
                         @([batteryInfo[@"BatteryLevel"] floatValue] * 100));
                }
            }
        }
    }
    // Add AppInstallUUID
    if ([self isIdentifierEnabled:@"AppInstallUUID"]) {
        [self generateAppInstallUUID];
    }
    // Add AppContainerUUID
    if ([self isIdentifierEnabled:@"AppContainerUUID"]) {
        [self generateAppContainerUUID];
    }
    // Add DeviceTheme
    if ([self isIdentifierEnabled:@"DeviceTheme"]) {
        [self generateDeviceTheme];
    }
    [self saveSettings];
}

#pragma mark - Settings Management

// Helper methods for file checks
- (BOOL)fileExistsAtPath:(NSString *)path {
    return [[NSFileManager defaultManager] fileExistsAtPath:path];
}

- (NSDictionary *)dictionaryAtPath:(NSString *)path {
    return [NSDictionary dictionaryWithContentsOfFile:path];
}

- (void)setIdentifierEnabled:(BOOL)enabled forType:(NSString *)type {
    // Set the enabled state in settings
    self.settings[type] = @(enabled);
    
    // If enabling an identifier, check if we need to generate a value
    if (enabled) {
        // Check if a value exists
        NSString *currentValue = [self currentValueForIdentifier:type];
        if (!currentValue) {
            PXLog(@"No value exists for %@ - generating new value...", type);
            
            // Generate a value based on the identifier type
            if ([type isEqualToString:@"IDFA"]) {
                [self generateIDFA];
            } 
            else if ([type isEqualToString:@"IDFV"]) {
                [self generateIDFV];
            }
            else if ([type isEqualToString:@"DeviceName"]) {
                [self generateDeviceName];
            }
            else if ([type isEqualToString:@"SerialNumber"]) {
                [self generateSerialNumber];
            }
            else if ([type isEqualToString:@"IMEI"]) {
                NSString *imei = [self generateIMEI];
                if (imei) [self setCustomIMEI:imei];
            }
            else if ([type isEqualToString:@"MEID"]) {
                NSString *meid = [self generateMEID];
                if (meid) [self setCustomMEID:meid];
            }
            else if ([type isEqualToString:@"IOSVersion"]) {
                [self generateIOSVersion];
            }
            else if ([type isEqualToString:@"SystemBootUUID"]) {
                [self generateSystemBootUUID];
            }
            else if ([type isEqualToString:@"DyldCacheUUID"]) {
                [self generateDyldCacheUUID];
            }
            else if ([type isEqualToString:@"PasteboardUUID"]) {
                [self generatePasteboardUUID];
            }
            else if ([type isEqualToString:@"KeychainUUID"]) {
                [self generateKeychainUUID];
            }
            else if ([type isEqualToString:@"UserDefaultsUUID"]) {
                [self generateUserDefaultsUUID];
            }
            else if ([type isEqualToString:@"AppGroupUUID"]) {
                [self generateAppGroupUUID];
            }
            else if ([type isEqualToString:@"CoreDataUUID"]) {
                [self generateCoreDataUUID];
            }
            else if ([type isEqualToString:@"SystemUptime"]) {
                NSString *profilePath = [self profileIdentityPath];
[[UptimeManager sharedManager] generateUptimeForProfile:profilePath];
            }
            else if ([type isEqualToString:@"BootTime"]) {
                NSString *profilePath = [self profileIdentityPath];
[[UptimeManager sharedManager] generateBootTimeForProfile:profilePath];
            }
            else if ([type isEqualToString:@"WiFi"]) {
                // Use WiFiManager to generate new WiFi info
                id wifiManager = NSClassFromString(@"WiFiManager");
                if (wifiManager && [wifiManager respondsToSelector:@selector(sharedManager)]) {
                    id sharedManager = [wifiManager sharedManager];
                    if (sharedManager && [sharedManager respondsToSelector:@selector(generateWiFiInfo)]) {
                        [sharedManager generateWiFiInfo];
                        PXLog(@"Generated new WiFi information");
                    }
                }
            }
            else if ([type isEqualToString:@"StorageSystem"]) {
                // Use StorageManager to generate new storage info
                id storageManager = NSClassFromString(@"StorageManager");
                if (storageManager && [storageManager respondsToSelector:@selector(sharedManager)]) {
                    id sharedManager = [storageManager sharedManager];
                    if (sharedManager && [sharedManager respondsToSelector:@selector(generateStorageForCapacity:)]) {
                        // Randomly choose between 64GB and 128GB
                        NSString *capacity = [sharedManager respondsToSelector:@selector(randomizeStorageCapacity)] ? 
                                               [sharedManager randomizeStorageCapacity] : @"64";
                        
                        NSDictionary *storageInfo = [sharedManager generateStorageForCapacity:capacity];
                        if (storageInfo) {
                            [sharedManager setTotalStorageCapacity:storageInfo[@"TotalStorage"]];
                            [sharedManager setFreeStorageSpace:storageInfo[@"FreeStorage"]];
                            [sharedManager setFilesystemType:storageInfo[@"FilesystemType"]];
                            PXLog(@"[WeaponX] 💾 Generated new storage information: %@ GB", storageInfo[@"TotalStorage"]);
                        }
                    }
                }
            }
            else if ([type isEqualToString:@"Battery"]) {
                // Use BatteryManager to generate new battery info
                id batteryManager = NSClassFromString(@"BatteryManager");
                if (batteryManager && [batteryManager respondsToSelector:@selector(sharedManager)]) {
                    id sharedManager = [batteryManager sharedManager];
                    if (sharedManager && [sharedManager respondsToSelector:@selector(generateBatteryInfo)]) {
                        NSDictionary *batteryInfo = [sharedManager generateBatteryInfo];
                        if (batteryInfo) {
                            PXLog(@"[WeaponX] 🔋 Generated new battery information: %@%%", 
                                 @([batteryInfo[@"BatteryLevel"] floatValue] * 100));
                        }
                    }
                }
            }
            else if ([type isEqualToString:@"AppInstallUUID"]) {
                [self generateAppInstallUUID];
            }
            else if ([type isEqualToString:@"AppContainerUUID"]) {
                [self generateAppContainerUUID];
            }
            else if ([type isEqualToString:@"DeviceTheme"]) {
                NSString *theme = [self generateDeviceTheme];
                if (theme) {
                    PXLog(@"[WeaponX] 🎨 Generated device theme: %@", theme);
                }
            }
        }
    }
    
    // Always ensure device model exists (prefer DB-based device profile if available)
    if (![self currentValueForIdentifier:@"DeviceModel"]) {
        NSString *m = [self regenerateDeviceProfileGroup];
        if (!m) {
            NSString *deviceModel = [self generateDeviceModel];
            if (deviceModel) {
                [self setCustomDeviceModel:deviceModel];
            }
        }
    }
    
    // For WiFi specifically, also update the SystemConfiguration plist
    if ([type isEqualToString:@"WiFi"]) {
        NSString *securitySettingsPath = @"/var/mobile/Library/Preferences/com.weaponx.securitySettings.plist";
        NSMutableDictionary *settingsDict = [NSMutableDictionary dictionaryWithContentsOfFile:securitySettingsPath] ?: [NSMutableDictionary dictionary];
        settingsDict[@"wifiSpoofEnabled"] = @(enabled);
        [settingsDict writeToFile:securitySettingsPath atomically:YES];
        
        // Also update in UserDefaults for compatibility
        NSUserDefaults *settings = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
        [settings setBool:enabled forKey:@"wifiSpoofEnabled"];
        [settings synchronize];
        
        // Post notification to inform system about WiFi spoofing change
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                           CFSTR("com.hydra.projectx.toggleWifiSpoof"),
                                           NULL, NULL, YES);
    }
    // For Battery specifically, update the SystemConfiguration plist
    else if ([type isEqualToString:@"Battery"]) {
        NSString *securitySettingsPath = @"/var/mobile/Library/Preferences/com.weaponx.securitySettings.plist";
        NSMutableDictionary *settingsDict = [NSMutableDictionary dictionaryWithContentsOfFile:securitySettingsPath] ?: [NSMutableDictionary dictionary];
        settingsDict[@"batterySpoofEnabled"] = @(enabled);
        [settingsDict writeToFile:securitySettingsPath atomically:YES];
        
        // Also update in UserDefaults for compatibility
        NSUserDefaults *settings = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
        [settings setBool:enabled forKey:@"batterySpoofEnabled"];
        [settings synchronize];
        
        // Post notification to inform system about Battery spoofing change
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                           CFSTR("com.hydra.projectx.toggleBatterySpoof"),
                                           NULL, NULL, YES);
    }
    // For DeviceTheme, update the SystemConfiguration plist
    else if ([type isEqualToString:@"DeviceTheme"]) {
        NSString *securitySettingsPath = @"/var/mobile/Library/Preferences/com.weaponx.securitySettings.plist";
        NSMutableDictionary *settingsDict = [NSMutableDictionary dictionaryWithContentsOfFile:securitySettingsPath] ?: [NSMutableDictionary dictionary];
        settingsDict[@"deviceThemeSpoofEnabled"] = @(enabled);
        [settingsDict writeToFile:securitySettingsPath atomically:YES];
        
        // Also update in UserDefaults for compatibility
        NSUserDefaults *settings = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
        [settings setBool:enabled forKey:@"deviceThemeSpoofEnabled"];
        [settings synchronize];
        
        // Post notification to inform system about DeviceTheme spoofing change
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                           CFSTR("com.hydra.projectx.toggleDeviceThemeSpoof"),
                                           NULL, NULL, YES);
    }
    
    [self saveSettings];
}

- (BOOL)isIdentifierEnabled:(NSString *)type {
    return [self.settings[type] boolValue];
}

#pragma mark - Current Values

- (NSString *)currentValueForIdentifier:(NSString *)type {
    // Special hardcoded serial number for Filza and ADManager
    if ([type isEqualToString:@"SerialNumber"]) {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if (bundleID) {
            if ([bundleID isEqualToString:@"com.tigisoftware.Filza"] || 
                [bundleID isEqualToString:@"com.tigisoftware.ADManager"]) {
                // Return hardcoded serial number for these specific apps
                NSString *hardcodedSerial = @"FCCC15Q4HG04";
                PXLog(@"[WeaponX] 📱 Returning hardcoded serial number for %@: %@", bundleID, hardcodedSerial);
                return hardcodedSerial;
            }
        }
    }
    
    // First try to get from profile-specific storage
    NSString *identityDir = [self profileIdentityPath];
    if (identityDir) {
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSDictionary *deviceIds = [NSDictionary dictionaryWithContentsOfFile:deviceIdsPath];
        NSString *value = deviceIds[type];
        
        if (value) {
            PXLog(@"Found %@ value in device_ids.plist: %@", type, value);
            return value;
        }
        
        // If not found in combined file, try type-specific files
        if ([type isEqualToString:@"IDFA"]) {
            NSString *idfaPath = [identityDir stringByAppendingPathComponent:@"advertising_id.plist"];
            NSDictionary *idfaDict = [NSDictionary dictionaryWithContentsOfFile:idfaPath];
            if (idfaDict && idfaDict[@"value"]) {
                PXLog(@"Found IDFA in advertising_id.plist: %@", idfaDict[@"value"]);
                return idfaDict[@"value"];
            }
        } 
        else if ([type isEqualToString:@"IDFV"]) {
            NSString *idfvPath = [identityDir stringByAppendingPathComponent:@"vendor_id.plist"];
            NSDictionary *idfvDict = [NSDictionary dictionaryWithContentsOfFile:idfvPath];
            if (idfvDict && idfvDict[@"value"]) {
                PXLog(@"Found IDFV in vendor_id.plist: %@", idfvDict[@"value"]);
                return idfvDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"SystemBootUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"system_boot_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found SystemBootUUID in system_boot_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"DyldCacheUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"dyld_cache_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found DyldCacheUUID in dyld_cache_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"PasteboardUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"pasteboard_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found PasteboardUUID in pasteboard_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"KeychainUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"keychain_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found KeychainUUID in keychain_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"UserDefaultsUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"userdefaults_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found UserDefaultsUUID in userdefaults_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"CoreDataUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"coredata_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found CoreDataUUID in coredata_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"AppInstallUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"appinstall_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found AppInstallUUID in appinstall_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"AppContainerUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"appcontainer_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found AppContainerUUID in appcontainer_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"AppGroupUUID"]) {
            NSString *uuidPath = [identityDir stringByAppendingPathComponent:@"appgroup_uuid.plist"];
            NSDictionary *uuidDict = [NSDictionary dictionaryWithContentsOfFile:uuidPath];
            if (uuidDict && uuidDict[@"value"]) {
                PXLog(@"Found AppGroupUUID in appgroup_uuid.plist: %@", uuidDict[@"value"]);
                return uuidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"IMEI"]) {
            NSString *imeiPath = [identityDir stringByAppendingPathComponent:@"imei.plist"];
            NSDictionary *imeiDict = [NSDictionary dictionaryWithContentsOfFile:imeiPath];
            if (imeiDict && imeiDict[@"value"]) {
                PXLog(@"Found IMEI in imei.plist: %@", imeiDict[@"value"]);
                return imeiDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"MEID"]) {
            NSString *meidPath = [identityDir stringByAppendingPathComponent:@"meid.plist"];
            NSDictionary *meidDict = [NSDictionary dictionaryWithContentsOfFile:meidPath];
            if (meidDict && meidDict[@"value"]) {
                PXLog(@"Found MEID in meid.plist: %@", meidDict[@"value"]);
                return meidDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"DeviceName"]) {
            NSString *deviceNamePath = [identityDir stringByAppendingPathComponent:@"device_name.plist"];
            NSDictionary *deviceNameDict = [NSDictionary dictionaryWithContentsOfFile:deviceNamePath];
            if (deviceNameDict && deviceNameDict[@"value"]) {
                PXLog(@"Found DeviceName in device_name.plist: %@", deviceNameDict[@"value"]);
                return deviceNameDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"SerialNumber"]) {
            NSString *serialPath = [identityDir stringByAppendingPathComponent:@"serial_number.plist"];
            NSDictionary *serialDict = [NSDictionary dictionaryWithContentsOfFile:serialPath];
            if (serialDict && serialDict[@"value"]) {
                PXLog(@"Found SerialNumber in serial_number.plist: %@", serialDict[@"value"]);
                return serialDict[@"value"];
            }
        }
        else if ([type isEqualToString:@"WiFi"]) {
            // Check for WiFi info in the profile
            NSString *wifiInfoPath = [identityDir stringByAppendingPathComponent:@"wifi_info.plist"];
            NSDictionary *wifiInfo = [NSDictionary dictionaryWithContentsOfFile:wifiInfoPath];
            if (wifiInfo && wifiInfo[@"ssid"] && wifiInfo[@"bssid"]) {
                NSString *formattedValue = [NSString stringWithFormat:@"%@ (%@)", wifiInfo[@"ssid"], wifiInfo[@"bssid"]];
                PXLog(@"Found WiFi info in wifi_info.plist: %@", formattedValue);
                return formattedValue;
            }
        }
        else if ([type isEqualToString:@"StorageSystem"]) {
            NSString *storagePath = [identityDir stringByAppendingPathComponent:@"storage.plist"];
            NSDictionary *storageDict = [NSDictionary dictionaryWithContentsOfFile:storagePath];
            if (storageDict && storageDict[@"TotalStorage"] && storageDict[@"FreeStorage"]) {
                NSString *formattedStorage = [NSString stringWithFormat:@"Total: %@ GB, Free: %@ GB", 
                                             storageDict[@"TotalStorage"], 
                                             storageDict[@"FreeStorage"]];
                PXLog(@"Found Storage info in storage.plist: %@", formattedStorage);
                return formattedStorage;
            }
        }
        else if ([type isEqualToString:@"BatteryLevel"] || [type isEqualToString:@"LowPowerMode"]) {
            NSString *batteryPath = [identityDir stringByAppendingPathComponent:@"battery_info.plist"];
            NSDictionary *batteryDict = [NSDictionary dictionaryWithContentsOfFile:batteryPath];
            if (batteryDict && batteryDict[type]) {
                PXLog(@"Found %@ in battery_info.plist: %@", type, batteryDict[type]);
                return batteryDict[type];
            }
        }
        else if ([type isEqualToString:@"SystemUptime"]) {
            NSString *profilePath = [self profileIdentityPath];
NSString *uptimePath = [profilePath stringByAppendingPathComponent:@"system_uptime.plist"];
NSDictionary *uptimeDict = [NSDictionary dictionaryWithContentsOfFile:uptimePath];
if (uptimeDict && uptimeDict[@"value"]) {
    NSTimeInterval uptime = [uptimeDict[@"value"] doubleValue];
    if (uptime > 0) {
        NSString *formattedUptime = [NSString stringWithFormat:@"%.2f hours", uptime / 3600.0];
        PXLog(@"[WeaponX] 📄 Showing SystemUptime from system_uptime.plist: %@", formattedUptime);
        return formattedUptime;
    }
}
return @"Not Set";
        }
        else if ([type isEqualToString:@"BootTime"]) {
            NSString *profilePath = [self profileIdentityPath];
NSString *bootTimePath = [profilePath stringByAppendingPathComponent:@"boot_time.plist"];
NSDictionary *bootTimeDict = [NSDictionary dictionaryWithContentsOfFile:bootTimePath];
if (bootTimeDict && bootTimeDict[@"value"]) {
    NSDate *bootTime = bootTimeDict[@"value"];
    if ([bootTime isKindOfClass:[NSDate class]]) {
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        formatter.dateStyle = NSDateFormatterMediumStyle;
        formatter.timeStyle = NSDateFormatterMediumStyle;
        NSString *formattedBootTime = [formatter stringFromDate:bootTime];
        PXLog(@"[WeaponX] 📄 Showing BootTime from boot_time.plist: %@", formattedBootTime);
        return formattedBootTime;
    }
}
return @"Not Set";
        }
        
        PXLog(@"No %@ value found in profile-specific files", type);
    } else {
        PXLog(@"Could not access identity directory for profile");
    }
    
    // Special handling for IOS Version which returns a composite string
    if ([type isEqualToString:@"IOSVersion"]) {
        // First try to get from profile-specific storage
        NSString *identityDir = [self profileIdentityPath];
        if (identityDir) {
            // First try to get from device_ids.plist
            NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
            NSDictionary *deviceIds = [NSDictionary dictionaryWithContentsOfFile:deviceIdsPath];
            NSString *version = deviceIds[@"IOSVersion"];
            
            // If we have a pre-formatted version string, use it
            if (version && [version containsString:@"("]) {
                PXLog(@"[WeaponX] Found pre-formatted iOS version: %@", version);
                return version;
            }
            
            // If not pre-formatted, try to combine version and build
            NSString *build = deviceIds[@"IOSBuild"];
            if (version && build) {
                NSString *formattedVersion = [NSString stringWithFormat:@"%@ (%@)", version, build];
                PXLog(@"[WeaponX] Formatted iOS version from components: %@", formattedVersion);
                return formattedVersion;
            }
        }
        
        // Fall back to IOSVersionInfo if profile-specific value not found
        NSDictionary *currentVersion = [[IOSVersionInfo sharedManager] currentIOSVersionInfo];
        if (currentVersion && currentVersion[@"version"] && currentVersion[@"build"]) {
            NSString *formattedVersion = [NSString stringWithFormat:@"%@ (%@)", currentVersion[@"version"], currentVersion[@"build"]];
            PXLog(@"[WeaponX] Formatted iOS version from IOSVersionInfo: %@", formattedVersion);
            return formattedVersion;
        }
        
        PXLog(@"[WeaponX] No iOS version information found");
        return nil;
    }
    
    // Special handling for WiFi which needs the WiFiManager
    if ([type isEqualToString:@"WiFi"]) {
        // Try to get WiFi info from WiFiManager
        id wifiManager = NSClassFromString(@"WiFiManager");
        if (wifiManager && [wifiManager respondsToSelector:@selector(sharedManager)]) {
            id sharedManager = [wifiManager sharedManager];
            if (sharedManager) {
                // Get WiFi info based on available methods
                NSString *ssid = nil;
                NSString *bssid = nil;
                
                if ([sharedManager respondsToSelector:@selector(currentSSID)]) {
                    ssid = [sharedManager currentSSID];
                }
                
                if ([sharedManager respondsToSelector:@selector(currentBSSID)]) {
                    bssid = [sharedManager currentBSSID];
                }
                
                if (ssid && bssid) {
                    NSString *formattedValue = [NSString stringWithFormat:@"%@ (%@)", ssid, bssid];
                    PXLog(@"[WeaponX] WiFi info from WiFiManager: %@", formattedValue);
                    return formattedValue;
                } else if (ssid) {
                    PXLog(@"[WeaponX] WiFi SSID only from WiFiManager: %@", ssid);
                    return ssid;
                }
            }
        }
    }
    
    // Special handling for StorageSystem - try to get from StorageManager
    if ([type isEqualToString:@"StorageSystem"]) {
        id storageManager = NSClassFromString(@"StorageManager");
        if (storageManager && [storageManager respondsToSelector:@selector(sharedManager)]) {
            id sharedManager = [storageManager sharedManager];
            if (sharedManager) {
                NSString *totalStorage = nil;
                NSString *freeStorage = nil;
                
                if ([sharedManager respondsToSelector:@selector(totalStorageCapacity)]) {
                    totalStorage = [sharedManager totalStorageCapacity];
                }
                
                if ([sharedManager respondsToSelector:@selector(freeStorageSpace)]) {
                    freeStorage = [sharedManager freeStorageSpace];
                }
                
                if (totalStorage && freeStorage) {
                    NSString *formattedStorage = [NSString stringWithFormat:@"Total: %@ GB, Free: %@ GB", 
                                               totalStorage, freeStorage];
                    return formattedStorage;
                }
                
                // Try to generate new values if we couldn't get existing ones
                if ([sharedManager respondsToSelector:@selector(generateStorageForCapacity:)]) {
                    // Randomly choose between 64GB and 128GB
                    NSString *capacity = [sharedManager respondsToSelector:@selector(randomizeStorageCapacity)] ? 
                                           [sharedManager randomizeStorageCapacity] : @"64";
                    
                    NSDictionary *storageInfo = [sharedManager generateStorageForCapacity:capacity];
                    if (storageInfo) {
                        [sharedManager setTotalStorageCapacity:storageInfo[@"TotalStorage"]];
                        [sharedManager setFreeStorageSpace:storageInfo[@"FreeStorage"]];
                        [sharedManager setFilesystemType:storageInfo[@"FilesystemType"]];
                        
                        NSString *formattedStorage = [NSString stringWithFormat:@"Total: %@ GB, Free: %@ GB", 
                                                  storageInfo[@"TotalStorage"], 
                                                  storageInfo[@"FreeStorage"]];
                        return formattedStorage;
                    }
                }
            }
        }
        
        // Final fallback for storage - 40% chance for 64GB, 60% chance for 128GB
        BOOL use128GB = (arc4random_uniform(100) < 60);
        NSString *storageCapacity = use128GB ? @"128" : @"64";
        NSString *freeSpaceValue = use128GB ? @"38.4" : @"19.8";
        
        // Save these values to StorageManager to ensure consistency
        if (storageManager && [storageManager respondsToSelector:@selector(sharedManager)]) {
            id sharedManager = [storageManager sharedManager];
            if (sharedManager) {
                [sharedManager setTotalStorageCapacity:storageCapacity];
                [sharedManager setFreeStorageSpace:freeSpaceValue];
                [sharedManager setFilesystemType:@"0x1A"];
            }
        }
        
        return [NSString stringWithFormat:@"Total: %@ GB, Free: %@ GB", storageCapacity, freeSpaceValue];
    }
    
    // Special handling for Battery info - try to get from BatteryManager
    if ([type isEqualToString:@"BatteryLevel"] || [type isEqualToString:@"LowPowerMode"] || [type isEqualToString:@"Battery"]) {
        id batteryManager = NSClassFromString(@"BatteryManager");
        if (batteryManager && [batteryManager respondsToSelector:@selector(sharedManager)]) {
            id sharedManager = [batteryManager sharedManager];
            if (sharedManager) {
                // Force a reload from disk first to ensure fresh values
                if ([sharedManager respondsToSelector:@selector(loadBatteryInfoFromDisk)]) {
                    [sharedManager loadBatteryInfoFromDisk];
                }
                
                // Handle Battery identifier which includes both level and low power mode
                if ([type isEqualToString:@"Battery"]) {
                    if ([sharedManager respondsToSelector:@selector(batteryLevel)]) {
                        
                        // Use explicit cast to BatteryManager to avoid confusion with UIDevice method
                        NSString *level = [(BatteryManager *)sharedManager batteryLevel];
                        
                        if (level) {
                            float levelFloat = [level floatValue];
                            int percentage = (int)(levelFloat * 100);
                            
                            NSString *displayValue = [NSString stringWithFormat:@"%d%%", percentage];
                                 
                            PXLog(@"[WeaponX] 🔋 Battery info from BatteryManager: %@", displayValue);
                            return displayValue;
                        }
                    }
                    
                    // If we couldn't get both values, try to get a pre-formatted display value
                    if ([sharedManager respondsToSelector:@selector(generateBatteryInfo)]) {
                        NSDictionary *batteryInfo = [sharedManager generateBatteryInfo];
                        if (batteryInfo) {
                            // Check if we have a pre-formatted display value
                            if (batteryInfo[@"DisplayValue"]) {
                                return batteryInfo[@"DisplayValue"];
                            }
                            
                            // Otherwise, format it ourselves
                            NSString *level = batteryInfo[@"BatteryLevel"];
                            
                            if (level) {
                                float levelFloat = [level floatValue];
                                int percentage = (int)(levelFloat * 100);
                                
                                NSString *displayValue = [NSString stringWithFormat:@"%d%%", percentage];
                                     
                                PXLog(@"[WeaponX] 🔋 Generated battery info: %@", displayValue);
                                return displayValue;
                            }
                        }
                    }
                } 
                // Handle individual battery values
                else if ([type isEqualToString:@"BatteryLevel"] && [sharedManager respondsToSelector:@selector(batteryLevel)]) {
                    NSString *level = [(BatteryManager *)sharedManager batteryLevel];
                    if (level) {
                        PXLog(@"[WeaponX] 🔋 Battery level from BatteryManager: %@", level);
                        return level;
                    }
                }
            }
        }
    }
    
    // Special handling for SystemUptime/BootTime
    if ([type isEqualToString:@"SystemUptime"]) {
        NSString *profilePath = [self profileIdentityPath];
NSTimeInterval uptime = [[UptimeManager sharedManager] currentUptimeForProfile:profilePath];
        NSString *result = [NSString stringWithFormat:@"%.2f hours", uptime / 3600.0];
        PXLog(@"Default SystemUptime value: %@", result);
        return result;
    }
    else if ([type isEqualToString:@"BootTime"]) {
        NSString *profilePath = [self profileIdentityPath];
NSDate *bootTime = [[UptimeManager sharedManager] currentBootTimeForProfile:profilePath];
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        formatter.dateStyle = NSDateFormatterMediumStyle;
        formatter.timeStyle = NSDateFormatterMediumStyle;
        NSString *result = [formatter stringFromDate:bootTime];
        PXLog(@"Default BootTime value: %@", result);
        return result;
    }
    
    // Fallback to the original implementation if profile-specific value not found
    PXLog(@"Falling back to default implementation for %@", type);
    if ([type isEqualToString:@"IDFA"]) {
        NSString *result = [[IDFAManager sharedManager] currentIDFA];
        PXLog(@"Default IDFA value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"IDFV"]) {
        NSString *result = [[IDFVManager sharedManager] currentIDFV];
        PXLog(@"Default IDFV value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"SystemBootUUID"]) {
        NSString *result = [[SystemUUIDManager sharedManager] currentBootUUID];
        PXLog(@"Default SystemBootUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"DyldCacheUUID"]) {
        NSString *result = [[DyldCacheUUIDManager sharedManager] currentDyldCacheUUID];
        PXLog(@"Default DyldCacheUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"PasteboardUUID"]) {
        NSString *result = [[PasteboardUUIDManager sharedManager] currentPasteboardUUID];
        PXLog(@"Default PasteboardUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"KeychainUUID"]) {
        NSString *result = [[KeychainUUIDManager sharedManager] currentKeychainUUID];
        PXLog(@"Default KeychainUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"UserDefaultsUUID"]) {
        NSString *result = [[UserDefaultsUUIDManager sharedManager] currentUserDefaultsUUID];
        PXLog(@"Default UserDefaultsUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"AppGroupUUID"]) {
        NSString *result = [[AppGroupUUIDManager sharedManager] currentAppGroupUUID];
        PXLog(@"Default AppGroupUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"CoreDataUUID"]) {
        NSString *result = [[CoreDataUUIDManager sharedManager] currentCoreDataUUID];
        PXLog(@"Default CoreDataUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"AppInstallUUID"]) {
        NSString *result = [[AppInstallUUIDManager sharedManager] currentAppInstallUUID];
        PXLog(@"Default AppInstallUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"AppContainerUUID"]) {
        NSString *result = [[AppContainerUUIDManager sharedManager] currentAppContainerUUID];
        PXLog(@"Default AppContainerUUID value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"DeviceName"]) {
        NSString *result = [[DeviceNameManager sharedManager] currentDeviceName];
        PXLog(@"Default DeviceName value: %@", result ?: @"nil");
        return result;
    } else if ([type isEqualToString:@"SerialNumber"]) {
        NSString *result = [[SerialNumberManager sharedManager] currentSerialNumber];
        PXLog(@"Default SerialNumber value: %@", result ?: @"nil");
        return result;
    }
    
    PXLog(@"No value found for %@", type);
    return nil;
}

#pragma mark - App Management

- (void)refreshScopedAppsInfoIfNeeded {
    // Iterate through all scoped apps and update their version/build info
    for (NSString *bundleID in self.scopedApps) {
        LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
        if (appProxy) {
            NSString *currentVersion = appProxy.shortVersionString;
            NSString *currentBuild = appProxy.bundleVersion ?: @"";
            NSMutableDictionary *appInfo = self.scopedApps[bundleID];
            BOOL needsUpdate = ![appInfo[@"version"] isEqualToString:currentVersion] ||
                               ![appInfo[@"build"] isEqualToString:currentBuild];
            if (needsUpdate) {
                appInfo[@"version"] = currentVersion ?: @"";
                appInfo[@"build"] = currentBuild ?: @"";
            }
        }
    }
    [self saveSettings];
}

- (void)addApplicationToScope:(NSString *)bundleID {
    if (!bundleID.length) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" 
                                       code:3001 
                                   userInfo:@{NSLocalizedDescriptionKey: @"Invalid bundle ID"}];
        return;
    }
    
    // Prevent the WeaponX app itself from being added to the scope list
    if ([bundleID isEqualToString:@"com.hydra.projectx"]) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" 
                                       code:3003 
                                   userInfo:@{NSLocalizedDescriptionKey: @"Cannot add the WeaponX app itself to the scope list"}];
        PXLog(@"[WeaponX] ⚠️ Prevented attempt to add the WeaponX app to the scope list");
        return;
    }
    
    // Get app info using LSApplicationProxy
    LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
    if (!appProxy) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" 
                                       code:3002 
                                   userInfo:@{NSLocalizedDescriptionKey: @"Application not found"}];
        return;
    }
    
    NSMutableDictionary *appInfo = [NSMutableDictionary dictionary];
    appInfo[@"name"] = appProxy.localizedName ?: bundleID;
    appInfo[@"version"] = appProxy.shortVersionString ?: @"App Not Found";
    NSString *buildVersion = nil;
    id proxy = (id)appProxy;
    if ([proxy respondsToSelector:@selector(bundleVersion)]) {
        buildVersion = [proxy performSelector:@selector(bundleVersion)];
    } else if ([proxy respondsToSelector:@selector(valueForKey:)]) {
        buildVersion = [proxy valueForKey:@"bundleVersion"];
        if (!buildVersion) {
            buildVersion = [proxy valueForKey:@"CFBundleVersion"];
        }
    }
    appInfo[@"build"] = buildVersion ?: @"Unknown";  // Add build number
    appInfo[@"installed"] = @YES;
    appInfo[@"enabled"] = @YES;
    
    // Store using the original case-sensitive bundle ID
    appInfo[@"bundleID"] = bundleID;
    appInfo[@"originalBundleID"] = bundleID;  // Store original case-sensitive version
    
    // Use the original case-sensitive bundle ID as the dictionary key
    self.scopedApps[bundleID] = appInfo;
    [self saveSettings];
}

- (void)removeApplicationFromScope:(NSString *)bundleID {
    [self.scopedApps removeObjectForKey:bundleID];
    [self saveSettings];
}

- (void)setApplication:(NSString *)bundleID enabled:(BOOL)enabled {
    NSMutableDictionary *appInfo = [self.scopedApps[bundleID] mutableCopy];
    if (appInfo) {
        appInfo[@"enabled"] = @(enabled);
        self.scopedApps[bundleID] = appInfo;
        [self saveSettings];
    }
}

- (NSDictionary *)getApplicationInfo:(NSString *)bundleID {
    if (bundleID) {
        NSDictionary *appInfo = self.scopedApps[bundleID];
        if (appInfo) {
            return [appInfo mutableCopy];
        }
        return nil;
    }
    
    // Return all apps with their original case-preserved bundle IDs
    NSMutableDictionary *displayApps = [NSMutableDictionary dictionary];
    [self.scopedApps enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSDictionary *appInfo, BOOL *stop) {
        NSMutableDictionary *displayInfo = [appInfo mutableCopy];
        NSString *originalBundleID = appInfo[@"originalBundleID"];
        if (originalBundleID) {
            // Use the original case-sensitive bundle ID
            displayInfo[@"bundleID"] = originalBundleID;
            displayApps[key] = displayInfo;
        } else {
            displayApps[key] = displayInfo;
        }
    }];
    return displayApps;
}

// Cache for application enabled status to reduce frequent lookups and logging
static NSMutableDictionary *_appEnabledCache = nil;
static NSTimeInterval _cacheExpirationTime = 30.0; // Cache results for 30 seconds

- (BOOL)isApplicationEnabled:(NSString *)bundleID {
    // Initialize cache if needed
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _appEnabledCache = [NSMutableDictionary dictionary];
    });
    
    // Check if we have a cached result that's still valid
    NSDictionary *cachedResult = _appEnabledCache[bundleID];
    if (cachedResult) {
        NSTimeInterval timestamp = [cachedResult[@"timestamp"] doubleValue];
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        
        // If the cache hasn't expired, use it
        if (now - timestamp < _cacheExpirationTime) {
            return [cachedResult[@"enabled"] boolValue];
        }
    }
    
    // Only log once every 30 seconds per app to avoid spamming logs
    static NSString *lastLoggedApp = nil;
    static NSTimeInterval lastLogTime = 0;
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    BOOL shouldLog = ![lastLoggedApp isEqualToString:bundleID] || (now - lastLogTime > 30.0);
    
    if (shouldLog) {
        PXLog(@"[WeaponX] IdentifierManager DEBUG: Checking if app is enabled: %@", bundleID);
        lastLoggedApp = [bundleID copy];
        lastLogTime = now;
    }
    
    // Never consider the WeaponX app itself as enabled for spoofing
    if ([bundleID isEqualToString:@"com.hydra.projectx"]) {
        if (shouldLog) {
            PXLog(@"[WeaponX] IdentifierManager DEBUG: WeaponX app itself is never considered enabled for spoofing");
        }
        
        // Cache the result
        _appEnabledCache[bundleID] = @{@"enabled": @NO, @"timestamp": @(now)};
        return NO;
    }
    
    // Direct equality check first for performance
    if (self.scopedApps[bundleID]) {
        BOOL isEnabled = [self.scopedApps[bundleID][@"enabled"] boolValue];
        
        if (shouldLog) {
            PXLog(@"[WeaponX] IdentifierManager DEBUG: Found app %@ in scopedApps, enabled = %@", bundleID, isEnabled ? @"YES" : @"NO");
        }
        
        // Cache the result
        _appEnabledCache[bundleID] = @{@"enabled": @(isEnabled), @"timestamp": @(now)};
        return isEnabled;
    }
    
    // Ensure we have the latest scoped apps data
    // Only reload scoped apps if we haven't reloaded recently
    static NSTimeInterval lastReloadTime = 0;
    if (now - lastReloadTime > 60.0) { // Only reload every minute at most
        if (shouldLog) {
            PXLog(@"[WeaponX] IdentifierManager DEBUG: App not found directly, reloading scoped apps");
        }
        [self loadScopedApps];
        lastReloadTime = now;
    }
    
    // Check again after potentially reloading the scoped apps
    if (self.scopedApps[bundleID]) {
        BOOL isEnabled = [self.scopedApps[bundleID][@"enabled"] boolValue];
        
        if (shouldLog) {
            PXLog(@"[WeaponX] IdentifierManager DEBUG: Found app %@ after reload, enabled = %@", bundleID, isEnabled ? @"YES" : @"NO");
        }
        
        // Cache the result
        _appEnabledCache[bundleID] = @{@"enabled": @(isEnabled), @"timestamp": @(now)};
        return isEnabled;
    }
    
    // Fallback to case-insensitive comparison if needed (this is expensive, so only log if needed)
    if (shouldLog) {
        PXLog(@"[WeaponX] IdentifierManager DEBUG: App still not found, trying case-insensitive match");
    }
    
    NSString *lowercaseBundleID = [bundleID lowercaseString];
    for (NSString *key in self.scopedApps) {
        if ([[key lowercaseString] isEqualToString:lowercaseBundleID]) {
            BOOL isEnabled = [self.scopedApps[key][@"enabled"] boolValue];
            
            if (shouldLog) {
                PXLog(@"[WeaponX] IdentifierManager DEBUG: Found app %@ via case-insensitive match with %@, enabled = %@", 
                      bundleID, key, isEnabled ? @"YES" : @"NO");
            }
            
            // Cache the result using the original bundle ID
            _appEnabledCache[bundleID] = @{@"enabled": @(isEnabled), @"timestamp": @(now)};
            return isEnabled;
        }
    }
    
    // App not found, only log this information sparingly
    if (shouldLog) {
        // Limit the keys we log to avoid excessive memory usage
        NSArray *allKeys = [self.scopedApps allKeys];
        NSArray *limitedKeys = allKeys.count > 10 ? [allKeys subarrayWithRange:NSMakeRange(0, 10)] : allKeys;
        
        PXLog(@"[WeaponX] IdentifierManager DEBUG: App %@ not found in scoped apps list", bundleID);
        PXLog(@"[WeaponX] IdentifierManager DEBUG: First %lu scoped apps: %@", (unsigned long)limitedKeys.count, limitedKeys);
    }
    
    // Cache the negative result
    _appEnabledCache[bundleID] = @{@"enabled": @NO, @"timestamp": @(now)};
    
    return NO;
}

// New method to load scoped apps configuration explicitly
- (void)loadScopedApps {
    // Try rootless path first
    NSString *prefsPath = @"/var/mobile/Library/Preferences";
    NSString *scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
    PXLog(@"[WeaponX] IdentifierManager DEBUG: Trying to load scoped apps from: %@", scopedAppsFile);
    
    // Fallback to standard path if rootless path doesn't exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:scopedAppsFile]) {
        PXLog(@"[WeaponX] IdentifierManager DEBUG: First path not found, trying Dopamine 2 path");
        // Try Dopamine 2 path
        prefsPath = @"/private/var/mobile/Library/Preferences";
        scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
        
        // Fallback to older paths if needed
        if (![fileManager fileExistsAtPath:scopedAppsFile]) {
            PXLog(@"[WeaponX] IdentifierManager DEBUG: Dopamine 2 path not found, trying legacy path");
            prefsPath = @"/var/mobile/Library/Preferences";
            scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
        }
    }
    
    PXLog(@"[WeaponX] IdentifierManager DEBUG: Loading scoped apps from: %@", scopedAppsFile);
    PXLog(@"[WeaponX] IdentifierManager DEBUG: File exists: %@", [fileManager fileExistsAtPath:scopedAppsFile] ? @"YES" : @"NO");
    
    // Load scoped apps from the global scope file
    NSDictionary *scopedAppsDict = [NSDictionary dictionaryWithContentsOfFile:scopedAppsFile];
    PXLog(@"[WeaponX] IdentifierManager DEBUG: Loaded dictionary: %@", scopedAppsDict ? @"YES" : @"NO");
    
    NSDictionary *savedApps = scopedAppsDict[@"ScopedApps"];
    PXLog(@"[WeaponX] IdentifierManager DEBUG: Scoped apps entry found in dictionary: %@", savedApps ? @"YES" : @"NO");
    
    if (savedApps) {
        PXLog(@"[WeaponX] IdentifierManager DEBUG: Number of scoped apps found: %lu", (unsigned long)savedApps.count);
        if (savedApps.count > 0) {
            PXLog(@"[WeaponX] IdentifierManager DEBUG: App list includes: %@", [savedApps allKeys]);
        }
        // Make sure we properly update the scoped apps dictionary
        if (!self.scopedApps) {
            self.scopedApps = [savedApps mutableCopy];
        } else {
            [self.scopedApps setDictionary:savedApps];
        }
        PXLog(@"[WeaponX] IdentifierManager: Loaded %lu scoped apps from %@", (unsigned long)savedApps.count, scopedAppsFile);
    } else {
        // Re-initialize the app list if loading failed
        if (!self.scopedApps) {
            self.scopedApps = [NSMutableDictionary dictionary];
        } else {
            [self.scopedApps removeAllObjects];
        }
        PXLog(@"[WeaponX] IdentifierManager: ⚠️ Failed to load scoped apps, using empty list");
    }
}

#pragma mark - Persistence

- (void)saveSettings {
    // Get the proper preferences path
    NSString *prefsPath = @"/var/mobile/Library/Preferences";
    NSString *prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.settings.plist"];
    
    // Global settings file for scoped apps (universal across all profiles)
    NSString *scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
    
    // Fallback to standard path if rootless path doesn't exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:prefsPath]) {
        // Try Dopamine 2 path first
        prefsPath = @"/private/var/mobile/Library/Preferences";
        prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.settings.plist"];
        scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
        
        // Fallback to standard path if needed
        if (![fileManager fileExistsAtPath:prefsFile]) {
            prefsPath = @"/var/mobile/Library/Preferences";
            prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.settings.plist"];
            scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
            
            // If still not found, try the original filename as a fallback
            if (![fileManager fileExistsAtPath:prefsFile]) {
                prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.plist"];
            }
        }
    }
    
    // Ensure preferences directory exists with proper permissions
    NSError *dirError = nil;
    
    // Create all intermediate directories with proper permissions
    if (![fileManager fileExistsAtPath:prefsPath]) {
        NSDictionary *attributes = @{NSFilePosixPermissions: @0755,
                                    NSFileOwnerAccountName: @"mobile"};
        
        if (![fileManager createDirectoryAtPath:prefsPath 
                    withIntermediateDirectories:YES 
                                     attributes:attributes
                                          error:&dirError]) {
            self.error = [NSError errorWithDomain:@"com.hydra.projectx" 
                                            code:4004 
                                        userInfo:@{NSLocalizedDescriptionKey: 
                                                  [NSString stringWithFormat:@"Failed to create preferences directory: %@", 
                                                   dirError.localizedDescription]}];
            return;
        }
    }
    
    // Create dictionary to save for main settings
    NSMutableDictionary *saveDict = [NSMutableDictionary dictionary];
    
    // Save enabled states - these are still global settings
    saveDict[@"EnabledIdentifiers"] = [self.settings copy];
    
    // Mark settings as initialized
    saveDict[@"SettingsInitialized"] = @YES;
    
    // Save main settings
    BOOL success = [saveDict writeToFile:prefsFile atomically:YES];
    if (!success) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" 
                                      code:4005 
                                  userInfo:@{NSLocalizedDescriptionKey: @"Failed to save settings"}];
        return;
    }
    
    // Save scoped apps separately in the global scope file
    NSDictionary *scopedAppsDict = @{@"ScopedApps": [self.scopedApps copy]};
    success = [scopedAppsDict writeToFile:scopedAppsFile atomically:YES];
    if (!success) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" 
                                      code:4006 
                                  userInfo:@{NSLocalizedDescriptionKey: @"Failed to save global scoped apps"}];
        PXLog(@"[WeaponX] ❌ Failed to save global scoped apps to: %@", scopedAppsFile);
        return;
    } else {
        PXLog(@"[WeaponX] ✅ Saved scoped apps to: %@", scopedAppsFile);
    }
}
    


- (void)loadSettings {
    PXLog(@"[WeaponX] Loading settings...");
    
    // Try rootless path first
    NSString *prefsPath = @"/var/mobile/Library/Preferences";
    NSString *prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.settings.plist"];
    NSString *scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
    
    // Fallback to standard path if rootless path doesn't exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:prefsFile]) {
        PXLog(@"[WeaponX] Settings not found at default path: %@", prefsFile);
        
        // Try Dopamine 2 path
        prefsPath = @"/private/var/mobile/Library/Preferences";
        prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.settings.plist"];
        scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
        
        // Fallback to standard path if needed
        if (![fileManager fileExistsAtPath:prefsFile]) {
            PXLog(@"[WeaponX] Settings not found at private path: %@", prefsFile);
            
            prefsPath = @"/var/mobile/Library/Preferences";
            prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.settings.plist"];
            scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
            
            // If still not found, try the original filename as a fallback
            if (![fileManager fileExistsAtPath:prefsFile]) {
                prefsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.plist"];
                PXLog(@"[WeaponX] Checking fallback legacy path: %@", prefsFile);
            }
        }
    }
    
    PXLog(@"[WeaponX] Final settings file path: %@", prefsFile);
    PXLog(@"[WeaponX] Final scoped apps file path: %@", scopedAppsFile);

    // Load dictionary from main settings file
    NSDictionary *loadedDict = [NSDictionary dictionaryWithContentsOfFile:prefsFile];
    if (loadedDict) {
        PXLog(@"[WeaponX] Successfully loaded settings dictionary.");
    } else {
        PXLog(@"[WeaponX] Failed to load settings dictionary (file may imply empty or permission denied?)");
    }

    // Check if settings are initialized
    if (!loadedDict || ![loadedDict[@"SettingsInitialized"] boolValue]) {
        // Initialize with default values
        PXLog(@"[WeaponX] Settings not initialized, using defaults.");
        self.settings = [NSMutableDictionary dictionaryWithDictionary:@{
            @"IDFA": @NO,
            @"IDFV": @NO,
            @"DeviceName": @NO,
            @"SerialNumber": @NO,
            @"UDID": @NO,
            @"IMEI": @NO,
            @"SystemVersion": @NO,
            @"BuildVersion": @NO,
            @"StorageSystem": @NO,
            @"SystemBootUUID": @NO,
            @"DyldCacheUUID": @NO,
            @"PasteboardUUID": @NO,
            @"KeychainUUID": @NO,
            @"UserDefaultsUUID": @NO,
            @"AppGroupUUID": @NO,
            @"CoreDataUUID": @NO,
            @"AppInstallUUID": @NO,
            @"AppContainerUUID": @NO,
            @"SettingsInitialized": @YES
        }];
    } else {
        // ✅ FIX: Load from the EnabledIdentifiers key, not the entire dictionary
        NSDictionary *enabledIdentifiers = loadedDict[@"EnabledIdentifiers"];
        if (enabledIdentifiers) {
            self.settings = [enabledIdentifiers mutableCopy];
            PXLog(@"[WeaponX] ✅ Loaded %lu identifier settings from EnabledIdentifiers", (unsigned long)self.settings.count);
        } else {
            PXLog(@"[WeaponX] ⚠️ EnabledIdentifiers key not found, using defaults");
            self.settings = [NSMutableDictionary dictionaryWithDictionary:@{
                @"IDFA": @NO,
                @"IDFV": @NO,
                @"DeviceName": @NO,
                @"SerialNumber": @NO
            }];
        }
    }
    
    // Load scoped apps
    NSDictionary *scopedAppsDict = [NSDictionary dictionaryWithContentsOfFile:scopedAppsFile];
    if (scopedAppsDict && scopedAppsDict[@"ScopedApps"]) {
        self.scopedApps = [scopedAppsDict[@"ScopedApps"] mutableCopy];
        PXLog(@"[WeaponX] Loaded Scoped Apps: %lu apps found.", (unsigned long)self.scopedApps.count);
        for (NSString *appID in self.scopedApps) {
            PXLog(@"[WeaponX] Scope App: %@ | Enabled: %@", appID, self.scopedApps[appID][@"enabled"]);
        }
    } else {
        PXLog(@"[WeaponX] No ScopedApps found or failed to load scoped apps file.");
        self.scopedApps = [NSMutableDictionary dictionary];
    }
}

#pragma mark - Error Handling

- (NSError *)lastError {
    return self.error;
}

- (NSString *)generateWiFiInformation {
    // Use WiFiManager to generate new WiFi info
    id wifiManager = NSClassFromString(@"WiFiManager");
    if (wifiManager && [wifiManager respondsToSelector:@selector(sharedManager)]) {
        id sharedManager = [wifiManager sharedManager];
        if (sharedManager && [sharedManager respondsToSelector:@selector(generateWiFiInfo)]) {
            NSDictionary *wifiInfo = [sharedManager generateWiFiInfo];
            if (wifiInfo && wifiInfo[@"ssid"] && wifiInfo[@"bssid"]) {
                NSString *formattedValue = [NSString stringWithFormat:@"%@ (%@)", wifiInfo[@"ssid"], wifiInfo[@"bssid"]];
                PXLog(@"Generated new WiFi information: %@", formattedValue);
                return formattedValue;
            }
        }
    }
    
    PXLog(@"Failed to generate WiFi information");
    return nil;
}

- (NSArray *)availableIdentifiers {
    // Return all available identifiers
    NSArray *identifiers = @[
        @"IDFA",
        @"IDFV",
        @"DeviceName",
        @"SerialNumber",
        @"IOSVersion",
        @"WiFi",
        @"StorageSystem",
        @"Battery",
        @"SystemBootUUID",
        @"DyldCacheUUID",
        @"PasteboardUUID",
        @"KeychainUUID",
        @"UserDefaultsUUID",
        @"AppGroupUUID",
        @"CoreDataUUID",
        @"AppInstallUUID",
        @"AppContainerUUID",
        @"SystemUptime",
        @"BootTime"
    ];
    
    return identifiers;
}

- (void)addApplicationWithExtensionsToScope:(NSString *)bundleID {
    if (!bundleID || [bundleID isEqualToString:@"com.hydra.projectx"]) {
        return;
    }
    
    // First add the main app
    [self addApplicationToScope:bundleID];
    
    // Create a more specific extension pattern
    // Instead of just using first component, use the main app's bundle ID as base
    NSString *extensionPattern = [NSString stringWithFormat:@"%@.*", bundleID];
    
    // Store the extension pattern in the app's info
    NSMutableDictionary *appInfo = [self.scopedApps[bundleID] mutableCopy];
    if (appInfo) {
        appInfo[@"extensionPattern"] = extensionPattern;
        self.scopedApps[bundleID] = appInfo;
        [self saveScopedApps];
        
        PXLog(@"[WeaponX] Added extension pattern: %@ for app: %@", extensionPattern, bundleID);
    }
}

- (BOOL)isBundleIDMatch:(NSString *)targetBundleID withPattern:(NSString *)patternBundleID {
    if (!targetBundleID || !patternBundleID) return NO;
    
    // Convert pattern to regex, escaping all dots except the wildcard
    NSString *regexPattern = [patternBundleID stringByReplacingOccurrencesOfString:@"." withString:@"\\."];
    regexPattern = [regexPattern stringByReplacingOccurrencesOfString:@"\\.*" withString:@".*"];
    regexPattern = [NSString stringWithFormat:@"^%@$", regexPattern];
    
    NSError *error = nil;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:regexPattern
                                                                         options:NSRegularExpressionCaseInsensitive
                                                                           error:&error];
    if (error) {
        PXLog(@"[WeaponX] Error creating regex for pattern %@: %@", patternBundleID, error);
        return NO;
    }
    
    NSRange range = NSMakeRange(0, targetBundleID.length);
    NSTextCheckingResult *match = [regex firstMatchInString:targetBundleID options:0 range:range];
    
    BOOL matches = (match != nil);
    if (matches) {
        PXLog(@"[WeaponX] Bundle ID: %@ matches pattern: %@", targetBundleID, patternBundleID);
    }
    
    return matches;
}

- (BOOL)shouldSpoofForBundle:(NSString *)bundleID {
    if (!bundleID) return NO;
    
    // Check cache first
    NSNumber *cachedDecision = self.spoofCache[bundleID];
    if (cachedDecision) {
        return [cachedDecision boolValue];
    }
    
    // Check if the app is directly in scope
    BOOL isInScope = self.scopedApps[bundleID] != nil;
    
    // If not directly in scope, check if it's an extension of a scoped app
    if (!isInScope) {
        isInScope = [self isExtensionEnabled:bundleID];
        
        // If it's an extension, log this for debugging
        if (isInScope) {
            PXLog(@"[WeaponX] Bundle ID %@ is enabled as an extension", bundleID);
        }
    } else {
        // If directly in scope, check if it's enabled
        isInScope = [self.scopedApps[bundleID][@"enabled"] boolValue];
        
        if (isInScope) {
            PXLog(@"[WeaponX] Bundle ID %@ is directly enabled in scope", bundleID);
        }
    }
    
    // Cache the decision with a timestamp
    self.spoofCache[bundleID] = @(isInScope);
    self.spoofCache[[bundleID stringByAppendingString:@"_timestamp"]] = [NSDate date];
    
    return isInScope;
}

- (void)saveScopedApps {
    // Get the proper preferences path
    NSString *prefsPath = @"/var/mobile/Library/Preferences";
    NSString *scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
    
    // Fallback to standard path if rootless path doesn't exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:prefsPath]) {
        // Try Dopamine 2 path first
        prefsPath = @"/private/var/mobile/Library/Preferences";
        scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
        
        // Fallback to standard path if needed
        if (![fileManager fileExistsAtPath:scopedAppsFile]) {
            prefsPath = @"/var/mobile/Library/Preferences";
            scopedAppsFile = [prefsPath stringByAppendingPathComponent:@"com.hydra.projectx.global_scope.plist"];
        }
    }
    
    // Save scoped apps separately in the global scope file
    NSDictionary *scopedAppsDict = @{@"ScopedApps": [self.scopedApps copy]};
    BOOL success = [scopedAppsDict writeToFile:scopedAppsFile atomically:YES];
    if (!success) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" 
                                      code:4006 
                                  userInfo:@{NSLocalizedDescriptionKey: @"Failed to save global scoped apps"}];
        return;
    }
    
    // Set proper permissions for global scope file
    NSError *permError = nil;
    NSDictionary *fileAttributes = @{NSFilePosixPermissions: @0644,
                                   NSFileOwnerAccountName: @"mobile"};
    
    if (![fileManager setAttributes:fileAttributes
                      ofItemAtPath:scopedAppsFile
                             error:&permError]) {
        NSLog(@"[ProjectX] Warning: Failed to set global scope file permissions: %@", permError);
    }
}

- (BOOL)isExtensionEnabled:(NSString *)bundleID {
    if (!bundleID) return NO;
    
    // Never consider the WeaponX app itself or system apps
    if ([bundleID isEqualToString:@"com.hydra.projectx"] || [bundleID hasPrefix:@"com.apple."]) {
        return NO;
    }
    
    // Check each scoped app's extension pattern
    for (NSString *scopedBundleID in self.scopedApps) {
        NSDictionary *appInfo = self.scopedApps[scopedBundleID];
        NSString *extensionPattern = appInfo[@"extensionPattern"];
        
        if (extensionPattern && [self isBundleIDMatch:bundleID withPattern:extensionPattern]) {
            PXLog(@"[WeaponX] Bundle ID %@ matches extension pattern %@ from app %@", bundleID, extensionPattern, scopedBundleID);
            return [appInfo[@"enabled"] boolValue];
        }
    }
    
    return NO;
}

#pragma mark - Custom Values

- (BOOL)saveCustomValue:(NSString *)value forType:(NSString *)type {
    // Save to profile-specific path
    NSString *identityDir = [self profileIdentityPath];
    if (!identityDir) {
        PXLog(@"[WeaponX] ❌ Failed to get profile identity path");
        return NO;
    }
    
    // Create the dictionary with timestamp
    NSDictionary *valueDict = @{@"value": value, @"lastUpdated": [NSDate date]};
    
    // Determine the file path based on type
    NSString *filePath = nil;
    if ([type isEqualToString:@"IDFA"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"advertising_id.plist"];
    } else if ([type isEqualToString:@"IDFV"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"vendor_id.plist"];
    } else if ([type isEqualToString:@"DeviceName"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"device_name.plist"];
    } else if ([type isEqualToString:@"SerialNumber"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"serial_number.plist"];
    } else if ([type isEqualToString:@"IMEI"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"imei.plist"];
    } else if ([type isEqualToString:@"MEID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"meid.plist"];
    } else if ([type isEqualToString:@"SystemBootUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"system_boot_uuid.plist"];
    } else if ([type isEqualToString:@"DyldCacheUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"dyld_cache_uuid.plist"];
    } else if ([type isEqualToString:@"PasteboardUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"pasteboard_uuid.plist"];
    } else if ([type isEqualToString:@"KeychainUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"keychain_uuid.plist"];
    } else if ([type isEqualToString:@"UserDefaultsUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"userdefaults_uuid.plist"];
    } else if ([type isEqualToString:@"AppGroupUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"appgroup_uuid.plist"];
    } else if ([type isEqualToString:@"CoreDataUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"coredata_uuid.plist"];
    } else if ([type isEqualToString:@"AppInstallUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"appinstall_uuid.plist"];
    } else if ([type isEqualToString:@"AppContainerUUID"]) {
        filePath = [identityDir stringByAppendingPathComponent:@"appcontainer_uuid.plist"];
    } else {
        PXLog(@"[WeaponX] ❌ Unknown identifier type: %@", type);
        return NO;
    }
    
    // Write the value to file
    BOOL success = [valueDict writeToFile:filePath atomically:YES];
    
    // Also update the combined device_ids.plist
    if (success) {
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: 
                                         [NSMutableDictionary dictionary];
        deviceIds[type] = value;
        success = [deviceIds writeToFile:deviceIdsPath atomically:YES];
        
        PXLog(@"[WeaponX] ✅ Custom %@ saved: %@", type, value);
        
        // For specific types, also update the respective manager
        if ([type isEqualToString:@"IDFA"]) {
            [[IDFAManager sharedManager] setCurrentIDFA:value];
        } else if ([type isEqualToString:@"IDFV"]) {
            [[IDFVManager sharedManager] setCurrentIDFV:value];
        } else if ([type isEqualToString:@"SystemBootUUID"]) {
            [[SystemUUIDManager sharedManager] setCurrentBootUUID:value];
        } else if ([type isEqualToString:@"DyldCacheUUID"]) {
            [[DyldCacheUUIDManager sharedManager] setCurrentDyldCacheUUID:value];
        } else if ([type isEqualToString:@"PasteboardUUID"]) {
            [[PasteboardUUIDManager sharedManager] setCurrentPasteboardUUID:value];
        } else if ([type isEqualToString:@"KeychainUUID"]) {
            [[KeychainUUIDManager sharedManager] setCurrentKeychainUUID:value];
        } else if ([type isEqualToString:@"UserDefaultsUUID"]) {
            [[UserDefaultsUUIDManager sharedManager] setCurrentUserDefaultsUUID:value];
        } else if ([type isEqualToString:@"AppGroupUUID"]) {
            [[AppGroupUUIDManager sharedManager] setCurrentAppGroupUUID:value];
        } else if ([type isEqualToString:@"CoreDataUUID"]) {
            [[CoreDataUUIDManager sharedManager] setCurrentCoreDataUUID:value];
        } else if ([type isEqualToString:@"AppInstallUUID"]) {
            [[AppInstallUUIDManager sharedManager] setCurrentAppInstallUUID:value];
        } else if ([type isEqualToString:@"AppContainerUUID"]) {
            [[AppContainerUUIDManager sharedManager] setCurrentAppContainerUUID:value];
        }
    }
    
    return success;
}

- (BOOL)setCustomIDFA:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"IDFA"];
}

#pragma mark - IMEI/MEID Spoofing

- (BOOL)setCustomIMEI:(NSString *)value {
    // Validate IMEI: must be 15 digits, Luhn valid, and start with a US TAC (e.g., 353918, 356938, 359254, etc.)
    if (![self isValidIMEI:value]) return NO;
    return [self saveCustomValue:value forType:@"IMEI"];
}

- (BOOL)setCustomMEID:(NSString *)value {
    // Validate MEID: must be 14 hex digits, and start with a US prefix (e.g., A00000, A10000, 990000, etc.)
    if (![self isValidMEID:value]) return NO;
    return [self saveCustomValue:value forType:@"MEID"];
}

- (NSString *)generateIMEI {
    // Use a realistic US iPhone TAC (Type Allocation Code)
    NSArray *usTACs = @[ @"353918", @"356938", @"359254", @"353915", @"353920", @"353929", @"353997", @"354994" ];
    NSString *tac = usTACs[arc4random_uniform((uint32_t)usTACs.count)];
    NSMutableString *imei = [NSMutableString stringWithString:tac];
    // 8 digits for SNR
    for (int i = 0; i < 8; i++) {
        [imei appendFormat:@"%d", arc4random_uniform(10)];
    }
    // Luhn check digit
    int sum = 0;
    for (int i = 0; i < 14; i++) {
        int digit = [imei characterAtIndex:i] - '0';
        if (i % 2 == 1) digit *= 2;
        if (digit > 9) digit -= 9;
        sum += digit;
    }
    int checkDigit = (10 - (sum % 10)) % 10;
    [imei appendFormat:@"%d", checkDigit];
    return imei;
}

- (NSString *)generateMEID {
    // Use a realistic US MEID prefix (A00000, A10000, 990000)
    NSArray *usMEIDPrefixes = @[ @"A00000", @"A10000", @"990000" ];
    NSString *prefix = usMEIDPrefixes[arc4random_uniform((uint32_t)usMEIDPrefixes.count)];
    NSMutableString *meid = [NSMutableString stringWithString:prefix];
    // 8 hex digits for the rest
    for (int i = 0; i < 8; i++) {
        [meid appendFormat:@"%X", arc4random_uniform(16)];
    }
    return meid;
}

// IMEI validation: 15 digits, Luhn valid, US TAC
- (BOOL)isValidIMEI:(NSString *)imei {
    if (imei.length != 15) return NO;
    if (![self isAllDigits:imei]) return NO;
    // Check TAC
    NSArray *usTACs = @[ @"353918", @"356938", @"359254", @"353915", @"353920", @"353929", @"353997", @"354994" ];
    NSString *tac = [imei substringToIndex:6];
    if (![usTACs containsObject:tac]) return NO;
    // Luhn check
    int sum = 0;
    for (int i = 0; i < 14; i++) {
        int digit = [imei characterAtIndex:i] - '0';
        if (i % 2 == 1) digit *= 2;
        if (digit > 9) digit -= 9;
        sum += digit;
    }
    int checkDigit = (10 - (sum % 10)) % 10;
    return (checkDigit == ([imei characterAtIndex:14] - '0'));
}

// MEID validation: 14 hex digits, US prefix
- (BOOL)isValidMEID:(NSString *)meid {
    if (meid.length != 14) return NO;
    NSArray *usMEIDPrefixes = @[ @"A00000", @"A10000", @"990000" ];
    NSString *prefix = [meid substringToIndex:6];
    if (![usMEIDPrefixes containsObject:prefix]) return NO;
    NSCharacterSet *hexSet = [NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEFabcdef"];
    for (NSUInteger i = 0; i < meid.length; i++) {
        unichar c = [meid characterAtIndex:i];
        if (![hexSet characterIsMember:c]) return NO;
    }
    return YES;
}

- (BOOL)isAllDigits:(NSString *)string {
    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    return ([string rangeOfCharacterFromSet:nonDigits].location == NSNotFound);
}

- (BOOL)setCustomIDFV:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"IDFV"];
}

- (BOOL)setCustomDeviceName:(NSString *)value {
    // No special validation for device name
    return [self saveCustomValue:value forType:@"DeviceName"];
}

- (BOOL)setCustomSerialNumber:(NSString *)value {
    // Serial numbers have specific format requirements
    // This is a simplified validation - implement appropriate validation for serial numbers
    if (!value || value.length < 8) return NO;
    return [self saveCustomValue:value forType:@"SerialNumber"];
}

- (BOOL)setCustomSystemBootUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"SystemBootUUID"];
}

- (BOOL)setCustomDyldCacheUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"DyldCacheUUID"];
}

- (BOOL)setCustomPasteboardUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"PasteboardUUID"];
}

- (BOOL)setCustomKeychainUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"KeychainUUID"];
}

- (BOOL)setCustomUserDefaultsUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"UserDefaultsUUID"];
}

- (BOOL)setCustomAppGroupUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"AppGroupUUID"];
}

- (BOOL)setCustomCoreDataUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"CoreDataUUID"];
}

- (BOOL)setCustomAppInstallUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"AppInstallUUID"];
}

- (BOOL)setCustomAppContainerUUID:(NSString *)value {
    // Validate UUID format
    if (![self validateUUID:value]) return NO;
    return [self saveCustomValue:value forType:@"AppContainerUUID"];
}

- (BOOL)validateUUID:(NSString *)uuid {
    if (!uuid) return NO;
    
    // Verify format: 8-4-4-4-12 hexadecimal characters
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" 
                                                                           options:NSRegularExpressionCaseInsensitive 
                                                                             error:nil];
    
    NSUInteger matches = [regex numberOfMatchesInString:uuid 
                                                options:0 
                                                  range:NSMakeRange(0, uuid.length)];
    
    return matches == 1;
}

#pragma mark - Device Model Specifications

- (NSDictionary *)getDeviceModelSpecifications {
    NSString *identityDir = [self profileIdentityPath];
    if (!identityDir) return nil;

    // Read from the combined device_ids.plist only (source of truth)
    NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
    NSDictionary *deviceIds = [NSDictionary dictionaryWithContentsOfFile:deviceIdsPath];
    
    if (deviceIds && deviceIds[@"DeviceModel"]) {
        NSMutableDictionary *specs = [NSMutableDictionary dictionary];
        
        specs[@"value"] = deviceIds[@"DeviceModel"];
        specs[@"name"] = deviceIds[@"DeviceModelName"] ?: @"Unknown";
        specs[@"screenResolution"] = deviceIds[@"ScreenResolution"] ?: @"Unknown";
        specs[@"viewportResolution"] = deviceIds[@"ViewportResolution"] ?: @"Unknown";
        specs[@"devicePixelRatio"] = deviceIds[@"DevicePixelRatio"] ?: @(0);
        specs[@"screenDensity"] = deviceIds[@"ScreenDensityPPI"] ?: @(0);
        specs[@"cpuArchitecture"] = deviceIds[@"CPUArchitecture"] ?: @"Unknown";
        specs[@"deviceMemory"] = deviceIds[@"DeviceMemory"] ?: @(0);
        specs[@"gpuFamily"] = deviceIds[@"GPUFamily"] ?: @"Unknown";
        specs[@"cpuCoreCount"] = deviceIds[@"CPUCoreCount"] ?: @(0);
        specs[@"metalFeatureSet"] = deviceIds[@"MetalFeatureSet"] ?: @"Unknown";
        
        // Rebuild webGLInfo from simplified fields
        NSMutableDictionary *webGLInfo = [NSMutableDictionary dictionary];
        webGLInfo[@"webglVendor"] = deviceIds[@"WebGLVendor"] ?: @"Apple";
        webGLInfo[@"webglRenderer"] = deviceIds[@"WebGLRenderer"] ?: @"Apple GPU";
        webGLInfo[@"unmaskedVendor"] = @"Apple Inc.";
        webGLInfo[@"unmaskedRenderer"] = deviceIds[@"GPUFamily"] ?: @"Apple GPU";
        webGLInfo[@"webglVersion"] = @"WebGL 2.0";
        webGLInfo[@"maxTextureSize"] = @(16384);
        webGLInfo[@"maxRenderBufferSize"] = @(16384);
        
        specs[@"webGLInfo"] = webGLInfo;

        if (deviceIds[@"ModelNumber"]) {
            specs[@"modelNumber"] = deviceIds[@"ModelNumber"];
        }
        
        return specs;
    }
    
    // If still not found, get the current device model and fetch its specs
    NSString *currentDeviceModel = [self currentValueForIdentifier:@"DeviceModel"];
    if (currentDeviceModel) {
        DeviceModelManager *deviceManager = [DeviceModelManager sharedManager];
        NSMutableDictionary *specs = [NSMutableDictionary dictionary];
        
        specs[@"value"] = currentDeviceModel;
        specs[@"name"] = [deviceManager deviceModelNameForString:currentDeviceModel] ?: @"Unknown";
        specs[@"screenResolution"] = [deviceManager screenResolutionForModel:currentDeviceModel] ?: @"Unknown";
        specs[@"viewportResolution"] = [deviceManager viewportResolutionForModel:currentDeviceModel] ?: @"Unknown";
        specs[@"devicePixelRatio"] = @([deviceManager devicePixelRatioForModel:currentDeviceModel]);
        specs[@"screenDensity"] = @([deviceManager screenDensityForModel:currentDeviceModel]);
        specs[@"cpuArchitecture"] = [deviceManager cpuArchitectureForModel:currentDeviceModel] ?: @"Unknown";
        specs[@"deviceMemory"] = @([deviceManager deviceMemoryForModel:currentDeviceModel]);
        specs[@"gpuFamily"] = [deviceManager gpuFamilyForModel:currentDeviceModel] ?: @"Unknown";
        specs[@"cpuCoreCount"] = @([deviceManager cpuCoreCountForModel:currentDeviceModel]);
        specs[@"metalFeatureSet"] = [deviceManager metalFeatureSetForModel:currentDeviceModel] ?: @"Unknown";
        specs[@"webGLInfo"] = [deviceManager webGLInfoForModel:currentDeviceModel] ?: @{};
        
        return specs;
    }
    
    
    return nil;
}

- (NSString *)getScreenResolution {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? specs[@"screenResolution"] : @"Unknown";
}

- (NSString *)getViewportResolution {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? specs[@"viewportResolution"] : @"Unknown";
}

- (CGFloat)getDevicePixelRatio {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? [specs[@"devicePixelRatio"] floatValue] : 0.0;
}

- (NSInteger)getScreenDensity {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? [specs[@"screenDensity"] integerValue] : 0;
}

- (NSString *)getCPUArchitecture {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? specs[@"cpuArchitecture"] : @"Unknown";
}

- (NSInteger)getDeviceMemory {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? [specs[@"deviceMemory"] integerValue] : 0;
}

- (NSString *)getGPUFamily {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? specs[@"gpuFamily"] : @"Unknown";
}

- (NSDictionary *)getWebGLInfo {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? specs[@"webGLInfo"] : @{};
}

- (NSInteger)getCPUCoreCount {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? [specs[@"cpuCoreCount"] integerValue] : 0;
}

- (NSString *)getMetalFeatureSet {
    NSDictionary *specs = [self getDeviceModelSpecifications];
    return specs ? specs[@"metalFeatureSet"] : @"Unknown";
}

// Device Theme Methods
- (NSString *)generateDeviceTheme {
    // Generate a random theme (Light or Dark)
    NSArray *themes = @[@"Light", @"Dark"];
    NSInteger randomIndex = arc4random_uniform(2);
    NSString *theme = themes[randomIndex];
    
    // Save the theme to the profile
    [self setCustomDeviceTheme:theme];
    
    return theme;
}

- (NSString *)toggleDeviceTheme {
    // Get current theme
    NSString *currentTheme = [self currentValueForIdentifier:@"DeviceTheme"];
    
    // Toggle between Light and Dark
    NSString *newTheme;
    if ([currentTheme isEqualToString:@"Light"]) {
        newTheme = @"Dark";
    } else {
        newTheme = @"Light";
    }
    
    // Save the new theme
    [self setCustomDeviceTheme:newTheme];
    
    return newTheme;
}

- (BOOL)setCustomDeviceTheme:(NSString *)value {
    // Validate theme value
    if (![value isEqualToString:@"Light"] && ![value isEqualToString:@"Dark"]) {
        self.error = [NSError errorWithDomain:@"com.hydra.projectx" code:2004 userInfo:@{NSLocalizedDescriptionKey: @"Invalid Device Theme (must be 'Light' or 'Dark')"}];
        return NO;
    }
    
    NSString *identityDir = [self profileIdentityPath];
    BOOL success = NO;
    
    if (identityDir) {
        // Create dictionary with theme value
        NSDictionary *themeDict = @{
            @"value": value,
            @"lastUpdated": [NSDate date]
        };
        
        // Save to device_theme.plist
        NSString *themePath = [identityDir stringByAppendingPathComponent:@"device_theme.plist"];
        success = [themeDict writeToFile:themePath atomically:YES];
        
        // Also update the combined device_ids.plist
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSMutableDictionary *deviceIds = [NSMutableDictionary dictionaryWithContentsOfFile:deviceIdsPath] ?: [NSMutableDictionary dictionary];
        
        // Add theme to device_ids.plist
        deviceIds[@"DeviceTheme"] = value;
        
        success = [deviceIds writeToFile:deviceIdsPath atomically:YES];
    }
    
    return success;
}

#pragma mark - Canvas Fingerprinting Protection

- (BOOL)toggleCanvasFingerprintProtection {
    BOOL currentValue = [self isCanvasFingerprintProtectionEnabled];
    BOOL newValue = !currentValue;
    
    // Update settings
    [self setCanvasFingerprintProtection:newValue];
    
    // Notify change
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.hydra.projectx.toggleCanvasFingerprint"),
        NULL, NULL, TRUE
    );
    
    PXLog(@"[WeaponX] 🎨 Canvas Fingerprint Protection %@", newValue ? @"ENABLED" : @"DISABLED");
    
    return newValue;
}

- (BOOL)isCanvasFingerprintProtectionEnabled {
    // Read directly from the plist file - SINGLE SOURCE OF TRUTH
    NSString *securitySettingsPath = @"/var/mobile/Library/Preferences/com.weaponx.securitySettings.plist";
    NSDictionary *settingsDict = [NSDictionary dictionaryWithContentsOfFile:securitySettingsPath];
    
    if (settingsDict) {
        if (settingsDict[@"canvasFingerprintingEnabled"] != nil) {
            return [settingsDict[@"canvasFingerprintingEnabled"] boolValue];
        }
        if (settingsDict[@"CanvasFingerprint"] != nil) {
            return [settingsDict[@"CanvasFingerprint"] boolValue];
        }
    }
    
    return NO; // Default to disabled if settings file doesn't exist
}

- (BOOL)setCanvasFingerprintProtection:(BOOL)enabled {
    // Read and update the plist file directly - SINGLE SOURCE OF TRUTH
    NSString *securitySettingsPath = @"/var/mobile/Library/Preferences/com.weaponx.securitySettings.plist";
    NSMutableDictionary *settingsDict = [NSMutableDictionary dictionaryWithContentsOfFile:securitySettingsPath] ?: [NSMutableDictionary dictionary];
    
    // Update with both key names for compatibility
    settingsDict[@"canvasFingerprintingEnabled"] = @(enabled);
    settingsDict[@"CanvasFingerprint"] = @(enabled);
    
    // Write back to the file
    BOOL success = [settingsDict writeToFile:securitySettingsPath atomically:YES];
    
    // Also update our in-memory settings to keep them in sync
    if (success) {
        NSMutableDictionary *updatedSettings = [self.settings mutableCopy];
        updatedSettings[@"canvasFingerprintingEnabled"] = @(enabled);
        updatedSettings[@"CanvasFingerprint"] = @(enabled);
        self.settings = updatedSettings;
    }
    
    // Notify about the change
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.hydra.projectx.settings.changed"),
        NULL, NULL, TRUE
    );
    
    return YES;
}

- (void)resetCanvasNoise {
    // Post notification to reset canvas noise seeds
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR("com.hydra.projectx.resetCanvasNoise"),
        NULL, NULL, TRUE
    );
    
    PXLog(@"[WeaponX] 🎨 Canvas Fingerprint Noise patterns reset");
}

@end
