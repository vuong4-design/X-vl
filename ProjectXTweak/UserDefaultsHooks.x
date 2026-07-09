#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "ProjectXLogging.h"
#import "IdentifierManager.h"
#import "UserDefaultsUUIDManager.h"
// #import <ellekit/ellekit.h> // Removed for rootful - using Substrate

#import "PXScope.h"

// Function declarations
static NSString *getSpoofedUserDefaultsUUID();
static BOOL isUUIDKey(NSString *key);
static id processDictionaryValues(id object);

// Global variables to track state
static NSMutableDictionary *cachedBundleDecisions = nil;
static NSTimeInterval kCacheValidityDuration = 300.0; // 5 minutes 

// Recursion guard to prevent infinite loops when getSpoofedUserDefaultsUUID accesses NSUserDefaults
static __thread BOOL isInsideHook = NO; 

// Callback function for notifications that clear the cache
static void clearCacheCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    // Clear cached decisions
    if (cachedBundleDecisions) {
        [cachedBundleDecisions removeAllObjects];
    }
}

// Helper function to check if we should spoof for this bundle ID (with caching)
static BOOL shouldSpoofForBundle(NSString *bundleID) {
    if (!bundleID) return NO;

    // Allow unscoped spoofing for Safari/Auth stack when enabled.
    if (PXAllowUnscopedSafariStack()) {
        return YES;
    }
    
    // Skip for system apps and the tweak itself
    NSString *proc = [NSProcessInfo processInfo].processName;
    if (([bundleID hasPrefix:@"com.apple."] && !(PXSafariStackSpoofEnabled() && PXIsSafariStackProcess(bundleID, proc))) ||
        [bundleID isEqualToString:@"com.hydra.projectx"]) {
        return NO;
    }
    
    // Check cache first
    if (!cachedBundleDecisions) {
        cachedBundleDecisions = [NSMutableDictionary dictionary];
    } else {
        NSNumber *cachedDecision = cachedBundleDecisions[bundleID];
        NSDate *decisionTimestamp = cachedBundleDecisions[[bundleID stringByAppendingString:@"_timestamp"]];
        
        if (cachedDecision && decisionTimestamp && 
            [[NSDate date] timeIntervalSinceDate:decisionTimestamp] < kCacheValidityDuration) {
            return [cachedDecision boolValue];
        }
    }
    
    // Get IdentifierManager to check if we should spoof
    if (!NSClassFromString(@"IdentifierManager")) {
        cachedBundleDecisions[bundleID] = @NO;
        cachedBundleDecisions[[bundleID stringByAppendingString:@"_timestamp"]] = [NSDate date];
        return NO;
    }
    
    IdentifierManager *manager = [NSClassFromString(@"IdentifierManager") sharedManager];
    
    // Check if this app is enabled for spoofing and UserDefaults UUID features are enabled
    BOOL shouldSpoof = [manager isApplicationEnabled:bundleID] && 
                       [manager isIdentifierEnabled:@"UserDefaultsUUID"];
    
    // Cache the decision
    cachedBundleDecisions[bundleID] = @(shouldSpoof);
    cachedBundleDecisions[[bundleID stringByAppendingString:@"_timestamp"]] = [NSDate date];
    
    return shouldSpoof;
}

// Add function to get spoofed UserDefaults UUID from manager
static NSString *getSpoofedUserDefaultsUUID() {
    // Use the UserDefaultsUUIDManager for consistent values across the app and hooks
    UserDefaultsUUIDManager *manager = [UserDefaultsUUIDManager sharedManager];
    NSString *uuid = [manager currentUserDefaultsUUID];
    
    if (uuid && uuid.length > 0) {
        return uuid;
    }
    
    // If UserDefaultsUUIDManager failed, read directly from active profile
    NSString *activeProfileId = nil;
    
    // Get active profile ID from central profile info
    NSString *centralInfoPath = @"/var/mobile/Library/WeaponX/Profiles/current_profile_info.plist";
    NSDictionary *centralInfo = [NSDictionary dictionaryWithContentsOfFile:centralInfoPath];
    if (centralInfo && centralInfo[@"ProfileId"]) {
        activeProfileId = centralInfo[@"ProfileId"];
    } else {
        // Try fallback location for profile ID
        NSString *fallbackPath = @"/var/mobile/Library/WeaponX/active_profile_info.plist";
        NSDictionary *fallbackInfo = [NSDictionary dictionaryWithContentsOfFile:fallbackPath];
        if (fallbackInfo && fallbackInfo[@"ProfileId"]) {
            activeProfileId = fallbackInfo[@"ProfileId"];
        }
    }
    
    if (activeProfileId) {
        // Build path to the profile's identity directory
        NSString *profileDir = [NSString stringWithFormat:@"/var/mobile/Library/WeaponX/Profiles/%@", activeProfileId];
        NSString *identityDir = [profileDir stringByAppendingPathComponent:@"identity"];
        
        // Read from device_ids.plist first (combined identifiers file)
        NSString *deviceIdsPath = [identityDir stringByAppendingPathComponent:@"device_ids.plist"];
        NSDictionary *deviceIds = [NSDictionary dictionaryWithContentsOfFile:deviceIdsPath];
        if (deviceIds && deviceIds[@"UserDefaultsUUID"]) {
            PXLog(@"[WeaponX] 🔍 Found UserDefaults UUID in device_ids.plist: %@", deviceIds[@"UserDefaultsUUID"]);
            return deviceIds[@"UserDefaultsUUID"];
        }
        
        // Try specific userdefaults_uuid.plist as fallback
        NSString *userDefaultsUUIDPath = [identityDir stringByAppendingPathComponent:@"userdefaults_uuid.plist"];
        NSDictionary *userDefaultsInfo = [NSDictionary dictionaryWithContentsOfFile:userDefaultsUUIDPath];
        if (userDefaultsInfo && userDefaultsInfo[@"value"]) {
            PXLog(@"[WeaponX] 🔍 Found UserDefaults UUID in userdefaults_uuid.plist: %@", userDefaultsInfo[@"value"]);
            return userDefaultsInfo[@"value"];
        }
        
        PXLog(@"[WeaponX] ⚠️ Could not find UserDefaults UUID in profile %@", activeProfileId);
    } else {
        PXLog(@"[WeaponX] ⚠️ Could not determine active profile ID");
    }
    
    // If all else fails, use a persistent fallback UUID
    NSString *fallbackUUIDPath = @"/var/mobile/Library/WeaponX/fallback_userdefaults_uuid.plist";
    NSMutableDictionary *fallbackDict = [NSMutableDictionary dictionaryWithContentsOfFile:fallbackUUIDPath];
    
    if (!fallbackDict) {
        fallbackDict = [NSMutableDictionary dictionary];
    }
    
    NSString *fallbackUUID = fallbackDict[@"UserDefaultsUUID"];
    if (!fallbackUUID) {
        // Generate new UUID only if we don't have one saved
        fallbackUUID = [[NSUUID UUID] UUIDString];
        fallbackDict[@"UserDefaultsUUID"] = fallbackUUID;
        [fallbackDict writeToFile:fallbackUUIDPath atomically:YES];
        PXLog(@"[WeaponX] 🔍 Generated and saved persistent fallback UUID: %@", fallbackUUID);
    } else {
        PXLog(@"[WeaponX] 🔍 Using existing fallback UUID: %@", fallbackUUID);
    }
    
    return fallbackUUID;
}

// Function to recursively process dictionary values and replace UUIDs
static id processDictionaryValues(id object) {
    // Base case: not a dictionary or array
    if (!object || (![object isKindOfClass:[NSDictionary class]] && ![object isKindOfClass:[NSArray class]])) {
        return object;
    }
    
    // For dictionaries, check each key and recursively process values
    if ([object isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)object;
        NSMutableDictionary *result = [NSMutableDictionary dictionaryWithCapacity:dict.count];
        
        NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
        
        for (id key in dict) {
            // Check if this key is UUID-related
            if ([key isKindOfClass:[NSString class]] && isUUIDKey(key)) {
                id value = dict[key];
                // If value is a string and looks like a UUID, replace it
                if ([value isKindOfClass:[NSString class]]) {
                    NSString *strValue = (NSString *)value;
                    // If the value matches a UUID pattern or is more than 8 chars and contains only hex
                    if ([strValue rangeOfString:@"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" 
                                         options:NSRegularExpressionSearch].location != NSNotFound ||
                        (strValue.length > 8 && [strValue rangeOfString:@"^[0-9a-f]+$" 
                                                               options:NSRegularExpressionSearch].location != NSNotFound)) {
                        result[key] = spoofedUUID;
                        continue;
                    }
                }
            }
            
            // Recursively process the value
            result[key] = processDictionaryValues(dict[key]);
        }
        
        return result;
    }
    
    // For arrays, recursively process each element
    if ([object isKindOfClass:[NSArray class]]) {
        NSArray *array = (NSArray *)object;
        NSMutableArray *result = [NSMutableArray arrayWithCapacity:array.count];
        
        for (id item in array) {
            [result addObject:processDictionaryValues(item)];
        }
        
        return result;
    }
    
    // Shouldn't reach here, but just in case
    return object;
}

// Helper to check if a string looks like a UUID (8-4-4-4-12 format)
static BOOL looksLikeUUIDString(NSString *str) {
    if (!str || str.length < 32) return NO;
    // Standard UUID format with dashes
    if (str.length == 36) {
        return [str rangeOfString:@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$" 
                          options:NSRegularExpressionSearch].location != NSNotFound;
    }
    // UUID without dashes (32 hex chars)
    if (str.length == 32) {
        return [str rangeOfString:@"^[0-9a-fA-F]{32}$" 
                          options:NSRegularExpressionSearch].location != NSNotFound;
    }
    return NO;
}

// Stricter isUUIDKey - only match keys that are definitely UUID-related
// Removed generic terms like 'token', 'tracking', 'device', 'identifier' that can match non-UUID values
static BOOL isUUIDKey(NSString *key) {
    if (!key) return NO;
    
    NSString *lowercaseKey = [key lowercaseString];
    
    // Strict UUID-related key patterns only
    NSArray *uuidPatterns = @[
        @"uuid", @"udid", 
        @"deviceuuid", @"device_uuid", @"device-uuid",
        @"uniqueid", @"unique-id", @"unique_id",
        @"vendorid", @"vendor-id", @"vendor_id", 
        @"idfa", @"idfv", @"adid", @"advertisingid", @"advertising_id",
        @"installationid", @"installation_id"
    ];
    
    // Check for exact matches only
    for (NSString *pattern in uuidPatterns) {
        if ([lowercaseKey isEqualToString:pattern]) {
            return YES;
        }
    }
    
    // Check for common suffixes with separators
    NSArray *strictSuffixes = @[@"uuid", @"udid", @"idfv", @"idfa"];
    for (NSString *suffix in strictSuffixes) {
        if ([lowercaseKey hasSuffix:[@"." stringByAppendingString:suffix]] ||
            [lowercaseKey hasSuffix:[@"-" stringByAppendingString:suffix]] ||
            [lowercaseKey hasSuffix:[@"_" stringByAppendingString:suffix]]) {
            return YES;
        }
    }
    
    return NO;
}

#pragma mark - NSUserDefaults Hooks

%hook NSUserDefaults

// Base method for getting objects - SAFE VERSION
// Always get original value first, only spoof if value is actually UUID-like
- (id)objectForKey:(NSString *)defaultName {
    // Recursion guard
    if (isInsideHook) {
        return %orig;
    }
    
    // Always get original value first
    id originalValue = %orig;
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if (!shouldSpoofForBundle(bundleID)) {
            return originalValue;
        }
        
        // Only consider spoofing if key looks like UUID key
        BOOL keyIsUUID = isUUIDKey(defaultName);
        
        // Case 1: Value is NSString that looks like UUID
        if ([originalValue isKindOfClass:[NSString class]]) {
            NSString *strValue = (NSString *)originalValue;
            if (keyIsUUID && looksLikeUUIDString(strValue)) {
                isInsideHook = YES;
                NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
                isInsideHook = NO;
                PXLog(@"[WeaponX] 🔍 Spoofing UUID string for key '%@'", defaultName);
                return spoofedUUID;
            }
            return originalValue;
        }
        
        // Case 2: Value is NSUUID 
        if ([originalValue isKindOfClass:NSClassFromString(@"NSUUID")]) {
            isInsideHook = YES;
            NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
            isInsideHook = NO;
            // Return as NSUUID to match expected type
            NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:spoofedUUID];
            PXLog(@"[WeaponX] 🔍 Spoofing NSUUID for key '%@'", defaultName);
            return uuid ?: originalValue;
        }
        
        // Case 3: Value is NSData 16 bytes (UUID bytes) and key is UUID-related
        if ([originalValue isKindOfClass:[NSData class]] && keyIsUUID) {
            NSData *dataValue = (NSData *)originalValue;
            if (dataValue.length == 16) {
                isInsideHook = YES;
                NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
                isInsideHook = NO;
                NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:spoofedUUID];
                if (uuid) {
                    uuid_t uuidBytes;
                    [uuid getUUIDBytes:uuidBytes];
                    PXLog(@"[WeaponX] 🔍 Spoofing UUID bytes for key '%@'", defaultName);
                    return [NSData dataWithBytes:uuidBytes length:16];
                }
            }
            return originalValue;
        }
        
        // Case 4: Value is NSDictionary - process only if key is UUID-related
        if ([originalValue isKindOfClass:[NSDictionary class]] && keyIsUUID) {
            isInsideHook = YES;
            id result = processDictionaryValues(originalValue);
            isInsideHook = NO;
            return result;
        }
        
        // Case 5: Value is NSArray - process only if key is UUID-related
        if ([originalValue isKindOfClass:[NSArray class]] && keyIsUUID) {
            isInsideHook = YES;
            id result = processDictionaryValues(originalValue);
            isInsideHook = NO;
            return result;
        }
        
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in objectForKey hook: %@", exception);
    }
    
    // Default: return original value unchanged
    return originalValue;
}

// String-specific method - SAFE VERSION
// Only spoof if original value looks like UUID
- (NSString *)stringForKey:(NSString *)defaultName {
    if (isInsideHook) return %orig;
    
    // Always get original value first
    NSString *originalValue = %orig;
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        // Only spoof if key is UUID-related AND original value looks like UUID
        if (shouldSpoofForBundle(bundleID) && isUUIDKey(defaultName) && looksLikeUUIDString(originalValue)) {
            isInsideHook = YES;
            NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
            isInsideHook = NO;
            PXLog(@"[WeaponX] 🔍 Spoofing string UUID for key '%@'", defaultName);
            return spoofedUUID;
        }
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in stringForKey hook: %@", exception);
    }
    
    return originalValue;
}

// Dictionary method - only process if key looks UUID-related
- (NSDictionary<NSString *, id> *)dictionaryForKey:(NSString *)defaultName {
    if (isInsideHook) return %orig;
    
    NSDictionary *originalDict = %orig;
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        // Only process if key looks UUID-related and dictionary is not empty
        if (!shouldSpoofForBundle(bundleID) || !isUUIDKey(defaultName) || !originalDict || originalDict.count == 0) {
            return originalDict;
        }
        
        // Use our recursive processor to handle nested dictionaries
        isInsideHook = YES;
        NSDictionary *result = processDictionaryValues(originalDict);
        isInsideHook = NO;
        return result;
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in dictionaryForKey hook: %@", exception);
        return originalDict;
    }
}

// Add additional accessor methods

- (NSArray *)arrayForKey:(NSString *)defaultName {
    if (isInsideHook) return %orig;
    
    NSArray *originalArray = %orig;
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        // Only process if key looks UUID-related and array is not empty
        if (!shouldSpoofForBundle(bundleID) || !isUUIDKey(defaultName) || !originalArray || originalArray.count == 0) {
            return originalArray;
        }
        
        // Use our recursive processor to handle arrays containing dictionaries with UUIDs
        isInsideHook = YES;
        NSArray *result = processDictionaryValues(originalArray);
        isInsideHook = NO;
        return result;
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in arrayForKey hook: %@", exception);
        return originalArray;
    }
}

// Data method - SAFE VERSION
// Only spoof if key is UUID AND data is 16 bytes (UUID binary format)
- (NSData *)dataForKey:(NSString *)defaultName {
    if (isInsideHook) return %orig;
    
    // Always get original value first
    NSData *originalData = %orig;
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        // Only spoof if:
        // 1. Key is UUID-related
        // 2. Data is exactly 16 bytes (UUID binary format)
        if (shouldSpoofForBundle(bundleID) && isUUIDKey(defaultName) && originalData && originalData.length == 16) {
            isInsideHook = YES;
            NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
            isInsideHook = NO;
            
            // Use NSUUID to get proper UUID bytes
            NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:spoofedUUID];
            if (uuid) {
                uuid_t uuidBytes;
                [uuid getUUIDBytes:uuidBytes];
                PXLog(@"[WeaponX] 🔍 Spoofing UUID bytes for key '%@'", defaultName);
                return [NSData dataWithBytes:uuidBytes length:16];
            }
        }
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in dataForKey hook: %@", exception);
    }
    
    return originalData;
}

- (NSURL *)URLForKey:(NSString *)defaultName {
    // URL values are rarely UUIDs, so use original
    return %orig;
}

// KVC accessor - important for accessing dictionaries
- (id)valueForKey:(NSString *)key {
    if (isInsideHook) return %orig;
    
    @try {
        // Only override for specific UUID keys to avoid breaking KVC for other properties
        if (isUUIDKey(key)) {
            id result = [self objectForKey:key];
            if (result) {
                return result;
            }
        }
    } @catch (NSException *exception) {
        PXLog(@"[WeaponX] ⚠️ Exception in valueForKey hook: %@", exception);
    }
    
    return %orig;
}

// Subscript accessor - important for dictionary-style access
- (id)objectForKeyedSubscript:(NSString *)key {
    if (isInsideHook) return %orig;
    
    @try {
        // This is used when accessing NSUserDefaults with subscript notation: userDefaults[key]
        if (isUUIDKey(key)) {
            return [self objectForKey:key];
        }
    } @catch (NSException *exception) {
        PXLog(@"[WeaponX] ⚠️ Exception in objectForKeyedSubscript hook: %@", exception);
    }
    
    return %orig;
}

// SETTER METHODS

// Base setter method
- (void)setObject:(id)value forKey:(NSString *)defaultName {
    if (isInsideHook) { %orig; return; }
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        if (shouldSpoofForBundle(bundleID)) {
            // If setting a UUID value, replace with our spoofed UUID
            if (isUUIDKey(defaultName) && [value isKindOfClass:[NSString class]]) {
                isInsideHook = YES;
                NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
                isInsideHook = NO;
                PXLog(@"[WeaponX] 🔍 Intercepting and spoofing UUID being saved to UserDefaults for key '%@'", defaultName);
                return %orig(spoofedUUID, defaultName);
            }
            
            // If setting a dictionary or array, process it to replace UUIDs
            if ([value isKindOfClass:[NSDictionary class]] || [value isKindOfClass:[NSArray class]]) {
                isInsideHook = YES;
                id processedValue = processDictionaryValues(value);
                isInsideHook = NO;
                return %orig(processedValue, defaultName);
            }
        }
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in setObject:forKey: hook: %@", exception);
    }
    
    return %orig;
}

// String-specific setter
- (void)setString:(NSString *)value forKey:(NSString *)defaultName {
    if (isInsideHook) { %orig; return; }
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        if (shouldSpoofForBundle(bundleID) && isUUIDKey(defaultName)) {
            isInsideHook = YES;
            NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
            isInsideHook = NO;
            PXLog(@"[WeaponX] 🔍 Intercepting and spoofing UUID string being saved to UserDefaults for key '%@'", defaultName);
            return %orig(spoofedUUID, defaultName);
        }
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in setString:forKey: hook: %@", exception);
    }
    
    return %orig;
}

// Dictionary-specific setter
- (void)setDictionary:(NSDictionary<NSString *,id> *)value forKey:(NSString *)defaultName {
    if (isInsideHook) { %orig; return; }
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        if (shouldSpoofForBundle(bundleID) && value) {
            // Process the dictionary to replace any UUIDs
            isInsideHook = YES;
            NSDictionary *processedDict = processDictionaryValues(value);
            isInsideHook = NO;
            return %orig(processedDict, defaultName);
        }
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in setDictionary:forKey: hook: %@", exception);
    }
    
    return %orig;
}

// Data-specific setter - SAFE VERSION
// Only spoof if key is UUID AND data is 16 bytes (UUID binary format)
- (void)setData:(NSData *)value forKey:(NSString *)defaultName {
    if (isInsideHook) { %orig; return; }
    
    @try {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        
        // Only spoof if:
        // 1. Key is UUID-related
        // 2. Data is exactly 16 bytes (UUID binary format)
        if (shouldSpoofForBundle(bundleID) && isUUIDKey(defaultName) && value && value.length == 16) {
            isInsideHook = YES;
            NSString *spoofedUUID = getSpoofedUserDefaultsUUID();
            isInsideHook = NO;
            
            // Use NSUUID to get proper UUID bytes
            NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:spoofedUUID];
            if (uuid) {
                uuid_t uuidBytes;
                [uuid getUUIDBytes:uuidBytes];
                NSData *spoofedData = [NSData dataWithBytes:uuidBytes length:16];
                PXLog(@"[WeaponX] 🔍 Spoofing UUID bytes being saved for key '%@'", defaultName);
                return %orig(spoofedData, defaultName);
            }
        }
    } @catch (NSException *exception) {
        isInsideHook = NO;
        PXLog(@"[WeaponX] ⚠️ Exception in setData:forKey: hook: %@", exception);
    }
    
    return %orig;
}

%end

#pragma mark - Constructor

%ctor {
    @autoreleasepool {
        // Skip for system processes
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        NSString *proc = [NSProcessInfo processInfo].processName;
        if (!bundleID || ([bundleID hasPrefix:@"com.apple."] && !(PXSafariStackSpoofEnabled() && PXIsSafariStackProcess(bundleID, proc)))) {
            return;
        }
        
        // Initialize cache with retained object
        cachedBundleDecisions = [[NSMutableDictionary alloc] init];
        
        // Register for settings change notifications
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            clearCacheCallback,
            CFSTR("com.hydra.projectx.settings.changed"),
            NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately
        );
        
        // Register for profile change notifications
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            clearCacheCallback,
            CFSTR("com.hydra.projectx.profileChanged"),
            NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately
        );
        
        // Additional notification for profile switching
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            clearCacheCallback,
            CFSTR("com.hydra.projectx.profileSwitched"),
            NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately
        );
        
        PXLog(@"[WeaponX] 🔍 UserDefaults hooks initialized");
    }
} 
