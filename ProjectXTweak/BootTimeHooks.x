#import "ProjectX.h"
#import "UptimeManager.h"
#import "ProfileManager.h"
#import "ProjectXLogging.h"
#import "HookOwnership.h"
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <sys/time.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <mach/mach_host.h>
#import <substrate.h>
// #import <ellekit/ellekit.h> // Removed for rootful - using Substrate
#import <dlfcn.h>
#import <objc/runtime.h>

#import "PXScope.h"

// Define the boot time structure for sysctl calls
struct timeval_boot {
    time_t tv_sec;
    suseconds_t tv_usec;
};

// Original function pointers - ONLY for system calls
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

// Cache for spoofed values to improve performance
static NSDate *cachedBootTime = nil;
static NSTimeInterval cachedUptime = 0;
static NSString *cachedProfilePath = nil;
static NSDate *cacheTimestamp = nil;
static const NSTimeInterval kCacheValidityDuration = 30.0; // 30 seconds cache

// Path to scoped apps plist
static NSString *const kScopedAppsPath = @"/var/mobile/Library/Preferences/com.hydra.projectx.global_scope.plist";
static NSString *const kScopedAppsPathAlt1 = @"/private/var/mobile/Library/Preferences/com.hydra.projectx.global_scope.plist";
static NSString *const kScopedAppsPathAlt2 = @"/var/mobile/Library/Preferences/com.hydra.projectx.global_scope.plist";

// Scoped apps cache
static NSMutableDictionary *scopedAppsCache = nil;
static NSDate *scopedAppsCacheTimestamp = nil;
static const NSTimeInterval kScopedAppsCacheValidDuration = 30.0; // 30 seconds

// Global flag to track if hooks are installed
static BOOL hooksInstalled = NO;

// Recursion guard to prevent infinite loops when UptimeManager calls sysctl
static __thread BOOL isInsideHook = NO;

// Forward declarations
static BOOL shouldSpoofBootTimeForApp(void);
static NSString *getCurrentProfilePath(void);
static void updateCachedBootTimeValues(void);
static void logBootTimeAccess(const char *method, NSString *bundleID);
static NSString *getCurrentBundleID(void);
static NSDictionary *loadScopedApps(void);
static BOOL isInScopedAppsList(void);
static void installSystemCallHooks(void);
static BOOL isBootTimeOrUptimeEnabled(void);

#pragma mark - Helper Functions

// Get the current bundle ID
static NSString *getCurrentBundleID(void) {
    @try {
        NSBundle *mainBundle = [NSBundle mainBundle];
        if (!mainBundle) {
            return nil;
        }
        return [mainBundle bundleIdentifier];
    } @catch (NSException *e) {
        return nil;
    }
}

// Load scoped apps from the plist file
static NSDictionary *loadScopedApps(void) {
    @try {
        // Check if cache is valid
        if (scopedAppsCache && scopedAppsCacheTimestamp && 
            [[NSDate date] timeIntervalSinceDate:scopedAppsCacheTimestamp] < kScopedAppsCacheValidDuration) {
            return scopedAppsCache;
        }
        
        // Initialize cache if needed
        if (!scopedAppsCache) {
            scopedAppsCache = [NSMutableDictionary dictionary];
        } else {
            [scopedAppsCache removeAllObjects];
        }
        
        // Try each possible path for the scoped apps file
        NSArray *possiblePaths = @[kScopedAppsPath, kScopedAppsPathAlt1, kScopedAppsPathAlt2];
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSString *validPath = nil;
        
        for (NSString *path in possiblePaths) {
            if ([fileManager fileExistsAtPath:path]) {
                validPath = path;
                break;
            }
        }
        
        if (!validPath) {
            // Don't log this error too frequently to avoid spam
            static NSDate *lastErrorLog = nil;
            if (!lastErrorLog || [[NSDate date] timeIntervalSinceDate:lastErrorLog] > 300.0) { // 5 minutes
                PXLog(@"[BootTimeHooks] Could not find scoped apps file");
                lastErrorLog = [NSDate date];
            }
            scopedAppsCacheTimestamp = [NSDate date];
            return scopedAppsCache;
        }
        
        // Load the plist file safely
        NSDictionary *plistDict = [NSDictionary dictionaryWithContentsOfFile:validPath];
        if (!plistDict || ![plistDict isKindOfClass:[NSDictionary class]]) {
            scopedAppsCacheTimestamp = [NSDate date];
            return scopedAppsCache;
        }
        
        // Get the scoped apps dictionary
        NSDictionary *scopedApps = plistDict[@"ScopedApps"];
        if (!scopedApps || ![scopedApps isKindOfClass:[NSDictionary class]]) {
            scopedAppsCacheTimestamp = [NSDate date];
            return scopedAppsCache;
        }
        
        // Copy the scoped apps to our cache
        [scopedAppsCache addEntriesFromDictionary:scopedApps];
        scopedAppsCacheTimestamp = [NSDate date];
        
        return scopedAppsCache;
        
    } @catch (NSException *e) {
        scopedAppsCacheTimestamp = [NSDate date];
        return scopedAppsCache ?: [NSMutableDictionary dictionary];
    }
}

// Check if the current app is in the scoped apps list
static BOOL isInScopedAppsList(void) {
    @try {
        NSString *bundleID = getCurrentBundleID();
        if (!bundleID || [bundleID length] == 0) {
            return NO;
        }
        
        NSDictionary *scopedApps = loadScopedApps();
        if (!scopedApps || scopedApps.count == 0) {
            return NO;
        }
        
        // Check if this bundle ID is in the scoped apps dictionary
        id appEntry = scopedApps[bundleID];
        if (!appEntry || ![appEntry isKindOfClass:[NSDictionary class]]) {
            return NO;
        }
        
        // Check if the app is enabled
        BOOL isEnabled = [appEntry[@"enabled"] boolValue];
        return isEnabled;
        
    } @catch (NSException *e) {
        return NO;
    }
}

// Check if boot time spoofing should be applied for the current app
static BOOL shouldSpoofBootTimeForApp(void) {
    static NSMutableDictionary *bundleDecisionCache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        bundleDecisionCache = [NSMutableDictionary dictionary];
    });
    
    @try {
        NSString *bundleID = getCurrentBundleID();
        if (!bundleID) return NO;
        
        // Check cache first
        NSString *cacheKey = bundleID;
        NSString *timestampKey = [bundleID stringByAppendingString:@"_timestamp"];
        NSNumber *cachedDecision = bundleDecisionCache[cacheKey];
        NSDate *decisionTimestamp = bundleDecisionCache[timestampKey];
        
        if (cachedDecision && decisionTimestamp && 
            [[NSDate date] timeIntervalSinceDate:decisionTimestamp] < 300.0) { // 5 minute cache
            return [cachedDecision boolValue];
        }
        
        // Exclude system processes, except Safari/Auth stack when enabled.
        NSString *proc = [NSProcessInfo processInfo].processName;
        if (([bundleID hasPrefix:@"com.apple."] && !(PXSafariStackSpoofEnabled() && PXIsSafariStackProcess(bundleID, proc))) ||
            [bundleID isEqualToString:@"com.hydra.projectx"] ||
            [bundleID hasPrefix:@"com.saurik."] ||
            [bundleID hasPrefix:@"org.coolstar."] ||
            [bundleID hasPrefix:@"com.ex.substitute"]) {
            bundleDecisionCache[cacheKey] = @NO;
            bundleDecisionCache[timestampKey] = [NSDate date];
            return NO;
        }
        
        // Check if the current app is a scoped app (or is Safari/Auth stack and enabled)
        BOOL isScoped = isInScopedAppsList() || PXAllowUnscopedSafariStack();
        
        // Cache the decision
        bundleDecisionCache[cacheKey] = @(isScoped);
        bundleDecisionCache[timestampKey] = [NSDate date];
        
        return isScoped;
        
    } @catch (NSException *e) {
        return NO;
    }
}

// Get the current profile path for spoofed values
static NSString *getCurrentProfilePath(void) {
    @try {
        ProfileManager *profileManager = [ProfileManager sharedManager];
        if (!profileManager) return nil;
        
        Profile *currentProfile = [profileManager currentProfile];
        if (!currentProfile) return nil;
        
        // Use the hardcoded profiles directory path since profilesDirectory is private
        NSString *profilesDir = @"/var/mobile/Library/WeaponX/Profiles";
        return [profilesDir stringByAppendingPathComponent:currentProfile.profileId];
    } @catch (NSException *e) {
        return nil;
    }
}

// Update cached boot time values from profile data
static void updateCachedBootTimeValues(void) {
    @try {
        NSString *profilePath = getCurrentProfilePath();
        if (!profilePath) {
            // Don't log this too frequently
            static NSDate *lastLog = nil;
            if (!lastLog || [[NSDate date] timeIntervalSinceDate:lastLog] > 300.0) {
                PXLog(@"[BootTimeHooks] ⚠️ No profile path available");
                lastLog = [NSDate date];
            }
            return;
        }
        
        // Check if cache is still valid
        if (cachedBootTime && cacheTimestamp && cachedProfilePath && 
            [cachedProfilePath isEqualToString:profilePath] &&
            [[NSDate date] timeIntervalSinceDate:cacheTimestamp] < kCacheValidityDuration) {
            return; // Cache is still valid
        }
        
        UptimeManager *uptimeManager = [UptimeManager sharedManager];
        if (!uptimeManager) return;
        
        // Get spoofed boot time and uptime
        NSDate *bootTime = [uptimeManager currentBootTimeForProfile:profilePath];
        NSTimeInterval uptime = [uptimeManager currentUptimeForProfile:profilePath];
        
        if (!bootTime || uptime <= 0) {
            [uptimeManager generateConsistentUptimeAndBootTimeForProfile:profilePath];
            bootTime = [uptimeManager currentBootTimeForProfile:profilePath];
            uptime = [uptimeManager currentUptimeForProfile:profilePath];
        }
        
        // Validate the data before caching
        if (bootTime && uptime > 0) {
            cachedBootTime = bootTime;
            cachedUptime = uptime;
            cachedProfilePath = profilePath;
            cacheTimestamp = [NSDate date];
        }
        
    } @catch (NSException *e) {
        // Silent failure to avoid crashes
    }
}

// Log boot time access attempts for debugging
static void logBootTimeAccess(const char *method, NSString *bundleID) {
    @try {
        // Early exit if parameters are invalid
        if (!method || !bundleID || [bundleID length] == 0) return;
        
        static NSMutableSet *loggedMethods = nil;
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            loggedMethods = [[NSMutableSet alloc] init];
        });
        
        if (!loggedMethods) return;
        
        // Use safer string creation
        NSString *methodStr = [NSString stringWithUTF8String:method];
        if (!methodStr) return;
        
        NSString *methodKey = [NSString stringWithFormat:@"%@:%@", methodStr, bundleID];
        if (!methodKey) return;
        
        if (![loggedMethods containsObject:methodKey]) {
            [loggedMethods addObject:methodKey];
            PXLog(@"[BootTimeHooks] 🕵️ App %@ accessed boot time via %@", bundleID, methodStr);
        }
    } @catch (NSException *e) {
        // Silent failure
    }
}

// Helper to check if a spoof identifier is enabled for the current profile
static BOOL isBootTimeOrUptimeEnabled(void) {
    @try {
        // Dynamically get IdentifierManager class and sharedManager
        Class managerClass = NSClassFromString(@"IdentifierManager");
        if (!managerClass) return NO;
        id manager = [managerClass respondsToSelector:@selector(sharedManager)] ? [managerClass sharedManager] : nil;
        if (!manager) return NO;
        
        SEL isEnabledSel = NSSelectorFromString(@"isIdentifierEnabled:");
        if (![manager respondsToSelector:isEnabledSel]) return NO;
        
        BOOL bootTimeEnabled = NO;
        BOOL uptimeEnabled = NO;
        NSString *bootTimeStr = @"BootTime";
        NSString *uptimeStr = @"SystemUptime";
        NSMethodSignature *sig = [manager methodSignatureForSelector:isEnabledSel];
        if (sig) {
            NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:sig];
            [invocation setSelector:isEnabledSel];
            [invocation setTarget:manager];
            // BootTime
            [invocation setArgument:&bootTimeStr atIndex:2];
            [invocation invoke];
            [invocation getReturnValue:&bootTimeEnabled];
            // SystemUptime
            [invocation setArgument:&uptimeStr atIndex:2];
            [invocation invoke];
            [invocation getReturnValue:&uptimeEnabled];
        }
        return bootTimeEnabled || uptimeEnabled;
    } @catch (NSException *e) {
        return NO;
    }
}

#pragma mark - System Call Hooks

// Hook sysctl() for KERN_BOOTTIME queries - ONLY method that App Store apps commonly use
int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // CRITICAL: Recursion guard - if we're already inside hook, pass through to original
    if (isInsideHook) {
        if (orig_sysctl) {
            return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
        }
        return -1;
    }
    
    @try {
        // Also handle kernel build/version queries here to avoid leaks when multiple sysctl hooks exist.
        if (namelen >= 2 && name && name[0] == CTL_KERN && oldlenp) {
            BOOL isOSVersion = (name[1] == KERN_OSVERSION);
            BOOL isOSRelease = (name[1] == KERN_OSRELEASE);
            BOOL isKernelVer = (name[1] == KERN_VERSION);
            if (isOSVersion || isOSRelease || isKernelVer) {
                @try {
                    id mgrClass = NSClassFromString(@"IdentifierManager");
                    id mgr = mgrClass ? [mgrClass performSelector:@selector(sharedManager)] : nil;
                    NSString *bundleID = getCurrentBundleID();

                    SEL selIsAppEnabled = @selector(isApplicationEnabled:);
                    SEL selIsIdEnabled = @selector(isIdentifierEnabled:);
                    SEL selProfilePath = @selector(profileIdentityPath);

                    BOOL appEnabled = NO;
                    BOOL iosEnabled = NO;
                    NSString *identityDir = nil;

                    if (mgr && bundleID && [mgr respondsToSelector:selIsAppEnabled]) {
                        // BOOL return
                        NSMethodSignature *sig = [mgr methodSignatureForSelector:selIsAppEnabled];
                        if (sig) {
                            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
                            [inv setTarget:mgr];
                            [inv setSelector:selIsAppEnabled];
                            NSString *arg = bundleID;
                            [inv setArgument:&arg atIndex:2];
                            [inv invoke];
                            [inv getReturnValue:&appEnabled];
                        }
                    }

                    if (mgr && [mgr respondsToSelector:selIsIdEnabled]) {
                        NSMethodSignature *sig = [mgr methodSignatureForSelector:selIsIdEnabled];
                        if (sig) {
                            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
                            [inv setTarget:mgr];
                            [inv setSelector:selIsIdEnabled];
                            NSString *arg = @"IOSVersion";
                            [inv setArgument:&arg atIndex:2];
                            [inv invoke];
                            [inv getReturnValue:&iosEnabled];
                        }
                    }

                    if (mgr && [mgr respondsToSelector:selProfilePath]) {
                        identityDir = [mgr performSelector:selProfilePath];
                    }

                    if (mgr && bundleID && appEnabled && iosEnabled) {
                        NSDictionary *deviceIds = identityDir.length > 0 ? [NSDictionary dictionaryWithContentsOfFile:[identityDir stringByAppendingPathComponent:@"device_ids.plist"]] : nil;
                        NSDictionary *current = nil;
                        id versionClass = NSClassFromString(@"IOSVersionInfo");
                        id versionMgr = versionClass ? [versionClass performSelector:@selector(sharedManager)] : nil;
                        if (versionMgr && [versionMgr respondsToSelector:@selector(currentIOSVersionInfo)]) {
                            current = [versionMgr performSelector:@selector(currentIOSVersionInfo)];
                        }
                        NSString *val = nil;
                        if (isOSVersion) val = deviceIds[@"IOSBuild"] ?: current[@"build"];
                        else if (isOSRelease) val = deviceIds[@"Darwin"] ?: current[@"darwin"];
                        else val = deviceIds[@"KernelVersion"] ?: current[@"kernel_version"];

                        if (val.length > 0) {
                            const char *s = [val UTF8String];
                            if (s) {
                                size_t required = strlen(s) + 1;
                                if (!oldp) {
                                    *oldlenp = required;
                                    return 0;
                                }
                                if (*oldlenp < required) {
                                    *oldlenp = required;
                                    errno = ENOMEM;
                                    return -1;
                                }
                                memset(oldp, 0, *oldlenp);
                                memcpy(oldp, s, required);
                                *oldlenp = required;
                                return 0;
                            }
                        }
                    }
                } @catch (__unused NSException *e) {
                }
            }
        }

        // Check if this is a KERN_BOOTTIME query
        if (namelen >= 2 && name && name[0] == CTL_KERN && name[1] == KERN_BOOTTIME) {
            if (shouldSpoofBootTimeForApp() && isBootTimeOrUptimeEnabled()) {
                NSString *bundleID = getCurrentBundleID();
                if (bundleID) {
                    logBootTimeAccess("sysctl(KERN_BOOTTIME)", bundleID);
                }
                
                // Set recursion guard before calling UptimeManager
                isInsideHook = YES;
                updateCachedBootTimeValues();
                isInsideHook = NO;
                
                if (cachedBootTime && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                    struct timeval boottime;
                    boottime.tv_sec = (time_t)[cachedBootTime timeIntervalSince1970];
                    boottime.tv_usec = 0;
                    memcpy(oldp, &boottime, sizeof(boottime));
                    *oldlenp = sizeof(boottime);
                    return 0; // Success
                }
            }
        }
    } @catch (NSException *e) {
        isInsideHook = NO; // Reset guard on exception
        // Silent failure, pass through to original
    }
    // Call original function for all other cases
    if (orig_sysctl) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    return -1;
}

// Hook sysctlbyname() for "kern.boottime" queries - ONLY method that App Store apps commonly use
int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // CRITICAL: Recursion guard - if we're already inside hook, pass through to original
    if (isInsideHook) {
        if (orig_sysctlbyname) {
            return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
        }
        return -1;
    }
    
    @try {
        if (name && strcmp(name, "kern.boottime") == 0) {
            if (shouldSpoofBootTimeForApp() && isBootTimeOrUptimeEnabled()) {
                NSString *bundleID = getCurrentBundleID();
                if (bundleID) {
                    logBootTimeAccess("sysctlbyname(kern.boottime)", bundleID);
                }
                
                // Set recursion guard before calling UptimeManager
                isInsideHook = YES;
                updateCachedBootTimeValues();
                isInsideHook = NO;
                
                if (cachedBootTime && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                    struct timeval boottime;
                    boottime.tv_sec = (time_t)[cachedBootTime timeIntervalSince1970];
                    boottime.tv_usec = 0;
                    memcpy(oldp, &boottime, sizeof(boottime));
                    *oldlenp = sizeof(boottime);
                    return 0; // Success
                }
            }
        }
    } @catch (NSException *e) {
        isInsideHook = NO; // Reset guard on exception
        // Silent failure, pass through to original
    }
    // Call original function for all other cases
    if (orig_sysctlbyname) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }
    return -1;
}

// Hook for -[NSProcessInfo systemUptime]
static NSTimeInterval (*orig_systemUptime)(NSProcessInfo *, SEL);
static NSTimeInterval hook_systemUptime(NSProcessInfo *self, SEL _cmd) {
    // Recursion guard
    if (isInsideHook) {
        return orig_systemUptime(self, _cmd);
    }
    
    if (shouldSpoofBootTimeForApp() && isBootTimeOrUptimeEnabled()) {
        isInsideHook = YES;
        updateCachedBootTimeValues();
        isInsideHook = NO;
        
        if (cachedUptime > 0) {
            return cachedUptime;
        }
    }
    return orig_systemUptime(self, _cmd);
}

// Install system call hooks ONLY for scoped apps
static void installSystemCallHooks(void) {
    @try {
        if (hooksInstalled) {
            return; // Already installed
        }
        
        BOOL hookingSuccess = NO;
        
        // Use Substrate for rootful jailbreaks (iOS 12+)
        if (dlsym(RTLD_DEFAULT, "MSHookFunction")) {
            // Hook sysctl
            void *sysctlPtr = dlsym(RTLD_DEFAULT, "sysctl");
            if (sysctlPtr) {
                MSHookFunction(sysctlPtr, (void *)hook_sysctl, (void **)&orig_sysctl);
                hookingSuccess = YES;
            }
            
            // Hook sysctlbyname
            void *sysctlbynamePtr = dlsym(RTLD_DEFAULT, "sysctlbyname");
            if (sysctlbynamePtr) {
                MSHookFunction(sysctlbynamePtr, (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname);
                hookingSuccess = YES;
            }
        }
        
        if (hookingSuccess) {
            hooksInstalled = YES;
            NSString *bundleID = getCurrentBundleID();
            PXLog(@"[BootTimeHooks] ✅ System call hooks installed for scoped app: %@", bundleID);
            // Add systemUptime hook for NSProcessInfo
            Class procInfoClass = objc_getClass("NSProcessInfo");
            if (procInfoClass) {
                MSHookMessageEx(procInfoClass, @selector(systemUptime), (IMP)hook_systemUptime, (IMP *)&orig_systemUptime);
            }
        }
        
    } @catch (NSException *e) {
        PXLog(@"[BootTimeHooks] ❌ Exception installing hooks: %@", e);
    }
}

#pragma mark - Initialization

// COMPLETELY REMOVED ALL %hook DIRECTIVES - NO MORE OBJECTIVE-C METHOD HOOKS
// This eliminates crashes in non-scoped apps

%ctor {
    @autoreleasepool {
        @try {
            NSString *bundleID = getCurrentBundleID();
            
            // Skip if we can't get bundle ID
            if (!bundleID || [bundleID length] == 0) {
                return;
            }
            
            // Skip system processes, except Safari/Auth stack when enabled
            NSString *proc = [NSProcessInfo processInfo].processName;
            if ([bundleID hasPrefix:@"com.apple."] &&
                !(PXSafariStackSpoofEnabled() && PXIsSafariStackProcess(bundleID, proc))) {
                return;
            }
            
            // Only install hooks if this app is scoped, OR if Safari/Auth stack spoof is enabled.
            if (!isInScopedAppsList() && !PXAllowUnscopedSafariStack()) {
                // App is NOT scoped - no hooks, no interference, no crashes
                return;
            }
            
            PXLog(@"[BootTimeHooks] 🎯 Installing minimal system call hooks for scoped app: %@", bundleID);
            
            // Install the minimal system call hooks that App Store apps actually use immediately
            installSystemCallHooks();
            
        } @catch (NSException *e) {
            // Silent failure to prevent crashes
        }
    }
} 
