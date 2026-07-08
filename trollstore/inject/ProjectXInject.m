// ProjectXInject.m - substrate-free injected dylib bootstrap for TrollStore modes.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <mach-o/arch.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/mach_host.h>
#import <stdarg.h>
#import <string.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <sys/ioctl.h>
#import <sys/mount.h>
#import <sys/sockio.h>
#import <sys/sysctl.h>
#import <sys/time.h>
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
static BOOL gEnableNetworkHook = NO;
static BOOL gEnableCarrierHook = NO;
static BOOL gEnablePrivateWiFiHook = NO;
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
static NSUInteger gDeviceMetricsImagesScanned = 0;
static NSUInteger gDeviceMetricsSymbolsPatched = 0;
static NSUInteger gNetworkImagesScanned = 0;
static NSUInteger gNetworkSymbolsPatched = 0;
static NSUInteger gSysctlByNameImagesScanned = 0;
static NSUInteger gSysctlByNameSymbolsPatched = 0;

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

static BOOL PXCopyTimevalToSysctlBuffer(struct timeval value, void *oldp, size_t *oldlenp) {
    return PXCopyBytesToSysctlBuffer(&value, sizeof(value), oldp, oldlenp);
}

static uint32_t PXCPUFamilyForArchitecture(NSString *architecture) {
    if ([architecture containsString:@"A9"]) return 0x67CEEE93;
    if ([architecture containsString:@"A10"]) return 0x92FB37C8;
    if ([architecture containsString:@"A11"]) return 0xDA33D83D;
    if ([architecture containsString:@"A12"]) return 0x8765EDEA;
    if ([architecture containsString:@"A13"]) return 0xAF4F32CB;
    if ([architecture containsString:@"A14"]) return 0x1B588BB3;
    if ([architecture containsString:@"A15"]) return 0xDA33D83D;
    if ([architecture containsString:@"A16"]) return 0x8765EDEA;
    if ([architecture containsString:@"A17"]) return 0xAF4F32CB;
    if ([architecture containsString:@"A18"]) return 0x1B588BB3;
    if ([architecture containsString:@"M1"] || [architecture containsString:@"M2"]) return 0x458F4D97;
    return 0;
}

static uint32_t PXCPUSubtypeForArchitecture(NSString *architecture) {
    if ([architecture containsString:@"A9"]) return 2;
    if ([architecture containsString:@"A10"]) return 3;
    if ([architecture containsString:@"A11"]) return 4;
    if ([architecture containsString:@"A12"]) return 5;
    if ([architecture containsString:@"A13"]) return 6;
    if ([architecture containsString:@"A14"]) return 7;
    if ([architecture containsString:@"A15"]) return 8;
    if ([architecture containsString:@"A16"]) return 9;
    if ([architecture containsString:@"A17"]) return 10;
    if ([architecture containsString:@"A18"]) return 11;
    if ([architecture containsString:@"M1"]) return 12;
    if ([architecture containsString:@"M2"]) return 13;
    return 1;
}

static uint64_t PXCPUFrequencyForArchitecture(NSString *architecture, const char *name) {
    uint64_t frequency = 0;
    if ([architecture containsString:@"A9"]) frequency = 1800000000ULL;
    else if ([architecture containsString:@"A10"]) frequency = 2340000000ULL;
    else if ([architecture containsString:@"A11"]) frequency = 2390000000ULL;
    else if ([architecture containsString:@"A12"]) frequency = 2490000000ULL;
    else if ([architecture containsString:@"A13"]) frequency = 2650000000ULL;
    else if ([architecture containsString:@"A14"]) frequency = 2990000000ULL;
    else if ([architecture containsString:@"A15"]) frequency = 3230000000ULL;
    else if ([architecture containsString:@"A16"]) frequency = 3460000000ULL;
    else if ([architecture containsString:@"A17"]) frequency = 3780000000ULL;
    else if ([architecture containsString:@"A18"]) frequency = 4050000000ULL;
    else if ([architecture containsString:@"M1"]) frequency = 3200000000ULL;
    else if ([architecture containsString:@"M2"]) frequency = 3490000000ULL;
    if (frequency > 0 && name && strcmp(name, "hw.cpufrequency_min") == 0) frequency = (uint64_t)((double)frequency * 0.4);
    return frequency;
}

static uint32_t PXCacheSizeForArchitecture(NSString *architecture, const char *name) {
    BOOL l1 = name && (strcmp(name, "hw.l1icachesize") == 0 || strcmp(name, "hw.l1dcachesize") == 0);
    BOOL l2 = name && strcmp(name, "hw.l2cachesize") == 0;
    if (!l1 && !l2) return 0;
    if ([architecture containsString:@"A11"] || [architecture containsString:@"A12"]) return l1 ? 32768 : 8388608;
    if ([architecture containsString:@"A13"]) return l1 ? 65536 : 8388608;
    if ([architecture containsString:@"A14"] || [architecture containsString:@"A15"]) return l1 ? 65536 : 12582912;
    if ([architecture containsString:@"A16"] || [architecture containsString:@"A17"]) return l1 ? 65536 : 16777216;
    if ([architecture containsString:@"A18"]) return l1 ? 131072 : 20971520;
    if ([architecture containsString:@"M1"]) return l1 ? 131072 : 12582912;
    if ([architecture containsString:@"M2"]) return l1 ? 131072 : 16777216;
    return l1 ? 32768 : 3145728;
}

static NSString *PXMetricsValueForSysctlName(const char *name, BOOL *isUInt64Out) {
    if (isUInt64Out) *isUInt64Out = NO;
    if (!gEnableDeviceMetricsHook || !name) return nil;
    if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.activecpu") == 0 || strcmp(name, "hw.physicalcpu") == 0 || strcmp(name, "hw.logicalcpu") == 0) {
        NSUInteger cores = PXSnapshotUnsignedInteger(@"CPUCoreCount");
        return cores > 0 ? [@(cores) stringValue] : nil;
    }
    if (strcmp(name, "hw.memsize") == 0 || strcmp(name, "hw.physmem") == 0) {
        NSUInteger gb = PXSnapshotUnsignedInteger(@"DeviceMemory");
        if (isUInt64Out) *isUInt64Out = YES;
        return gb > 0 ? [@((uint64_t)gb * 1024ULL * 1024ULL * 1024ULL) stringValue] : nil;
    }
    if (strcmp(name, "hw.cpu.brand_string") == 0 || strcmp(name, "machdep.cpu.brand_string") == 0 || strcmp(name, "hw.cpubrand") == 0) {
        return PXSnapshotString(@"CPUArchitecture");
    }
    if (strcmp(name, "hw.cpufamily") == 0 || strcmp(name, "hw.cputype") == 0 || strcmp(name, "hw.cpusubtype") == 0 || strcmp(name, "hw.cachelinesize") == 0) {
        NSString *architecture = PXSnapshotString(@"CPUArchitecture");
        if (strcmp(name, "hw.cputype") == 0) return @"16777228";
        if (strcmp(name, "hw.cpusubtype") == 0) return [@(PXCPUSubtypeForArchitecture(architecture)) stringValue];
        if (strcmp(name, "hw.cpufamily") == 0) {
            uint32_t family = PXCPUFamilyForArchitecture(architecture);
            return family > 0 ? [@(family) stringValue] : nil;
        }
        return @"64";
    }
    if (strcmp(name, "hw.cpufrequency") == 0 || strcmp(name, "hw.cpufrequency_max") == 0 || strcmp(name, "hw.cpufrequency_min") == 0) {
        if (isUInt64Out) *isUInt64Out = YES;
        uint64_t frequency = PXCPUFrequencyForArchitecture(PXSnapshotString(@"CPUArchitecture"), name);
        return frequency > 0 ? [@(frequency) stringValue] : nil;
    }
    if (strcmp(name, "hw.l1icachesize") == 0 || strcmp(name, "hw.l1dcachesize") == 0 || strcmp(name, "hw.l2cachesize") == 0) {
        uint32_t size = PXCacheSizeForArchitecture(PXSnapshotString(@"CPUArchitecture"), name);
        return size > 0 ? [@(size) stringValue] : nil;
    }
    return nil;
}

static BOOL PXMetricsSysctlNameIsString(const char *name) {
    return name && (strcmp(name, "hw.cpu.brand_string") == 0 || strcmp(name, "machdep.cpu.brand_string") == 0 || strcmp(name, "hw.cpubrand") == 0);
}

static BOOL PXMetricsSysctlNameIsUInt64(const char *name) {
    return name && (strcmp(name, "hw.memsize") == 0 || strcmp(name, "hw.physmem") == 0 || strcmp(name, "hw.cpufrequency") == 0 || strcmp(name, "hw.cpufrequency_max") == 0 || strcmp(name, "hw.cpufrequency_min") == 0);
}

static NSString *PXValueForSysctlName(const char *name) {
    if (!name) return nil;
    if (strcmp(name, "hw.machine") == 0 && PXSysctlNameEnabled(@"hw.machine")) return PXSnapshotString(@"DeviceModel");
    if (strcmp(name, "hw.model") == 0 && PXSysctlNameEnabled(@"hw.model")) return PXSnapshotString(@"HwModel") ?: PXSnapshotString(@"BoardID");
    if (strcmp(name, "kern.osversion") == 0 && PXSysctlNameEnabled(@"kern.osversion")) return PXSnapshotString(@"IOSBuild");
    if (strcmp(name, "kern.version") == 0 && PXSysctlNameEnabled(@"kern.version")) return PXSnapshotString(@"KernelVersion");
    if (strcmp(name, "kern.osrelease") == 0) return PXSnapshotString(@"Darwin");
    if (strcmp(name, "kern.hostname") == 0) return PXSnapshotString(@"DeviceName") ?: PXSnapshotString(@"DeviceModel") ?: @"iPhone";
    if (strcmp(name, "kern.ostype") == 0) return @"Darwin";
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
    } else if (name[0] == CTL_KERN && name[1] == KERN_OSRELEASE) {
        sysctlName = @"kern.osrelease";
        value = PXSnapshotString(@"Darwin");
#ifdef KERN_HOSTNAME
    } else if (name[0] == CTL_KERN && name[1] == KERN_HOSTNAME) {
        sysctlName = @"kern.hostname";
        value = PXSnapshotString(@"DeviceName") ?: PXSnapshotString(@"DeviceModel") ?: @"iPhone";
#endif
#ifdef KERN_OSTYPE
    } else if (name[0] == CTL_KERN && name[1] == KERN_OSTYPE) {
        sysctlName = @"kern.ostype";
        value = @"Darwin";
#endif
#ifdef KERN_BOOTTIME
    } else if (gEnableDeviceMetricsHook && name[0] == CTL_KERN && name[1] == KERN_BOOTTIME) {
        sysctlName = @"kern.boottime";
        value = @"timeval";
#endif
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
#ifdef HW_PHYSMEM
    } else if (gEnableDeviceMetricsHook && name[0] == CTL_HW && name[1] == HW_PHYSMEM) {
        sysctlName = @"hw.physmem";
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

static uint64_t PXSnapshotStorageBytes(NSString *key) {
    double gb = PXSnapshotDouble(key);
    return gb > 0 ? (uint64_t)(gb * 1000.0 * 1000.0 * 1000.0) : 0;
}

static NSTimeInterval PXSnapshotUptime(void) {
    NSTimeInterval uptime = PXSnapshotDouble(@"SystemUptime");
    if (uptime > 0) return uptime;
    NSTimeInterval boot = PXSnapshotDouble(@"BootTime");
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    return boot > 0 && now > boot ? now - boot : 0;
}

static BOOL PXSnapshotBootTimeval(struct timeval *outValue) {
    if (!outValue) return NO;
    NSTimeInterval boot = PXSnapshotDouble(@"BootTime");
    if (boot <= 0) {
        NSTimeInterval uptime = PXSnapshotUptime();
        if (uptime > 0) boot = [[NSDate date] timeIntervalSince1970] - uptime;
    }
    if (boot <= 0) return NO;
    outValue->tv_sec = (time_t)boot;
    outValue->tv_usec = 0;
    return YES;
}

static BOOL PXShouldSpoofFilesystemPath(const char *path) {
    if (!path) return NO;
    return strcmp(path, "/") == 0 || strcmp(path, "/var") == 0 || strcmp(path, "/private/var") == 0 || strncmp(path, "/var/mobile", 11) == 0 || strncmp(path, "/private/var/mobile", 19) == 0;
}

static void PXApplyStatfsSpoof(struct statfs *value) {
    if (!value || !gEnableDeviceMetricsHook) return;
    uint64_t total = PXSnapshotStorageBytes(@"TotalStorage");
    uint64_t free = PXSnapshotStorageBytes(@"FreeStorage");
    if (total == 0 && free == 0) return;
    uint32_t blockSize = value->f_bsize > 0 ? (uint32_t)value->f_bsize : 4096;
    if (total > 0) value->f_blocks = total / blockSize;
    if (free > 0) {
        value->f_bfree = free / blockSize;
        value->f_bavail = value->f_bfree;
    }
}

static void PXMemoryDistribution(uint64_t total, uint64_t *freeOut, uint64_t *wiredOut, uint64_t *activeOut, uint64_t *inactiveOut) {
    if (freeOut) *freeOut = (uint64_t)((double)total * 0.35);
    if (wiredOut) *wiredOut = (uint64_t)((double)total * 0.20);
    if (activeOut) *activeOut = (uint64_t)((double)total * 0.30);
    if (inactiveOut) *inactiveOut = total - (freeOut ? *freeOut : 0) - (wiredOut ? *wiredOut : 0) - (activeOut ? *activeOut : 0);
}

static BOOL PXHasNetworkSnapshot(void) {
    return PXSnapshotString(@"SSID").length > 0 || PXSnapshotString(@"BSSID").length > 0 || PXSnapshotString(@"CarrierName").length > 0 || PXSnapshotString(@"CarrierMCC").length > 0 || PXSnapshotString(@"CarrierMNC").length > 0;
}

static NSString *PXCarrierName(void) {
    return PXSnapshotString(@"CarrierName") ?: @"Viettel";
}

static NSString *PXCarrierMCC(void) {
    return PXSnapshotString(@"CarrierMCC") ?: @"452";
}

static NSString *PXCarrierMNC(void) {
    return PXSnapshotString(@"CarrierMNC") ?: @"04";
}

static NSString *PXCarrierISO(void) {
    NSString *mcc = PXCarrierMCC();
    if ([mcc isEqualToString:@"452"]) return @"vn";
    return nil;
}

static id PXCarrierProviderObject(id original) {
    if (original) return original;
    if (!PXCarrierName().length && !PXCarrierMCC().length && !PXCarrierMNC().length) return nil;
    static id provider = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class carrier = NSClassFromString(@"CTCarrier");
        if (carrier) provider = [[carrier alloc] init];
    });
    return provider;
}

static NSDictionary *PXWiFiNetworkInfo(void) {
    NSString *ssid = PXSnapshotString(@"SSID");
    NSString *bssid = PXSnapshotString(@"BSSID");
    if (!ssid.length && !bssid.length) return nil;
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    if (ssid.length) info[@"SSID"] = ssid;
    if (bssid.length) info[@"BSSID"] = bssid;
    if (ssid.length) info[@"SSIDDATA"] = [ssid dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    return info;
}

static NSString *PXSnapshotLocalIPv4(void) {
    NSString *value = PXSnapshotString(@"LocalIPAddress");
    return value.length ? value : @"192.168.1.64";
}

static NSString *PXSnapshotLocalIPv6(void) {
    NSString *value = PXSnapshotString(@"LocalIPv6Address");
    return value.length ? value : @"fe80::1234:abcd:5678:9abc";
}

static NSString *PXSnapshotWiFiMAC(void) {
    NSString *value = PXSnapshotString(@"WiFiMAC") ?: PXSnapshotString(@"MACAddress") ?: PXSnapshotString(@"BSSID");
    return value.length ? value : @"02:00:00:00:00:00";
}

static BOOL PXParseMACAddress(NSString *value, uint8_t out[6]) {
    if (!value.length || !out) return NO;
    NSArray<NSString *> *parts = [value componentsSeparatedByString:@":"];
    if (parts.count != 6) return NO;
    for (NSUInteger i = 0; i < 6; i++) {
        unsigned int byte = 0;
        NSScanner *scanner = [NSScanner scannerWithString:parts[i]];
        if (![scanner scanHexInt:&byte] || byte > 0xff) return NO;
        out[i] = (uint8_t)byte;
    }
    return YES;
}

static BOOL PXFillSockaddrIn(struct sockaddr_in *addr, NSString *ip) {
    if (!addr || !ip.length) return NO;
    memset(addr, 0, sizeof(*addr));
    addr->sin_len = sizeof(*addr);
    addr->sin_family = AF_INET;
    return inet_pton(AF_INET, ip.UTF8String, &addr->sin_addr) == 1;
}

static BOOL PXFillSockaddrIn6(struct sockaddr_in6 *addr, NSString *ip) {
    if (!addr || !ip.length) return NO;
    memset(addr, 0, sizeof(*addr));
    addr->sin6_len = sizeof(*addr);
    addr->sin6_family = AF_INET6;
    return inet_pton(AF_INET6, ip.UTF8String, &addr->sin6_addr) == 1;
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
        @"EnableNetworkHook": @(PXSnapshotBool(@"EnableNetworkHook", PXSnapshotBool(@"EnableDeviceMetricsHook", NO))),
        @"EnableCarrierHook": @(PXSnapshotBool(@"EnableCarrierHook", PXSnapshotBool(@"EnableDeviceMetricsHook", NO))),
        @"EnablePrivateWiFiHook": @(PXSnapshotBool(@"EnablePrivateWiFiHook", NO)),
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
static NSTimeInterval (*orig_NSProcessInfo_systemUptime)(id, SEL) = NULL;
static CGRect (*orig_UIScreen_bounds)(id, SEL) = NULL;
static CGRect (*orig_UIScreen_nativeBounds)(id, SEL) = NULL;
static CGFloat (*orig_UIScreen_scale)(id, SEL) = NULL;
static CGFloat (*orig_UIScreen_nativeScale)(id, SEL) = NULL;
static float (*orig_UIDevice_batteryLevel)(id, SEL) = NULL;
static NSInteger (*orig_UIDevice_batteryState)(id, SEL) = NULL;
static NSDictionary *(*orig_NSFileManager_attributesOfFileSystemForPath_error)(id, SEL, NSString *, NSError **) = NULL;
static unsigned long long (*orig_NSFileManager_volumeAvailableCapacityForImportantUsageForURL_error)(id, SEL, NSURL *, NSError **) = NULL;
static unsigned long long (*orig_NSFileManager_volumeAvailableCapacityForOpportunisticUsageForURL_error)(id, SEL, NSURL *, NSError **) = NULL;
static unsigned long long (*orig_NSFileManager_volumeTotalCapacityForURL_error)(id, SEL, NSURL *, NSError **) = NULL;
static BOOL (*orig_NSURL_getResourceValue_forKey_error)(id, SEL, id *, NSString *, NSError **) = NULL;
static NSDictionary *(*orig_NSURL_resourceValuesForKeys_error)(id, SEL, NSArray *, NSError **) = NULL;
static id (*orig_CTTelephonyNetworkInfo_subscriberCellularProvider)(id, SEL) = NULL;
static id (*orig_CTTelephonyNetworkInfo_serviceSubscriberCellularProviders)(id, SEL) = NULL;
static NSString *(*orig_CTCarrier_carrierName)(id, SEL) = NULL;
static NSString *(*orig_CTCarrier_mobileCountryCode)(id, SEL) = NULL;
static NSString *(*orig_CTCarrier_mobileNetworkCode)(id, SEL) = NULL;
static NSString *(*orig_CTCarrier_isoCountryCode)(id, SEL) = NULL;
static BOOL (*orig_CTCarrier_allowsVOIP)(id, SEL) = NULL;

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

static id px_CTTelephonyNetworkInfo_subscriberCellularProvider(id self, SEL _cmd) {
    id provider = orig_CTTelephonyNetworkInfo_subscriberCellularProvider ? orig_CTTelephonyNetworkInfo_subscriberCellularProvider(self, _cmd) : nil;
    provider = PXCarrierProviderObject(provider);
    BOOL active = provider != nil && PXHasNetworkSnapshot();
    PXRecordHookCall(@"network", @"CTTelephonyNetworkInfo.subscriberCellularProvider", active ? @"provider" : @"", active, active);
    return provider;
}

static id px_CTTelephonyNetworkInfo_serviceSubscriberCellularProviders(id self, SEL _cmd) {
    id providers = orig_CTTelephonyNetworkInfo_serviceSubscriberCellularProviders ? orig_CTTelephonyNetworkInfo_serviceSubscriberCellularProviders(self, _cmd) : nil;
    if (!providers || ([providers respondsToSelector:@selector(count)] && [providers count] == 0)) {
        id provider = PXCarrierProviderObject(nil);
        if (provider) providers = @{@"0000000100000001": provider};
    }
    BOOL active = providers != nil && PXHasNetworkSnapshot();
    PXRecordHookCall(@"network", @"CTTelephonyNetworkInfo.serviceSubscriberCellularProviders", active ? @"providers" : @"", active, active);
    return providers;
}

static NSString *px_CTCarrier_carrierName(id self, SEL _cmd) {
    NSString *value = PXCarrierName();
    PXRecordHookCall(@"network", @"CTCarrier.carrierName", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_CTCarrier_carrierName ? orig_CTCarrier_carrierName(self, _cmd) : nil);
}

static NSString *px_CTCarrier_mobileCountryCode(id self, SEL _cmd) {
    NSString *value = PXCarrierMCC();
    PXRecordHookCall(@"network", @"CTCarrier.mobileCountryCode", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_CTCarrier_mobileCountryCode ? orig_CTCarrier_mobileCountryCode(self, _cmd) : nil);
}

static NSString *px_CTCarrier_mobileNetworkCode(id self, SEL _cmd) {
    NSString *value = PXCarrierMNC();
    PXRecordHookCall(@"network", @"CTCarrier.mobileNetworkCode", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_CTCarrier_mobileNetworkCode ? orig_CTCarrier_mobileNetworkCode(self, _cmd) : nil);
}

static NSString *px_CTCarrier_isoCountryCode(id self, SEL _cmd) {
    NSString *value = PXCarrierISO();
    PXRecordHookCall(@"network", @"CTCarrier.isoCountryCode", value ?: @"", value.length > 0, value.length > 0);
    return value ?: (orig_CTCarrier_isoCountryCode ? orig_CTCarrier_isoCountryCode(self, _cmd) : nil);
}

static BOOL px_CTCarrier_allowsVOIP(id self, SEL _cmd) {
    BOOL active = PXHasNetworkSnapshot();
    PXRecordHookCall(@"network", @"CTCarrier.allowsVOIP", active ? @"1" : @"", active, active);
    return active ? YES : (orig_CTCarrier_allowsVOIP ? orig_CTCarrier_allowsVOIP(self, _cmd) : YES);
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

static NSTimeInterval px_NSProcessInfo_systemUptime(id self, SEL _cmd) {
    NSTimeInterval value = gEnableDeviceMetricsHook ? PXSnapshotUptime() : 0;
    PXRecordHookCall(@"metrics", @"NSProcessInfo.systemUptime", value > 0 ? [@(value) stringValue] : @"", value > 0, value > 0);
    return value > 0 ? value : (orig_NSProcessInfo_systemUptime ? orig_NSProcessInfo_systemUptime(self, _cmd) : 0);
}

static float px_UIDevice_batteryLevel(id self, SEL _cmd) {
    double value = gEnableDeviceMetricsHook ? PXSnapshotDouble(@"BatteryLevel") : 0;
    BOOL valid = value >= 0.01 && value <= 1.0;
    PXRecordHookCall(@"metrics", @"UIDevice.batteryLevel", valid ? [@(value) stringValue] : @"", valid, valid);
    return valid ? (float)value : (orig_UIDevice_batteryLevel ? orig_UIDevice_batteryLevel(self, _cmd) : -1.0f);
}

static NSInteger px_UIDevice_batteryState(id self, SEL _cmd) {
    double value = gEnableDeviceMetricsHook ? PXSnapshotDouble(@"BatteryLevel") : 0;
    BOOL valid = value >= 0.01 && value <= 1.0;
    PXRecordHookCall(@"metrics", @"UIDevice.batteryState", valid ? @"1" : @"", valid, valid);
    return valid ? 1 : (orig_UIDevice_batteryState ? orig_UIDevice_batteryState(self, _cmd) : 0);
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

static NSDictionary *px_NSFileManager_attributesOfFileSystemForPath_error(id self, SEL _cmd, NSString *path, NSError **error) {
    NSDictionary *original = orig_NSFileManager_attributesOfFileSystemForPath_error ? orig_NSFileManager_attributesOfFileSystemForPath_error(self, _cmd, path, error) : nil;
    uint64_t total = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"TotalStorage") : 0;
    uint64_t free = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"FreeStorage") : 0;
    if (!original || (total == 0 && free == 0)) {
        PXRecordHookCall(@"storage", @"NSFileManager.attributesOfFileSystemForPath", @"", NO, NO);
        return original;
    }
    NSMutableDictionary *modified = [original mutableCopy];
    if (total > 0) modified[NSFileSystemSize] = @(total);
    if (free > 0) modified[NSFileSystemFreeSize] = @(free);
    PXRecordHookCall(@"storage", @"NSFileManager.attributesOfFileSystemForPath", [NSString stringWithFormat:@"total=%llu free=%llu", (unsigned long long)total, (unsigned long long)free], YES, YES);
    return modified;
}

static unsigned long long px_NSFileManager_volumeAvailableCapacityForImportantUsageForURL_error(id self, SEL _cmd, NSURL *url, NSError **error) {
    uint64_t free = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"FreeStorage") : 0;
    PXRecordHookCall(@"storage", @"NSFileManager.volumeAvailableCapacityForImportantUsageForURL", free > 0 ? [@(free) stringValue] : @"", free > 0, free > 0);
    return free > 0 ? free : (orig_NSFileManager_volumeAvailableCapacityForImportantUsageForURL_error ? orig_NSFileManager_volumeAvailableCapacityForImportantUsageForURL_error(self, _cmd, url, error) : 0);
}

static unsigned long long px_NSFileManager_volumeAvailableCapacityForOpportunisticUsageForURL_error(id self, SEL _cmd, NSURL *url, NSError **error) {
    uint64_t free = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"FreeStorage") : 0;
    uint64_t opportunistic = free > 0 ? (uint64_t)((double)free * 0.9) : 0;
    PXRecordHookCall(@"storage", @"NSFileManager.volumeAvailableCapacityForOpportunisticUsageForURL", opportunistic > 0 ? [@(opportunistic) stringValue] : @"", opportunistic > 0, opportunistic > 0);
    return opportunistic > 0 ? opportunistic : (orig_NSFileManager_volumeAvailableCapacityForOpportunisticUsageForURL_error ? orig_NSFileManager_volumeAvailableCapacityForOpportunisticUsageForURL_error(self, _cmd, url, error) : 0);
}

static unsigned long long px_NSFileManager_volumeTotalCapacityForURL_error(id self, SEL _cmd, NSURL *url, NSError **error) {
    uint64_t total = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"TotalStorage") : 0;
    PXRecordHookCall(@"storage", @"NSFileManager.volumeTotalCapacityForURL", total > 0 ? [@(total) stringValue] : @"", total > 0, total > 0);
    return total > 0 ? total : (orig_NSFileManager_volumeTotalCapacityForURL_error ? orig_NSFileManager_volumeTotalCapacityForURL_error(self, _cmd, url, error) : 0);
}

static BOOL px_NSURL_getResourceValue_forKey_error(id self, SEL _cmd, id *value, NSString *key, NSError **error) {
    BOOL result = orig_NSURL_getResourceValue_forKey_error ? orig_NSURL_getResourceValue_forKey_error(self, _cmd, value, key, error) : NO;
    uint64_t total = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"TotalStorage") : 0;
    uint64_t free = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"FreeStorage") : 0;
    if (result && value && key.length) {
        if ([key isEqualToString:NSURLVolumeTotalCapacityKey] && total > 0) *value = @(total);
        else if ([key isEqualToString:NSURLVolumeAvailableCapacityKey] && free > 0) *value = @(free);
        else if ([key isEqualToString:@"NSURLVolumeAvailableCapacityForImportantUsageKey"] && free > 0) *value = @(free);
        else if ([key isEqualToString:@"NSURLVolumeAvailableCapacityForOpportunisticUsageKey"] && free > 0) *value = @((uint64_t)((double)free * 0.9));
        else return result;
        PXRecordHookCall(@"storage", @"NSURL.getResourceValue", [NSString stringWithFormat:@"%@=%@", key, *value ?: @""], YES, YES);
    }
    return result;
}

static NSDictionary *px_NSURL_resourceValuesForKeys_error(id self, SEL _cmd, NSArray *keys, NSError **error) {
    NSDictionary *original = orig_NSURL_resourceValuesForKeys_error ? orig_NSURL_resourceValuesForKeys_error(self, _cmd, keys, error) : nil;
    uint64_t total = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"TotalStorage") : 0;
    uint64_t free = gEnableDeviceMetricsHook ? PXSnapshotStorageBytes(@"FreeStorage") : 0;
    if (!original || !keys.count || (total == 0 && free == 0)) return original;
    NSMutableDictionary *modified = [original mutableCopy];
    if ([keys containsObject:NSURLVolumeTotalCapacityKey] && total > 0) modified[NSURLVolumeTotalCapacityKey] = @(total);
    if ([keys containsObject:NSURLVolumeAvailableCapacityKey] && free > 0) modified[NSURLVolumeAvailableCapacityKey] = @(free);
    if ([keys containsObject:@"NSURLVolumeAvailableCapacityForImportantUsageKey"] && free > 0) modified[@"NSURLVolumeAvailableCapacityForImportantUsageKey"] = @(free);
    if ([keys containsObject:@"NSURLVolumeAvailableCapacityForOpportunisticUsageKey"] && free > 0) modified[@"NSURLVolumeAvailableCapacityForOpportunisticUsageKey"] = @((uint64_t)((double)free * 0.9));
    PXRecordHookCall(@"storage", @"NSURL.resourceValuesForKeys", [NSString stringWithFormat:@"total=%llu free=%llu", (unsigned long long)total, (unsigned long long)free], YES, YES);
    return modified;
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
        PXReplaceInstanceMethod(processInfo, @selector(systemUptime), (IMP)px_NSProcessInfo_systemUptime, (IMP *)&orig_NSProcessInfo_systemUptime);
        PXReplaceInstanceMethod(device, @selector(batteryLevel), (IMP)px_UIDevice_batteryLevel, (IMP *)&orig_UIDevice_batteryLevel);
        PXReplaceInstanceMethod(device, @selector(batteryState), (IMP)px_UIDevice_batteryState, (IMP *)&orig_UIDevice_batteryState);

        Class screen = objc_getClass("UIScreen");
        PXReplaceInstanceMethod(screen, @selector(bounds), (IMP)px_UIScreen_bounds, (IMP *)&orig_UIScreen_bounds);
        PXReplaceInstanceMethod(screen, @selector(nativeBounds), (IMP)px_UIScreen_nativeBounds, (IMP *)&orig_UIScreen_nativeBounds);
        PXReplaceInstanceMethod(screen, @selector(scale), (IMP)px_UIScreen_scale, (IMP *)&orig_UIScreen_scale);
        PXReplaceInstanceMethod(screen, @selector(nativeScale), (IMP)px_UIScreen_nativeScale, (IMP *)&orig_UIScreen_nativeScale);

        Class fileManager = objc_getClass("NSFileManager");
        PXReplaceInstanceMethod(fileManager, @selector(attributesOfFileSystemForPath:error:), (IMP)px_NSFileManager_attributesOfFileSystemForPath_error, (IMP *)&orig_NSFileManager_attributesOfFileSystemForPath_error);
        PXReplaceInstanceMethod(fileManager, @selector(volumeAvailableCapacityForImportantUsageForURL:error:), (IMP)px_NSFileManager_volumeAvailableCapacityForImportantUsageForURL_error, (IMP *)&orig_NSFileManager_volumeAvailableCapacityForImportantUsageForURL_error);
        PXReplaceInstanceMethod(fileManager, @selector(volumeAvailableCapacityForOpportunisticUsageForURL:error:), (IMP)px_NSFileManager_volumeAvailableCapacityForOpportunisticUsageForURL_error, (IMP *)&orig_NSFileManager_volumeAvailableCapacityForOpportunisticUsageForURL_error);
        PXReplaceInstanceMethod(fileManager, @selector(volumeTotalCapacityForURL:error:), (IMP)px_NSFileManager_volumeTotalCapacityForURL_error, (IMP *)&orig_NSFileManager_volumeTotalCapacityForURL_error);

        Class url = objc_getClass("NSURL");
        PXReplaceInstanceMethod(url, @selector(getResourceValue:forKey:error:), (IMP)px_NSURL_getResourceValue_forKey_error, (IMP *)&orig_NSURL_getResourceValue_forKey_error);
        PXReplaceInstanceMethod(url, @selector(resourceValuesForKeys:error:), (IMP)px_NSURL_resourceValuesForKeys_error, (IMP *)&orig_NSURL_resourceValuesForKeys_error);

    }

    if (gEnableCarrierHook) {
        Class telephony = NSClassFromString(@"CTTelephonyNetworkInfo");
        PXReplaceInstanceMethod(telephony, NSSelectorFromString(@"subscriberCellularProvider"), (IMP)px_CTTelephonyNetworkInfo_subscriberCellularProvider, (IMP *)&orig_CTTelephonyNetworkInfo_subscriberCellularProvider);
        PXReplaceInstanceMethod(telephony, NSSelectorFromString(@"serviceSubscriberCellularProviders"), (IMP)px_CTTelephonyNetworkInfo_serviceSubscriberCellularProviders, (IMP *)&orig_CTTelephonyNetworkInfo_serviceSubscriberCellularProviders);

        Class carrier = NSClassFromString(@"CTCarrier");
        PXReplaceInstanceMethod(carrier, NSSelectorFromString(@"carrierName"), (IMP)px_CTCarrier_carrierName, (IMP *)&orig_CTCarrier_carrierName);
        PXReplaceInstanceMethod(carrier, NSSelectorFromString(@"mobileCountryCode"), (IMP)px_CTCarrier_mobileCountryCode, (IMP *)&orig_CTCarrier_mobileCountryCode);
        PXReplaceInstanceMethod(carrier, NSSelectorFromString(@"mobileNetworkCode"), (IMP)px_CTCarrier_mobileNetworkCode, (IMP *)&orig_CTCarrier_mobileNetworkCode);
        PXReplaceInstanceMethod(carrier, NSSelectorFromString(@"isoCountryCode"), (IMP)px_CTCarrier_isoCountryCode, (IMP *)&orig_CTCarrier_isoCountryCode);
        PXReplaceInstanceMethod(carrier, NSSelectorFromString(@"allowsVOIP"), (IMP)px_CTCarrier_allowsVOIP, (IMP *)&orig_CTCarrier_allowsVOIP);
    }
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;
static void *(*orig_dlsym)(void *, const char *) = NULL;
static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef) = NULL;
static CFTypeRef (*orig_MGCopyAnswerWithError)(CFStringRef, int *) = NULL;
static CFArrayRef (*orig_CNCopySupportedInterfaces)(void) = NULL;
static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef) = NULL;
static int (*orig_getifaddrs)(struct ifaddrs **) = NULL;
static unsigned int (*orig_if_nametoindex)(const char *) = NULL;
static int (*orig_ioctl)(int, unsigned long, void *) = NULL;
static CFPropertyListRef (*orig_SCDynamicStoreCopyValue)(void *, CFStringRef) = NULL;
static CFArrayRef (*orig_WiFiManagerClientCopyDevices)(void *) = NULL;
static CFStringRef (*orig_WiFiDeviceClientCopyCurrentNetwork)(void *) = NULL;
static CFStringRef (*orig_WiFiNetworkGetSSID)(void *) = NULL;
static CFStringRef (*orig_WiFiNetworkGetBSSID)(void *) = NULL;
static int (*orig_statfs)(const char *, struct statfs *) = NULL;
static int (*orig_getfsstat)(struct statfs *, int, int) = NULL;
static kern_return_t (*orig_host_statistics64)(host_t, host_flavor_t, host_info64_t, mach_msg_type_number_t *) = NULL;
static kern_return_t (*orig_host_info)(host_t, host_flavor_t, host_info_t, mach_msg_type_number_t *) = NULL;
static const NXArchInfo *(*orig_NXGetLocalArchInfo)(void) = NULL;

static int px_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int px_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int px_uname(struct utsname *value);
static void *px_dlsym(void *handle, const char *symbol);
static CFArrayRef px_CNCopySupportedInterfaces(void);
static CFDictionaryRef px_CNCopyCurrentNetworkInfo(CFStringRef interfaceName);
static int px_getifaddrs(struct ifaddrs **interfaces);
static unsigned int px_if_nametoindex(const char *name);
static int px_ioctl(int fd, unsigned long request, void *argp);
static CFPropertyListRef px_SCDynamicStoreCopyValue(void *store, CFStringRef key);
static CFArrayRef px_WiFiManagerClientCopyDevices(void *manager);
static CFStringRef px_WiFiDeviceClientCopyCurrentNetwork(void *device);
static CFStringRef px_WiFiNetworkGetSSID(void *network);
static CFStringRef px_WiFiNetworkGetBSSID(void *network);
static int px_statfs(const char *path, struct statfs *buf);
static int px_getfsstat(struct statfs *buf, int bufsize, int flags);
static kern_return_t px_host_statistics64(host_t host, host_flavor_t flavor, host_info64_t info, mach_msg_type_number_t *count);
static kern_return_t px_host_info(host_t host, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t *count);
static const NXArchInfo *px_NXGetLocalArchInfo(void);

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

static void PXRebindSysctlByName(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (!PXShouldRebindImagePath(path, bundlePath)) continue;
        gSysctlByNameImagesScanned++;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        gSysctlByNameSymbolsPatched += PXRebindSymbolInImage(header, "_sysctlbyname", (const void *)px_sysctlbyname, (void **)&orig_sysctlbyname);
    }
    PXRecordHookCall(@"rebind-summary", @"sysctlbyname", [NSString stringWithFormat:@"images=%lu patched=%lu", (unsigned long)gSysctlByNameImagesScanned, (unsigned long)gSysctlByNameSymbolsPatched], gSysctlByNameSymbolsPatched > 0, gSysctlByNameSymbolsPatched > 0);
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

static void PXRebindDeviceMetrics(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (!PXShouldRebindImagePath(path, bundlePath)) continue;
        gDeviceMetricsImagesScanned++;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        gDeviceMetricsSymbolsPatched += PXRebindSymbolInImage(header, "_statfs", (const void *)px_statfs, (void **)&orig_statfs);
        gDeviceMetricsSymbolsPatched += PXRebindSymbolInImage(header, "_getfsstat", (const void *)px_getfsstat, (void **)&orig_getfsstat);
        gDeviceMetricsSymbolsPatched += PXRebindSymbolInImage(header, "_host_statistics64", (const void *)px_host_statistics64, (void **)&orig_host_statistics64);
        gDeviceMetricsSymbolsPatched += PXRebindSymbolInImage(header, "_host_info", (const void *)px_host_info, (void **)&orig_host_info);
        gDeviceMetricsSymbolsPatched += PXRebindSymbolInImage(header, "_NXGetLocalArchInfo", (const void *)px_NXGetLocalArchInfo, (void **)&orig_NXGetLocalArchInfo);
    }
    PXRecordHookCall(@"rebind-summary", @"device-metrics-c", [NSString stringWithFormat:@"images=%lu patched=%lu", (unsigned long)gDeviceMetricsImagesScanned, (unsigned long)gDeviceMetricsSymbolsPatched], gDeviceMetricsSymbolsPatched > 0, gDeviceMetricsSymbolsPatched > 0);
}

static void PXRebindNetwork(void) {
    NSString *bundlePath = PXNormalizePath([[NSBundle mainBundle] bundlePath]);
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        NSString *path = imageName ? PXNormalizePath([NSString stringWithUTF8String:imageName]) : @"";
        if (!PXShouldRebindImagePath(path, bundlePath)) continue;
        gNetworkImagesScanned++;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (gEnableNetworkHook) {
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_CNCopySupportedInterfaces", (const void *)px_CNCopySupportedInterfaces, (void **)&orig_CNCopySupportedInterfaces);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_CNCopyCurrentNetworkInfo", (const void *)px_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_getifaddrs", (const void *)px_getifaddrs, (void **)&orig_getifaddrs);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_if_nametoindex", (const void *)px_if_nametoindex, (void **)&orig_if_nametoindex);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_ioctl", (const void *)px_ioctl, (void **)&orig_ioctl);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_SCDynamicStoreCopyValue", (const void *)px_SCDynamicStoreCopyValue, (void **)&orig_SCDynamicStoreCopyValue);
        }
        if (gEnablePrivateWiFiHook) {
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_WiFiManagerClientCopyDevices", (const void *)px_WiFiManagerClientCopyDevices, (void **)&orig_WiFiManagerClientCopyDevices);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_WiFiDeviceClientCopyCurrentNetwork", (const void *)px_WiFiDeviceClientCopyCurrentNetwork, (void **)&orig_WiFiDeviceClientCopyCurrentNetwork);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_WiFiNetworkGetSSID", (const void *)px_WiFiNetworkGetSSID, (void **)&orig_WiFiNetworkGetSSID);
            gNetworkSymbolsPatched += PXRebindSymbolInImage(header, "_WiFiNetworkGetBSSID", (const void *)px_WiFiNetworkGetBSSID, (void **)&orig_WiFiNetworkGetBSSID);
        }
    }
    PXRecordHookCall(@"rebind-summary", @"network-c", [NSString stringWithFormat:@"images=%lu patched=%lu", (unsigned long)gNetworkImagesScanned, (unsigned long)gNetworkSymbolsPatched], gNetworkSymbolsPatched > 0, gNetworkSymbolsPatched > 0);
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
        if (strcmp(name, "kern.boottime") == 0) {
            struct timeval boot = {0};
            BOOL copied = PXSnapshotBootTimeval(&boot) && PXCopyTimevalToSysctlBuffer(boot, oldp, oldlenp);
            PXRecordHookCall(@"sysctlbyname", @"kern.boottime", copied ? [NSString stringWithFormat:@"%lld", (long long)boot.tv_sec] : @"", copied, copied);
            if (copied) return 0;
        }
        BOOL isUInt64 = NO;
        NSString *metricsValue = PXMetricsValueForSysctlName(name, &isUInt64);
        if (metricsValue.length) {
            BOOL copied = NO;
            if (PXMetricsSysctlNameIsString(name)) {
                copied = PXCopyCStringToSysctlBuffer(metricsValue, oldp, oldlenp);
            } else if (isUInt64 || PXMetricsSysctlNameIsUInt64(name)) {
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
            if ([sysctlName isEqualToString:@"kern.boottime"]) {
                struct timeval boot = {0};
                BOOL copied = PXSnapshotBootTimeval(&boot) && PXCopyTimevalToSysctlBuffer(boot, oldp, oldlenp);
                PXRecordHookCall(@"sysctl", sysctlName, copied ? [NSString stringWithFormat:@"%lld", (long long)boot.tv_sec] : @"", copied, copied);
                if (copied) return 0;
            }
            if (value.length) {
                BOOL copied = NO;
                BOOL metricsInteger = [sysctlName isEqualToString:@"hw.ncpu"] || [sysctlName isEqualToString:@"hw.activecpu"] || [sysctlName isEqualToString:@"hw.physicalcpu"] || [sysctlName isEqualToString:@"hw.logicalcpu"] || [sysctlName isEqualToString:@"hw.memsize"] || [sysctlName isEqualToString:@"hw.physmem"];
                if ([sysctlName isEqualToString:@"hw.memsize"] || [sysctlName isEqualToString:@"hw.physmem"]) {
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

static int px_statfs(const char *path, struct statfs *buf) {
    if (!orig_statfs) orig_statfs = dlsym(RTLD_NEXT, "statfs");
    int result = orig_statfs ? orig_statfs(path, buf) : -1;
    if (result == 0 && gCHooksReady && gEnableDeviceMetricsHook && PXShouldSpoofFilesystemPath(path)) {
        PXApplyStatfsSpoof(buf);
        PXRecordHookCall(@"storage-c", @"statfs", path ? [NSString stringWithUTF8String:path] ?: @"" : @"", YES, YES);
    }
    return result;
}

static int px_getfsstat(struct statfs *buf, int bufsize, int flags) {
    if (!orig_getfsstat) orig_getfsstat = dlsym(RTLD_NEXT, "getfsstat");
    int result = orig_getfsstat ? orig_getfsstat(buf, bufsize, flags) : -1;
    if (result > 0 && gCHooksReady && gEnableDeviceMetricsHook && buf && bufsize > 0) {
        for (int i = 0; i < result; i++) {
            if (PXShouldSpoofFilesystemPath(buf[i].f_mntonname)) PXApplyStatfsSpoof(&buf[i]);
        }
        PXRecordHookCall(@"storage-c", @"getfsstat", [NSString stringWithFormat:@"filesystems=%d", result], YES, YES);
    }
    return result;
}

static kern_return_t px_host_statistics64(host_t host, host_flavor_t flavor, host_info64_t info, mach_msg_type_number_t *count) {
    if (!orig_host_statistics64) orig_host_statistics64 = dlsym(RTLD_NEXT, "host_statistics64");
    kern_return_t result = orig_host_statistics64 ? orig_host_statistics64(host, flavor, info, count) : KERN_FAILURE;
    if (result != KERN_SUCCESS || !gCHooksReady || !gEnableDeviceMetricsHook || !info || !count) return result;
    uint64_t total = (uint64_t)PXSnapshotUnsignedInteger(@"DeviceMemory") * 1024ULL * 1024ULL * 1024ULL;
    if (total == 0) return result;
    if (flavor == HOST_VM_INFO64 && *count >= HOST_VM_INFO64_COUNT) {
        vm_statistics64_data_t *stats = (vm_statistics64_data_t *)info;
        uint64_t freeBytes = 0, wiredBytes = 0, activeBytes = 0, inactiveBytes = 0;
        PXMemoryDistribution(total, &freeBytes, &wiredBytes, &activeBytes, &inactiveBytes);
        vm_size_t pageSize = 4096;
        host_page_size(host, &pageSize);
        if (pageSize == 0) pageSize = 4096;
        stats->free_count = (natural_t)(freeBytes / pageSize);
        stats->wire_count = (natural_t)(wiredBytes / pageSize);
        stats->active_count = (natural_t)(activeBytes / pageSize);
        stats->inactive_count = (natural_t)(inactiveBytes / pageSize);
        PXRecordHookCall(@"host", @"host_statistics64.HOST_VM_INFO64", [NSString stringWithFormat:@"total=%llu", (unsigned long long)total], YES, YES);
    }
    return result;
}

static kern_return_t px_host_info(host_t host, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t *count) {
    if (!orig_host_info) orig_host_info = dlsym(RTLD_NEXT, "host_info");
    kern_return_t result = orig_host_info ? orig_host_info(host, flavor, info, count) : KERN_FAILURE;
    if (result != KERN_SUCCESS || !gCHooksReady || !gEnableDeviceMetricsHook || !info || !count) return result;
    NSUInteger cores = PXSnapshotUnsignedInteger(@"CPUCoreCount");
    uint64_t total = (uint64_t)PXSnapshotUnsignedInteger(@"DeviceMemory") * 1024ULL * 1024ULL * 1024ULL;
    if (flavor == HOST_BASIC_INFO && *count >= HOST_BASIC_INFO_COUNT) {
        host_basic_info_t basic = (host_basic_info_t)info;
        if (total > 0) basic->max_mem = total;
        if (cores > 0) {
            basic->avail_cpus = (integer_t)cores;
            basic->max_cpus = (integer_t)cores;
        }
        PXRecordHookCall(@"host", @"host_info.HOST_BASIC_INFO", [NSString stringWithFormat:@"cores=%lu total=%llu", (unsigned long)cores, (unsigned long long)total], YES, YES);
    }
    return result;
}

static const NXArchInfo *px_NXGetLocalArchInfo(void) {
    if (!orig_NXGetLocalArchInfo) orig_NXGetLocalArchInfo = dlsym(RTLD_NEXT, "NXGetLocalArchInfo");
    const NXArchInfo *original = orig_NXGetLocalArchInfo ? orig_NXGetLocalArchInfo() : NULL;
    if (!gCHooksReady || !gEnableDeviceMetricsHook || !original) return original;
    NSString *architecture = PXSnapshotString(@"CPUArchitecture");
    if (!architecture.length) return original;
    static NXArchInfo custom;
    custom = *original;
    custom.cpusubtype = (cpu_subtype_t)PXCPUSubtypeForArchitecture(architecture);
    if ([architecture containsString:@"M1"]) custom.description = "arm64v8 Apple M1";
    else if ([architecture containsString:@"M2"]) custom.description = "arm64v8 Apple M2";
    else if ([architecture containsString:@"A11"] || [architecture containsString:@"A12"] || [architecture containsString:@"A13"] || [architecture containsString:@"A14"] || [architecture containsString:@"A15"] || [architecture containsString:@"A16"] || [architecture containsString:@"A17"] || [architecture containsString:@"A18"]) custom.description = "ARM64E";
    PXRecordHookCall(@"host", @"NXGetLocalArchInfo", architecture, YES, YES);
    return &custom;
}

static CFArrayRef px_CNCopySupportedInterfaces(void) {
    NSDictionary *network = PXWiFiNetworkInfo();
    if (gCHooksReady && gEnableNetworkHook && network.count) {
        PXRecordHookCall(@"network-c", @"CNCopySupportedInterfaces", @"en0", YES, YES);
        return CFBridgingRetain(@[@"en0"]);
    }
    if (!orig_CNCopySupportedInterfaces) orig_CNCopySupportedInterfaces = dlsym(RTLD_NEXT, "CNCopySupportedInterfaces");
    return orig_CNCopySupportedInterfaces ? orig_CNCopySupportedInterfaces() : NULL;
}

static CFDictionaryRef px_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    NSDictionary *network = PXWiFiNetworkInfo();
    if (gCHooksReady && gEnableNetworkHook && network.count) {
        NSString *iface = interfaceName ? (__bridge NSString *)interfaceName : @"";
        PXRecordHookCall(@"network-c", @"CNCopyCurrentNetworkInfo", [NSString stringWithFormat:@"%@ %@ %@", iface ?: @"", network[@"SSID"] ?: @"", network[@"BSSID"] ?: @""], YES, YES);
        return CFBridgingRetain(network);
    }
    if (!orig_CNCopyCurrentNetworkInfo) orig_CNCopyCurrentNetworkInfo = dlsym(RTLD_NEXT, "CNCopyCurrentNetworkInfo");
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

static int px_getifaddrs(struct ifaddrs **interfaces) {
    if (!orig_getifaddrs) orig_getifaddrs = dlsym(RTLD_NEXT, "getifaddrs");
    int result = orig_getifaddrs ? orig_getifaddrs(interfaces) : -1;
    if (result != 0 || !gCHooksReady || !gEnableNetworkHook || !interfaces || !*interfaces) return result;
    NSString *ipv4 = PXSnapshotLocalIPv4();
    NSString *ipv6 = PXSnapshotLocalIPv6();
    NSString *mac = PXSnapshotWiFiMAC();
    BOOL spoofed = NO;
    for (struct ifaddrs *cursor = *interfaces; cursor; cursor = cursor->ifa_next) {
        if (!cursor->ifa_name || strcmp(cursor->ifa_name, "en0") != 0 || !cursor->ifa_addr) continue;
        if (cursor->ifa_addr->sa_family == AF_INET) {
            spoofed |= PXFillSockaddrIn((struct sockaddr_in *)cursor->ifa_addr, ipv4);
        } else if (cursor->ifa_addr->sa_family == AF_INET6) {
            spoofed |= PXFillSockaddrIn6((struct sockaddr_in6 *)cursor->ifa_addr, ipv6);
        } else if (cursor->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *dl = (struct sockaddr_dl *)cursor->ifa_addr;
            uint8_t bytes[6] = {0};
            if (dl->sdl_alen >= 6 && PXParseMACAddress(mac, bytes)) {
                memcpy(LLADDR(dl), bytes, 6);
                spoofed = YES;
            }
        }
    }
    PXRecordHookCall(@"network-c", @"getifaddrs", [NSString stringWithFormat:@"en0 %@ %@ %@", ipv4 ?: @"", ipv6 ?: @"", mac ?: @""], spoofed, spoofed);
    return result;
}

static unsigned int px_if_nametoindex(const char *name) {
    if (!orig_if_nametoindex) orig_if_nametoindex = dlsym(RTLD_NEXT, "if_nametoindex");
    unsigned int result = orig_if_nametoindex ? orig_if_nametoindex(name) : 0;
    if (gCHooksReady && gEnableNetworkHook && name && strcmp(name, "en0") == 0) {
        PXRecordHookCall(@"network-c", @"if_nametoindex", [NSString stringWithFormat:@"en0=%u", result ?: 4], YES, YES);
        return result ?: 4;
    }
    return result;
}

static int px_ioctl(int fd, unsigned long request, void *argp) {
    if (!orig_ioctl) orig_ioctl = dlsym(RTLD_NEXT, "ioctl");
    int result = orig_ioctl ? orig_ioctl(fd, request, argp) : -1;
    if (result != 0 || !gCHooksReady || !gEnableNetworkHook || !argp) return result;
    struct ifreq *ifr = (struct ifreq *)argp;
    if (strncmp(ifr->ifr_name, "en0", IFNAMSIZ) != 0) return result;
    if (request == SIOCGIFADDR) {
        NSString *ipv4 = PXSnapshotLocalIPv4();
        BOOL copied = PXFillSockaddrIn((struct sockaddr_in *)&ifr->ifr_addr, ipv4);
        PXRecordHookCall(@"network-c", @"ioctl.SIOCGIFADDR", ipv4 ?: @"", copied, copied);
    }
#ifdef SIOCGIFLLADDR
    else if (request == SIOCGIFLLADDR) {
        NSString *mac = PXSnapshotWiFiMAC();
        uint8_t bytes[6] = {0};
        BOOL copied = PXParseMACAddress(mac, bytes);
        if (copied) memcpy(ifr->ifr_addr.sa_data, bytes, 6);
        PXRecordHookCall(@"network-c", @"ioctl.SIOCGIFLLADDR", mac ?: @"", copied, copied);
    }
#endif
    return result;
}

static CFPropertyListRef px_SCDynamicStoreCopyValue(void *store, CFStringRef key) {
    NSString *keyString = key ? (__bridge NSString *)key : @"";
    if (gCHooksReady && gEnableNetworkHook && keyString.length) {
        NSDictionary *wifi = PXWiFiNetworkInfo();
        NSString *ipv4 = PXSnapshotLocalIPv4();
        NSString *ipv6 = PXSnapshotLocalIPv6();
        if ([keyString containsString:@"State:/Network/Interface/en0/IPv4"] && ipv4.length) {
            NSDictionary *value = @{@"Addresses": @[ipv4], @"InterfaceName": @"en0"};
            PXRecordHookCall(@"network-c", @"SCDynamicStoreCopyValue.IPv4", ipv4, YES, YES);
            return CFBridgingRetain(value);
        }
        if ([keyString containsString:@"State:/Network/Interface/en0/IPv6"] && ipv6.length) {
            NSDictionary *value = @{@"Addresses": @[ipv6], @"InterfaceName": @"en0"};
            PXRecordHookCall(@"network-c", @"SCDynamicStoreCopyValue.IPv6", ipv6, YES, YES);
            return CFBridgingRetain(value);
        }
        if (([keyString containsString:@"AirPort"] || [keyString containsString:@"Wi-Fi"] || [keyString containsString:@"WiFi"]) && wifi.count) {
            PXRecordHookCall(@"network-c", @"SCDynamicStoreCopyValue.WiFi", [NSString stringWithFormat:@"%@ %@", wifi[@"SSID"] ?: @"", wifi[@"BSSID"] ?: @""], YES, YES);
            return CFBridgingRetain(wifi);
        }
    }
    if (!orig_SCDynamicStoreCopyValue) orig_SCDynamicStoreCopyValue = dlsym(RTLD_NEXT, "SCDynamicStoreCopyValue");
    return orig_SCDynamicStoreCopyValue ? orig_SCDynamicStoreCopyValue(store, key) : NULL;
}

static CFArrayRef px_WiFiManagerClientCopyDevices(void *manager) {
    if (gCHooksReady && gEnablePrivateWiFiHook && PXWiFiNetworkInfo().count) {
        PXRecordHookCall(@"network-private", @"WiFiManagerClientCopyDevices", @"en0", YES, YES);
        return CFBridgingRetain(@[@"en0"]);
    }
    if (!orig_WiFiManagerClientCopyDevices) orig_WiFiManagerClientCopyDevices = dlsym(RTLD_NEXT, "WiFiManagerClientCopyDevices");
    return orig_WiFiManagerClientCopyDevices ? orig_WiFiManagerClientCopyDevices(manager) : NULL;
}

static CFStringRef px_WiFiDeviceClientCopyCurrentNetwork(void *device) {
    if (gCHooksReady && gEnablePrivateWiFiHook && PXWiFiNetworkInfo().count) {
        PXRecordHookCall(@"network-private", @"WiFiDeviceClientCopyCurrentNetwork", @"ProjectXNetwork", YES, YES);
        return CFBridgingRetain(@"ProjectXNetwork");
    }
    if (!orig_WiFiDeviceClientCopyCurrentNetwork) orig_WiFiDeviceClientCopyCurrentNetwork = dlsym(RTLD_NEXT, "WiFiDeviceClientCopyCurrentNetwork");
    return orig_WiFiDeviceClientCopyCurrentNetwork ? orig_WiFiDeviceClientCopyCurrentNetwork(device) : NULL;
}

static CFStringRef px_WiFiNetworkGetSSID(void *network) {
    NSString *ssid = PXSnapshotString(@"SSID");
    if (gCHooksReady && gEnablePrivateWiFiHook && ssid.length) {
        PXRecordHookCall(@"network-private", @"WiFiNetworkGetSSID", ssid, YES, YES);
        return (__bridge CFStringRef)ssid;
    }
    if (!orig_WiFiNetworkGetSSID) orig_WiFiNetworkGetSSID = dlsym(RTLD_NEXT, "WiFiNetworkGetSSID");
    return orig_WiFiNetworkGetSSID ? orig_WiFiNetworkGetSSID(network) : NULL;
}

static CFStringRef px_WiFiNetworkGetBSSID(void *network) {
    NSString *bssid = PXSnapshotString(@"BSSID");
    if (gCHooksReady && gEnablePrivateWiFiHook && bssid.length) {
        PXRecordHookCall(@"network-private", @"WiFiNetworkGetBSSID", bssid, YES, YES);
        return (__bridge CFStringRef)bssid;
    }
    if (!orig_WiFiNetworkGetBSSID) orig_WiFiNetworkGetBSSID = dlsym(RTLD_NEXT, "WiFiNetworkGetBSSID");
    return orig_WiFiNetworkGetBSSID ? orig_WiFiNetworkGetBSSID(network) : NULL;
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
        if ([name isEqualToString:@"statfs"] && gEnableDeviceMetricsHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_statfs;
        }
        if ([name isEqualToString:@"getfsstat"] && gEnableDeviceMetricsHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_getfsstat;
        }
        if ([name isEqualToString:@"host_statistics64"] && gEnableDeviceMetricsHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_host_statistics64;
        }
        if ([name isEqualToString:@"host_info"] && gEnableDeviceMetricsHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_host_info;
        }
        if ([name isEqualToString:@"NXGetLocalArchInfo"] && gEnableDeviceMetricsHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_NXGetLocalArchInfo;
        }
        if ([name isEqualToString:@"CNCopySupportedInterfaces"] && gEnableNetworkHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_CNCopySupportedInterfaces;
        }
        if ([name isEqualToString:@"CNCopyCurrentNetworkInfo"] && gEnableNetworkHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_CNCopyCurrentNetworkInfo;
        }
        if ([name isEqualToString:@"getifaddrs"] && gEnableNetworkHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_getifaddrs;
        }
        if ([name isEqualToString:@"if_nametoindex"] && gEnableNetworkHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_if_nametoindex;
        }
        if ([name isEqualToString:@"ioctl"] && gEnableNetworkHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_ioctl;
        }
        if ([name isEqualToString:@"SCDynamicStoreCopyValue"] && gEnableNetworkHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_SCDynamicStoreCopyValue;
        }
        if ([name isEqualToString:@"WiFiManagerClientCopyDevices"] && gEnablePrivateWiFiHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_WiFiManagerClientCopyDevices;
        }
        if ([name isEqualToString:@"WiFiDeviceClientCopyCurrentNetwork"] && gEnablePrivateWiFiHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_WiFiDeviceClientCopyCurrentNetwork;
        }
        if ([name isEqualToString:@"WiFiNetworkGetSSID"] && gEnablePrivateWiFiHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_WiFiNetworkGetSSID;
        }
        if ([name isEqualToString:@"WiFiNetworkGetBSSID"] && gEnablePrivateWiFiHook) {
            PXRecordHookCall(@"dlsym", name, @"ProjectX replacement", YES, YES);
            return (void *)px_WiFiNetworkGetBSSID;
        }
    }
    return PXCallOrigDlsym(handle, symbol);
}

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
    gEnableNetworkHook = PXSnapshotBool(@"EnableNetworkHook", gEnableDeviceMetricsHook);
    gEnableCarrierHook = PXSnapshotBool(@"EnableCarrierHook", gEnableDeviceMetricsHook);
    gEnablePrivateWiFiHook = PXSnapshotBool(@"EnablePrivateWiFiHook", NO);
    gEnableMobileGestaltHook = PXSnapshotBool(@"EnableMobileGestaltHook", NO);
    gCHooksReady = YES;
    if (gEnableSysctlHook) {
        PXRebindSysctl();
    }
    if (gEnableSysctlByNameHook) {
        PXRebindSysctlByName();
    }
    if (gEnableUnameHook) {
        PXRebindUname();
    }
    if (gEnableDlsymHook) {
        PXRebindDlsym();
    }
    if (gEnableDeviceMetricsHook) {
        PXRebindDeviceMetrics();
    }
    if (gEnableNetworkHook || gEnablePrivateWiFiHook) {
        PXRebindNetwork();
    }
    if (gEnableMobileGestaltHook) {
        PXRebindMobileGestalt();
    }
    PXInjectLog(@"C hooks enabled mode=%@ sysctlbyname=%p enabled=%@ sysctl=%p enabled=%@ uname=%p enabled=%@ dlsym=%p enabled=%@ metrics=%@ network=%@ carrier=%@ privateWiFi=%@ MGCopyAnswer=%p MGCopyAnswerWithError=%p MobileGestalt enabled=%@",
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
                gEnableNetworkHook ? @"YES" : @"NO",
                gEnableCarrierHook ? @"YES" : @"NO",
                gEnablePrivateWiFiHook ? @"YES" : @"NO",
                orig_MGCopyAnswer,
                orig_MGCopyAnswerWithError,
                gEnableMobileGestaltHook ? @"YES" : @"NO");
}

__attribute__((constructor))
static void ProjectXInjectInit(void) {
    @autoreleasepool {
        PXLoadSnapshot();
        gEnableDeviceMetricsHook = PXSnapshotBool(@"EnableDeviceMetricsHook", NO);
        gEnableNetworkHook = PXSnapshotBool(@"EnableNetworkHook", gEnableDeviceMetricsHook);
        gEnableCarrierHook = PXSnapshotBool(@"EnableCarrierHook", gEnableDeviceMetricsHook);
        gEnablePrivateWiFiHook = PXSnapshotBool(@"EnablePrivateWiFiHook", NO);
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
