// JailbreakBypassHooks.x
// Phase 1: File/URL/InstalledApps/LoopbackPortScan/WriteCheck

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CoreFoundation/CoreFoundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <dirent.h>
#import <stdarg.h>
#import <stdlib.h>
#import <spawn.h>
#import <signal.h>
#import <sys/stat.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <sys/types.h>
#import <sys/syscall.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <sys/sysctl.h>
#if __has_include(<sys/attr.h>)
#import <sys/attr.h>
#endif
#if __has_include(<sys/user.h>)
#import <sys/user.h>
#endif
#import <string.h>
#import <pthread.h>
#import <dispatch/dispatch.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <stdint.h>

// XPC types — Theos SDK doesn't ship <xpc/xpc.h>.
// We only need opaque pointers and a few functions.
typedef void *xpc_object_t;
typedef const struct _xpc_type_s *xpc_type_t;
extern xpc_type_t _xpc_type_dictionary;
#define XPC_TYPE_DICTIONARY (&_xpc_type_dictionary)
extern xpc_type_t xpc_get_type(xpc_object_t object);
extern xpc_object_t xpc_dictionary_create(const char * const *keys, const xpc_object_t *values, size_t count);
extern xpc_object_t xpc_dictionary_create_empty(void);
extern uint64_t xpc_dictionary_get_uint64(xpc_object_t xdict, const char *key);
extern void xpc_dictionary_set_uint64(xpc_object_t xdict, const char *key, uint64_t value);

// bootstrap_look_up from bootstrap.h
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
#ifndef BOOTSTRAP_UNKNOWN_SERVICE
#define BOOTSTRAP_UNKNOWN_SERVICE 1102
#endif

// fcntl code-signing constants (not in all SDKs)
#ifndef F_ADDSIGS
#define F_ADDSIGS 61
#endif
#ifndef F_GETSIGSINFO
#define F_GETSIGSINFO 69
#endif
#ifndef GETSIGSINFO_PLATFORM_BINARY
#define GETSIGSINFO_PLATFORM_BINARY 1
#endif
// fsignatures_t is already defined in <sys/fcntl.h> on iOS 16.5+ SDK.
// fgetsigsinfo may not be available in all SDKs.
#ifndef _FGETSIGSINFO_T
typedef struct {
    off_t       fg_file_start;
    int         fg_info_request;
    int         fg_sig_is_platform;
} fgetsigsinfo;
#endif

// XPC private pipe functions (resolved via libxpc at link time)
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t request, xpc_object_t *reply);
extern int xpc_pipe_routine_with_flags(xpc_object_t pipe, xpc_object_t request, xpc_object_t *reply, uint64_t flags);

// Some iOS SDKs used by Theos don't ship <link.h>, but we only need the
// leading fields of dl_phdr_info to access dlpi_name for dl_iterate_phdr.
struct dl_phdr_info {
    uintptr_t dlpi_addr;
    const char *dlpi_name;
    const void *dlpi_phdr;
    unsigned short dlpi_phnum;
};

// Some Theos SDKs for iOS don't ship <sys/ptrace.h>.
// PT_DENY_ATTACH is 31 on Darwin.
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

// Code signing constants (not always available in Theos SDKs).
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS       0
#endif
#ifndef CS_PLATFORM_BINARY
#define CS_PLATFORM_BINARY  0x4000000
#endif
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#import <unistd.h>
#import <limits.h>

#import <substrate.h>

// Optional logging macro if ProjectXLogging is present.
#ifndef PXLog
#define PXLog(...) NSLog(__VA_ARGS__)
#endif

@interface IdentifierManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isApplicationEnabled:(NSString *)bundleID;
@end

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (NSArray *)allInstalledApplications;
- (NSArray *)installedApplications;
- (NSArray *)allApplications;
- (NSArray *)installedPlugins;
@end

@interface LSBundleProxy : NSObject
- (NSString *)bundleIdentifier;
@end

@interface LSPlugInKitProxy : LSBundleProxy
- (NSString *)pluginIdentifier;
- (LSBundleProxy *)containingBundle;
@end

static void *FindSymbol(const char *image, const char *symbol) {
    if (!symbol) return NULL;
    if (image) {
        void *handle = dlopen(image, RTLD_NOW);
        if (!handle) return dlsym(RTLD_DEFAULT, symbol);
        return dlsym(handle, symbol);
    }
    return dlsym(RTLD_DEFAULT, symbol);
}

static BOOL PXStrEqNoCase(const char *a, const char *b) {
    if (!a || !b) return NO;
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return NO;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

static BOOL PXHasPrefix(const char *s, const char *prefix) {
    if (!s || !prefix) return NO;
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0;
}

static BOOL PXHasPrefixNoCase(const char *s, const char *prefix) {
    if (!s || !prefix) return NO;
    while (*prefix) {
        char a = *s;
        char b = *prefix;
        if (!a) return NO;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return NO;
        s++; prefix++;
    }
    return YES;
}

static NSString *PXMainBundleID(void) {
    static NSString *bid = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        bid = [[NSBundle mainBundle] bundleIdentifier];
    });
    return bid;
}

static BOOL PXJBIsCriticalProcess(void) {
    static BOOL computed = NO;
    static BOOL isCritical = NO;
    if (computed) return isCritical;
    computed = YES;
    NSString *p = [NSProcessInfo processInfo].processName;
    if ([p isEqualToString:@"launchd"] || [p isEqualToString:@"SpringBoard"] || [p isEqualToString:@"backboardd"]) {
        isCritical = YES;
    }
    return isCritical;
}

static volatile BOOL gJBEnabled = NO;
static volatile BOOL gJBStatfsEnabled = NO;
static volatile BOOL gJBHideDylibsEnabled = NO;
static volatile BOOL gJBSyscallHookEnabled = NO;
static volatile BOOL gJBBlockDyldAddImageCallbacksEnabled = NO;
static volatile BOOL gJBHideTaskDyldInfoEnabled = NO;
static volatile BOOL gJBHideDlIteratePhdrEnabled = NO;
static volatile BOOL gJBBlockDlopenDlsymProbesEnabled = NO;
static volatile BOOL gJBSysctlProcSanitizeEnabled = NO;
static volatile BOOL gJBHideProcMapsEnabled = NO;
static volatile BOOL gJBHideObjcImagesEnabled = NO;
static volatile BOOL gJBHookSandboxCheckEnabled = NO;
static volatile BOOL gJBHookFstatPathEnabled = NO;
static volatile BOOL gJBHookGetattrlistEnabled = NO;
static volatile BOOL gJBHookExecEnabled = NO;
static volatile BOOL gJBHideProcInfoEnabled = NO;
static volatile BOOL gJBDebugLoggingEnabled = NO;
static volatile CFTimeInterval gJBLastCheck = 0;
// A5: Static toggles (the jbBypass* flags) change only when the user edits
// settings and the app relaunches; they do not need to be re-read every
// cache cycle. We load them once via dispatch_once. The hot 1-second cache
// then only re-evaluates gJBEnabled (which depends on isApplicationEnabled).
// NOTE: the gJB*Enabled flags are plain volatile BOOLs read without atomics
// from arbitrary threads. Since they are written once (dispatch_once) before
// most hooks run, and are simple booleans, torn reads are not a concern.
static void PXJBLoadStaticTogglesOnce(NSUserDefaults *securitySettings) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gJBStatfsEnabled = [securitySettings boolForKey:@"jbBypassStatfsEnabled"];
        gJBHideDylibsEnabled = [securitySettings boolForKey:@"jbBypassHideDylibsEnabled"];
        gJBSyscallHookEnabled = [securitySettings boolForKey:@"jbBypassHookSyscallFallbackEnabled"];
        gJBBlockDyldAddImageCallbacksEnabled = [securitySettings boolForKey:@"jbBypassBlockDyldAddImageCallbacksEnabled"];
        gJBHideTaskDyldInfoEnabled = [securitySettings boolForKey:@"jbBypassHideTaskDyldInfoEnabled"];
        gJBHideDlIteratePhdrEnabled = [securitySettings boolForKey:@"jbBypassHideDlIteratePhdrEnabled"];
        gJBBlockDlopenDlsymProbesEnabled = [securitySettings boolForKey:@"jbBypassBlockDlopenDlsymProbesEnabled"];
        gJBSysctlProcSanitizeEnabled = [securitySettings boolForKey:@"jbBypassSysctlProcSanitizeEnabled"];
        gJBHideProcMapsEnabled = [securitySettings boolForKey:@"jbBypassHideProcMapsEnabled"];
        gJBHideObjcImagesEnabled = [securitySettings boolForKey:@"jbBypassHideObjcImagesEnabled"];
        gJBHookSandboxCheckEnabled = [securitySettings boolForKey:@"jbBypassHookSandboxCheckEnabled"];
        gJBHookFstatPathEnabled = [securitySettings boolForKey:@"jbBypassHookFstatPathEnabled"];
        gJBHookGetattrlistEnabled = [securitySettings boolForKey:@"jbBypassHookGetattrlistEnabled"];
        gJBHookExecEnabled = [securitySettings boolForKey:@"jbBypassHookExecEnabled"];
        gJBHideProcInfoEnabled = [securitySettings boolForKey:@"jbBypassHideProcInfoEnabled"];
        gJBDebugLoggingEnabled = [securitySettings boolForKey:@"jbBypassDebugLoggingEnabled"];
    });
}

static BOOL PXJBShouldBypassCached(void) {
    if (PXJBIsCriticalProcess()) return NO;
    CFTimeInterval now = CFAbsoluteTimeGetCurrent();
    if (now - gJBLastCheck < 1.0) {
        return gJBEnabled;
    }
    gJBLastCheck = now;

    @autoreleasepool {
        NSString *bundleID = PXMainBundleID();
        if (!bundleID.length) {
            gJBEnabled = NO;
            return gJBEnabled;
        }
        if ([bundleID isEqualToString:@"com.hydra.projectx"]) {
            gJBEnabled = NO;
            return gJBEnabled;
        }
        if ([bundleID hasPrefix:@"com.apple."]) {
            gJBEnabled = NO;
            return gJBEnabled;
        }

        NSUserDefaults *securitySettings = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
        BOOL enabled = [securitySettings boolForKey:@"jailbreakDetectionEnabled"];
        if (!enabled) {
            gJBEnabled = NO;
            gJBStatfsEnabled = NO;
            return gJBEnabled;
        }

        // Load the static jbBypass* toggles exactly once.
        PXJBLoadStaticTogglesOnce(securitySettings);

        Class mgrCls = NSClassFromString(@"IdentifierManager");
        if (!mgrCls || ![mgrCls respondsToSelector:@selector(sharedManager)]) {
            gJBEnabled = NO;
            return gJBEnabled;
        }
        IdentifierManager *mgr = [mgrCls performSelector:@selector(sharedManager)];
        if (!mgr || ![mgr respondsToSelector:@selector(isApplicationEnabled:)]) {
            gJBEnabled = NO;
            return gJBEnabled;
        }
        gJBEnabled = [mgr isApplicationEnabled:bundleID];
        return gJBEnabled;
    }
}

static BOOL PXJBStatfsBypassEnabled(void) {
    return PXJBShouldBypassCached() && gJBStatfsEnabled;
}

static BOOL PXJBHideDylibsEnabled(void) {
    return PXJBShouldBypassCached() && gJBHideDylibsEnabled;
}

// Forward declaration (defined later in dyld section).
static BOOL PXStrContainsNoCase(const char *haystack, const char *needle);

static BOOL PXJBBlockDyldAddImageCallbacksEnabled(void) {
    return PXJBShouldBypassCached() && gJBBlockDyldAddImageCallbacksEnabled;
}

static BOOL PXJBHideTaskDyldInfoEnabled(void) {
    return PXJBShouldBypassCached() && gJBHideTaskDyldInfoEnabled;
}

static BOOL PXJBHideDlIteratePhdrEnabled(void) {
    return PXJBShouldBypassCached() && gJBHideDlIteratePhdrEnabled;
}

static BOOL PXJBBlockDlopenDlsymProbesEnabled(void) {
    return PXJBShouldBypassCached() && gJBBlockDlopenDlsymProbesEnabled;
}

static BOOL PXJBSysctlProcSanitizeEnabled(void) {
    return PXJBShouldBypassCached() && gJBSysctlProcSanitizeEnabled;
}

static BOOL PXJBHideProcMapsEnabled(void) {
    return PXJBShouldBypassCached() && gJBHideProcMapsEnabled;
}

static BOOL PXJBHideObjcImagesEnabled(void) {
    return PXJBShouldBypassCached() && gJBHideObjcImagesEnabled;
}

static BOOL PXJBHookSandboxCheckEnabled(void) {
    return PXJBShouldBypassCached() && gJBHookSandboxCheckEnabled;
}

static BOOL PXJBHookFstatPathEnabled(void) {
    return PXJBShouldBypassCached() && gJBHookFstatPathEnabled;
}

static BOOL PXJBHookGetattrlistEnabled(void) {
    return PXJBShouldBypassCached() && gJBHookGetattrlistEnabled;
}

static BOOL PXJBHookExecEnabled(void) {
    return PXJBShouldBypassCached() && gJBHookExecEnabled;
}

static BOOL PXJBHideProcInfoEnabled(void) {
    return PXJBShouldBypassCached() && gJBHideProcInfoEnabled;
}

static BOOL PXJBDebugLoggingEnabled(void) {
    return PXJBShouldBypassCached() && gJBDebugLoggingEnabled;
}

static void PXJBLogBlockedOncePerSecond(const char *what, const char *detail) {
    if (!PXJBDebugLoggingEnabled()) return;
    static CFTimeInterval last = 0;
    CFTimeInterval now = CFAbsoluteTimeGetCurrent();
    if ((now - last) < 1.0) return;
    last = now;
    if (!what) what = "(unknown)";
    if (!detail) detail = "";
    PXLog(@"[JailbreakBypass][debug] blocked %s %s", what, detail);
}

static BOOL PXJBSyscallBypassEnabled(void) {
    return PXJBShouldBypassCached() && gJBSyscallHookEnabled;
}

// Path matching
static BOOL PXJBIsHiddenExactPath(const char *path) {
    if (!path) return NO;
    static const char *kExact[] = {
        // Jailbreak package managers / apps
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Filza.app",
        "/Applications/Installer.app",
        "/Applications/RockApp.app",
        "/Applications/Icy.app",
        "/Applications/WinterBoard.app",
        "/Applications/SBSettings.app",
        "/Applications/MxTube.app",
        "/Applications/IntelliScreen.app",
        "/Applications/FakeCarrier.app",
        "/Applications/blackra1n.app",
        "/Applications/Dopamine.app",
        "/Applications/Th0r.app",
        "/Applications/iFile.app",
        "/Applications/Terminal.app",
        "/Applications/NewTerm.app",
        
        // MobileSubstrate files
        "/Library/MobileSubstrate/DynamicLibraries/0Cr4shed.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/libappstoreplus.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/ Crane.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/ProjectXTweak.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/FilzaHack.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/Library/dpkg/info/mobilesubstrate.md5sums",
        "/Library/dpkg/status", 
        "/private/var/binpack/Applications/loader.app",      

        // Substrate/hooking libs
        "/usr/lib/substrate/SubstrateBootstrap.dylib",
        "/usr/lib/substrate/SubstrateLoader.dylib",
        "/usr/lib/substrate/SubstrateInserter.dylib",

        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/libmryipc.dylib",
        "/usr/lib/libFrida.dylib",
        "/usr/lib/libcycript.dylib",
        "/usr/lib/libjailbreak.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/TweakInject.dylib",
        "/usr/lib/ellekit/libinjector.dylib",
        "/usr/lib/libellekit.dylib",
        
        // Frameworks
        "/Library/Frameworks/CydiaSubstrate.framework",
        "/Library/PreferenceBundles",
        "/Library/PreferenceLoader",
        
        // SSH / shell tools
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "/usr/bin/sftp",
        "/usr/sbin/sshd",
        "/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/usr/bin/cycript",
        "/usr/bin/dpkg",
        "/usr/bin/apt",
        "/usr/bin/apt-get",
        
        // SSH support files
        "/usr/libexec/cydia",
        "/usr/libexec/sftp-server",
        "/usr/libexec/ssh-keysign",
        
        // Common directories
        "/etc/apt",
        "/private/etc/apt",
        "/etc/ssh",
        "/private/etc/ssh",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/var/cache/apt",
        "/var/log/syslog",
        "/var/tmp/cydia.log",
        "/Library/dpkg",
        "/private/var/binpack",
        
        // Jailbreak markers / files
        "/var/checkra1n.dmg",
        "/var/binpack",
        "/.bootstrapped_electra",
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/.installed_taurine",
        "/.installed_odyssey",
        "/.installed_chimera",
        "/.installed_dopamine",
        "/.installed_palera1n",
        "/private/var/stash",
        
        // Frida detection paths
        "/usr/sbin/frida-server",
        "/usr/lib/frida/frida-agent.dylib",
        
        // LaunchDaemons used for detection
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        
        // Write test paths
        "/private/jailbreak_test",
        "/private/var/jailbreak_test",
        
        // Rootless jailbreak specific
        "/var/jb",
        "/var/jb/Applications",
        "/var/jb/usr",
        "/var/jb/Library",
        "/private/preboot",
        
        NULL
    };
    for (int i = 0; kExact[i]; i++) {
        if (strcmp(path, kExact[i]) == 0) return YES;
    }
    return NO;
}

static BOOL PXJBIsHiddenPrefixPath(const char *path) {
    if (!path) return NO;
    static const char *kPrefixes[] = {
        // Substrate/hooking framework paths
        "/usr/lib/substrate/",
        "/usr/lib/TweakInject/",
        "/usr/lib/ellekit/",
        "/usr/lib/substitute/",
        "/usr/lib/libhooker/",
        
        // MobileSubstrate paths
        "/Library/MobileSubstrate/",
        "/private/var/Library/MobileSubstrate/",
        "/private/var/mobile/Library/MobileSubstrate/",
        
        // Cydia cache injection paths
        "/Library/Caches/cy-",
        "/private/var/Library/Caches/cy-",
        "/private/var/mobile/Library/Caches/cy-",
        
        // Library paths
        "/Library/Frameworks/CydiaSubstrate.framework/",
        "/Library/PreferenceBundles/",
        "/Library/PreferenceLoader/",
        "/Library/dpkg/info/",
        "/Library/Themes/",
        "/Library/Ringtones/",
        "/Library/Wallpaper/",
        
        // Rootless jailbreak paths (Dopamine, palera1n, etc.)
        "/var/jb/",
        "/private/var/jb/",
        "/var/jb/Applications/",
        "/var/jb/usr/",
        "/var/jb/Library/",
        "/var/jb/bin/",
        "/var/jb/sbin/",
        "/var/jb/etc/",
        
        // Preboot jailbreak paths
        "/private/preboot/jb/",
        "/private/preboot/",
        
        // Package manager paths
        "/var/lib/apt/",
        "/private/var/lib/apt/",
        "/var/cache/apt/",
        "/private/var/cache/apt/",
        "/var/lib/dpkg/",
        "/private/var/lib/dpkg/",
        
        // Cydia temp/log paths
        "/var/tmp/cydia",
        "/private/var/tmp/cydia",
        
        // Stash paths (older jailbreaks)
        "/private/var/stash/",
        "/var/stash/",
        
        // Frida paths
        "/usr/lib/frida/",
        
        // procursus (modern package set)
        "/var/jb/procursus/",
        
        // ElleKit injection
        "/var/jb/usr/lib/ellekit/",

        // Additional prefixes found from sandbox logs (MB Bank / VNID)
        "/etc/apt/",
        "/private/etc/apt/",
        "/etc/ssh/",
        "/private/etc/ssh/",
        "/Library/dpkg/",
        "/private/var/binpack/",
        "/usr/libexec/cydia/",
        
        NULL
    };
    for (int i = 0; kPrefixes[i]; i++) {
        if (PXHasPrefix(path, kPrefixes[i])) return YES;
    }
    return NO;
}

static BOOL PXJBPathShouldHide(const char *path) {
    if (!path) return NO;
    if (path[0] != '/') return NO;
    // Quick exact/prefix checks.
    if (PXJBIsHiddenExactPath(path)) return YES;
    if (PXJBIsHiddenPrefixPath(path)) return YES;
    return NO;
}

static BOOL PXJBIsWriteAttempt(int flags) {
    if (flags & O_CREAT) return YES;
    if (flags & O_TRUNC) return YES;
    if ((flags & O_ACCMODE) == O_WRONLY) return YES;
    if ((flags & O_ACCMODE) == O_RDWR) return YES;
    return NO;
}

static BOOL PXJBIsSandboxAllowedWritePath(const char *path) {
    if (!path) return NO;
    // Allow normal sandbox container paths.
    if (PXHasPrefix(path, "/var/mobile/Containers/")) return YES;
    if (PXHasPrefix(path, "/private/var/mobile/Containers/")) return YES;
    if (PXHasPrefix(path, "/containers/Data/")) return YES;
    if (PXHasPrefix(path, "/private/var/containers/")) return YES;
    return NO;
}

static BOOL PXJBWriteCheckShouldBlock(const char *path, int flags) {
    if (!path) return NO;
    if (!PXJBIsWriteAttempt(flags)) return NO;
    // Only block classic jailbreak write-probe targets and obvious restricted prefixes.
    if (PXJBIsSandboxAllowedWritePath(path)) return NO;
    if (PXHasPrefix(path, "/private/jailbreak_test")) return YES;
    if (PXHasPrefix(path, "/private/var/jailbreak_test")) return YES;
    if (PXHasPrefix(path, "/var/tmp/cydia")) return YES;
    if (PXHasPrefix(path, "/private/var/tmp/cydia")) return YES;
    return NO;
}

// Loopback port scan blocking
static BOOL PXJBIsDeniedLoopbackPort(uint16_t port) {
    switch (port) {
        case 22:      // ssh
        case 44:      // historically used by some detectors
        case 27042:   // frida
        case 4444:
        case 5555:
            return YES;
        default:
            return NO;
    }
}

// --- C hooks ---
static int (*orig_stat)(const char *, struct stat *);
static int hook_stat(const char *path, struct stat *st) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, st) : -1;
}

static int (*orig_stat64)(const char *, struct stat *);
static int hook_stat64(const char *path, struct stat *st) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat64 ? orig_stat64(path, st) : -1;
}

static int (*orig_lstat)(const char *, struct stat *);
static int hook_lstat(const char *path, struct stat *st) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, st) : -1;
}

static int (*orig_lstat64)(const char *, struct stat *);
static int hook_lstat64(const char *path, struct stat *st) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat64 ? orig_lstat64(path, st) : -1;
}

static int (*orig_access)(const char *, int);
static int hook_access(const char *path, int amode) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, amode) : -1;
}

static int (*orig_open)(const char *, int, ...);
static int hook_open(const char *path, int oflag, ...) {
    if (PXJBShouldBypassCached()) {
        if (PXJBPathShouldHide(path)) {
            errno = ENOENT;
            return -1;
        }
        if (PXJBWriteCheckShouldBlock(path, oflag)) {
            errno = EACCES;
            return -1;
        }
    }

    int mode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return orig_open ? orig_open(path, oflag, mode) : -1;
}

static int (*orig_openat)(int, const char *, int, ...);

static BOOL PXJBRelativePathLooksLikeProbe(const char *path) {
    if (!path) return NO;
    // Keep this list tight to avoid false positives.
    static const char *needles[] = {
        "mobilesubstrate",
        "cydia.app",
        "sileo.app",
        "zebra.app",
        "filza.app",
        "preferenceloader",
        "preferencebundles",
        "var/jb",
        "library/caches/cy-",
        "substrate",
        "ellekit",
        "libhooker",
        "frida",
        NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (PXStrContainsNoCase(path, needles[i])) return YES;
    }
    return NO;
}

static BOOL PXJBNormalizeAbsolutePath(const char *inPath, char *out, size_t outsz) {
    if (!inPath || !out || outsz < 2) return NO;
    if (inPath[0] != '/') return NO;

    size_t w = 0;
    out[w++] = '/';

    const char *p = inPath;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t segLen = (size_t)(p - seg);
        if (segLen == 1 && seg[0] == '.') {
            continue;
        }
        if (segLen == 2 && seg[0] == '.' && seg[1] == '.') {
            // pop last segment
            if (w > 1) {
                // remove trailing slash if any
                if (out[w - 1] == '/' && w > 1) w--;
                while (w > 1 && out[w - 1] != '/') w--;
            }
            continue;
        }
        // append segment
        if (w > 1 && out[w - 1] != '/') {
            if (w + 1 >= outsz) return NO;
            out[w++] = '/';
        }
        if (w + segLen + 1 >= outsz) return NO;
        memcpy(out + w, seg, segLen);
        w += segLen;
        out[w] = '\0';
    }

    if (w == 0) {
        out[0] = '/';
        out[1] = '\0';
    } else {
        out[w] = '\0';
    }
    return YES;
}

// Re-entrancy guard for getcwd-based resolution.
// getcwd() may internally call open()/stat()/__getcwd, which we hook. Without
// a guard, hook_openat -> PXJBJoinCwdAndNormalize -> getcwd -> hook_open(at)
// could recurse or add cost on a hot path. We use a thread-local flag so the
// resolver is skipped if we're already inside it on this thread.
static pthread_key_t gPXJBCwdGuardKey;
static pthread_once_t gPXJBCwdGuardOnce = PTHREAD_ONCE_INIT;
static void PXJBCwdGuardKeyInit(void) {
    pthread_key_create(&gPXJBCwdGuardKey, NULL);
}
static BOOL PXJBCwdGuardEnter(void) {
    pthread_once(&gPXJBCwdGuardOnce, PXJBCwdGuardKeyInit);
    if (pthread_getspecific(gPXJBCwdGuardKey) != NULL) {
        return NO; // already inside on this thread
    }
    pthread_setspecific(gPXJBCwdGuardKey, (void *)1);
    return YES;
}
static void PXJBCwdGuardLeave(void) {
    pthread_setspecific(gPXJBCwdGuardKey, NULL);
}

static BOOL PXJBJoinCwdAndNormalize(const char *relPath, char *out, size_t outsz) {
    if (!relPath || !out || outsz < 2) return NO;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return NO;
    size_t cwdLen = strlen(cwd);
    size_t relLen = strlen(relPath);
    if (cwdLen == 0 || cwd[0] != '/') return NO;

    char tmp[PATH_MAX];
    size_t need = cwdLen + 1 + relLen + 1;
    if (need >= sizeof(tmp)) return NO;
    memcpy(tmp, cwd, cwdLen);
    tmp[cwdLen] = '/';
    memcpy(tmp + cwdLen + 1, relPath, relLen);
    tmp[cwdLen + 1 + relLen] = '\0';
    return PXJBNormalizeAbsolutePath(tmp, out, outsz);
}

static int hook_openat(int fd, const char *path, int oflag, ...) {
    if (PXJBShouldBypassCached()) {
        if (path) {
            if (path[0] == '/') {
                if (PXJBPathShouldHide(path)) {
                    PXJBLogBlockedOncePerSecond("openat", path);
                    errno = ENOENT;
                    return -1;
                }
                if (PXJBWriteCheckShouldBlock(path, oflag)) {
                    PXJBLogBlockedOncePerSecond("openat(write)", path);
                    errno = EACCES;
                    return -1;
                }
            } else {
#ifndef AT_FDCWD
#define AT_FDCWD (-2)
#endif
                if (fd == AT_FDCWD) {
                    char normalized[PATH_MAX];
                    BOOL guardOk = PXJBCwdGuardEnter();
                    BOOL resolved = guardOk && PXJBJoinCwdAndNormalize(path, normalized, sizeof(normalized));
                    if (guardOk) PXJBCwdGuardLeave();
                    if (resolved) {
                        if (PXJBPathShouldHide(normalized)) {
                            PXJBLogBlockedOncePerSecond("openat", normalized);
                            errno = ENOENT;
                            return -1;
                        }
                        if (PXJBWriteCheckShouldBlock(normalized, oflag)) {
                            PXJBLogBlockedOncePerSecond("openat(write)", normalized);
                            errno = EACCES;
                            return -1;
                        }
                    } else if (PXJBRelativePathLooksLikeProbe(path)) {
                        PXJBLogBlockedOncePerSecond("openat(rel)", path);
                        errno = ENOENT;
                        return -1;
                    }
                } else {
                    // Don't try to resolve fd->path (avoid side effects). Only block obvious probes.
                    if (PXJBRelativePathLooksLikeProbe(path)) {
                        PXJBLogBlockedOncePerSecond("openat(relfd)", path);
                        errno = ENOENT;
                        return -1;
                    }
                }
            }
        }
    }

    int mode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return orig_openat ? orig_openat(fd, path, oflag, mode) : -1;
}

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hook_fopen(const char *path, const char *mode) {
    if (PXJBShouldBypassCached()) {
        if (PXJBPathShouldHide(path)) {
            errno = ENOENT;
            return NULL;
        }
        if (path && mode) {
            // If mode implies write.
            if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) {
                int flags = O_WRONLY | O_CREAT;
                if (PXJBWriteCheckShouldBlock(path, flags)) {
                    errno = EACCES;
                    return NULL;
                }
            }
        }
    }
    return orig_fopen ? orig_fopen(path, mode) : NULL;
}

static DIR *(*orig_opendir)(const char *);
static DIR *hook_opendir(const char *path) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir ? orig_opendir(path) : NULL;
}

// A6: readdir now hides entries by building the full path of each entry and
// running it through PXJBPathShouldHide, instead of a hardcoded 4-name list.
// To avoid resolving the directory's path on every entry (readdir is called
// once per entry), we resolve DIR* -> dir path once via dirfd()+F_GETPATH and
// cache it per DIR*. The cache is a tiny fixed ring keyed by the DIR pointer.
//
// PERF/RISK NOTE: the per-DIR resolve costs one fcntl(F_GETPATH) the first
// time we see a given DIR*; subsequent entries reuse the cached path. The
// cache is intentionally small and lock-protected to stay thread-safe without
// adding meaningful overhead on the listing hot path.
#define PXJB_DIRPATH_CACHE_SLOTS 16
typedef struct {
    DIR *dirp;
    char path[PATH_MAX];
} PXJBDirPathEntry;
static PXJBDirPathEntry gPXJBDirPathCache[PXJB_DIRPATH_CACHE_SLOTS];
static uint32_t gPXJBDirPathNext = 0;
static pthread_mutex_t gPXJBDirPathLock = PTHREAD_MUTEX_INITIALIZER;

static BOOL PXJBResolveDirPath(DIR *dirp, char *out, size_t outsz) {
    if (!dirp || !out || outsz < 2) return NO;
    pthread_mutex_lock(&gPXJBDirPathLock);
    for (int i = 0; i < PXJB_DIRPATH_CACHE_SLOTS; i++) {
        if (gPXJBDirPathCache[i].dirp == dirp && gPXJBDirPathCache[i].path[0]) {
            strlcpy(out, gPXJBDirPathCache[i].path, outsz);
            pthread_mutex_unlock(&gPXJBDirPathLock);
            return YES;
        }
    }
    pthread_mutex_unlock(&gPXJBDirPathLock);

    int fd = dirfd(dirp);
    if (fd < 0) return NO;
    char resolved[PATH_MAX];
    resolved[0] = '\0';
    if (fcntl(fd, F_GETPATH, resolved) != 0 || !resolved[0]) return NO;

    pthread_mutex_lock(&gPXJBDirPathLock);
    uint32_t slot = gPXJBDirPathNext % PXJB_DIRPATH_CACHE_SLOTS;
    gPXJBDirPathNext++;
    gPXJBDirPathCache[slot].dirp = dirp;
    strlcpy(gPXJBDirPathCache[slot].path, resolved, sizeof(gPXJBDirPathCache[slot].path));
    pthread_mutex_unlock(&gPXJBDirPathLock);

    strlcpy(out, resolved, outsz);
    return YES;
}

static struct dirent *(*orig_readdir)(DIR *);
static struct dirent *hook_readdir(DIR *dirp) {
    if (!orig_readdir) return NULL;
    struct dirent *ent = orig_readdir(dirp);
    if (!PXJBShouldBypassCached()) return ent;

    char dirpath[PATH_MAX];
    BOOL haveDir = PXJBResolveDirPath(dirp, dirpath, sizeof(dirpath));

    while (ent) {
        const char *n = ent->d_name;
        if (n && !(n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0')))) {
            BOOL hide = NO;
            if (haveDir) {
                char full[PATH_MAX];
                int w = snprintf(full, sizeof(full), "%s/%s", dirpath, n);
                if (w > 0 && (size_t)w < sizeof(full) && PXJBPathShouldHide(full)) {
                    hide = YES;
                }
            }
            // Fallback to name-only check when the dir path could not be resolved.
            if (!hide && !haveDir && PXJBPathShouldHide(n)) {
                hide = YES;
            }
            if (hide) {
                ent = orig_readdir(dirp);
                continue;
            }
        }
        break;
    }
    return ent;
}

static ssize_t (*orig_readlink)(const char *, char *, size_t);
static ssize_t hook_readlink(const char *path, char *buf, size_t bufsiz) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_readlink ? orig_readlink(path, buf, bufsiz) : -1;
}

static char *(*orig_realpath)(const char *, char *);
static char *hook_realpath(const char *path, char *resolved) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_realpath ? orig_realpath(path, resolved) : NULL;
}

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (PXJBShouldBypassCached() && addr) {
        if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
            uint32_t ip = ntohl(a->sin_addr.s_addr);
            uint16_t port = ntohs(a->sin_port);
            if (ip == INADDR_LOOPBACK && PXJBIsDeniedLoopbackPort(port)) {
                errno = ECONNREFUSED;
                return -1;
            }
        } else if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
            uint16_t port = ntohs(a6->sin6_port);
            static const struct in6_addr loop = IN6ADDR_LOOPBACK_INIT;
            if (memcmp(&a6->sin6_addr, &loop, sizeof(loop)) == 0 && PXJBIsDeniedLoopbackPort(port)) {
                errno = ECONNREFUSED;
                return -1;
            }
        }
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
}

static char *(*orig_getenv)(const char *);
static char *hook_getenv(const char *name) {
    if (PXJBShouldBypassCached() && name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
            strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
            strcmp(name, "DYLD_FRAMEWORK_PATH") == 0 ||
            strcmp(name, "DYLD_FALLBACK_LIBRARY_PATH") == 0 ||
            strcmp(name, "DYLD_FALLBACK_FRAMEWORK_PATH") == 0 ||
            strcmp(name, "DYLD_ROOT_PATH") == 0 ||
            strcmp(name, "DYLD_SHARED_CACHE_DIR") == 0 ||
            strcmp(name, "DYLD_PRINT_TO_FILE") == 0 ||
            strcmp(name, "DYLD_PRINT_LIBRARIES") == 0 ||
            strcmp(name, "DYLD_PRINT_APIS") == 0 ||
            strcmp(name, "DYLD_PRINT_OPTS") == 0 ||
            strcmp(name, "DYLD_PRINT_ENV") == 0 ||
            strcmp(name, "LD_PRELOAD") == 0 ||
            strcmp(name, "_MSSafeMode") == 0 ||
            strcmp(name, "JB_SANDBOX_EXTENSIONS") == 0 ||
            strcmp(name, "SHELL") == 0) {
            return NULL;
        }
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

static void PXJBUnsetSuspiciousEnvIfNeeded(void) {
    if (!PXJBShouldBypassCached()) return;
    // Proactive cleanup so detectors reading env via non-getenv paths see a clean environment.
    // Low risk: only affects this process.
    const char *keys[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_ROOT_PATH",
        "DYLD_SHARED_CACHE_DIR",
        "DYLD_PRINT_TO_FILE",
        "DYLD_PRINT_LIBRARIES",
        "DYLD_PRINT_APIS",
        "DYLD_PRINT_OPTS",
        "DYLD_PRINT_ENV",
        "LD_PRELOAD",
        "_MSSafeMode",
        "MSDebug",
        "JB_SANDBOX_EXTENSIONS",
        NULL
    };
    for (int i = 0; keys[i]; i++) {
        unsetenv(keys[i]);
    }
}

// Phase 2: anti-debug / anti-exec probes
static int (*orig_ptrace)(int request, pid_t pid, void *addr, int data);
static int hook_ptrace(int request, pid_t pid, void *addr, int data) {
    if (PXJBShouldBypassCached()) {
        // PT_DENY_ATTACH == 31 on Darwin.
        if (request == PT_DENY_ATTACH || request == 31) {
            return 0;
        }
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : -1;
}

static pid_t (*orig_fork)(void);
static pid_t hook_fork(void) {
    if (PXJBShouldBypassCached()) {
        errno = EPERM;
        return (pid_t)-1;
    }
    return orig_fork ? orig_fork() : (pid_t)-1;
}

static pid_t (*orig_vfork)(void);
static pid_t hook_vfork(void) {
    if (PXJBShouldBypassCached()) {
        errno = EPERM;
        return (pid_t)-1;
    }
    return orig_vfork ? orig_vfork() : (pid_t)-1;
}

// Hook syscall() as a fallback when apps bypass libc wrappers.
//
// RISK NOTE (EXPERIMENTAL, default OFF):
// syscall() is fully variadic with no portable way to know the real arg
// count for an arbitrary syscall number. The previous implementation read
// 6 varargs unconditionally for EVERY syscall, which is undefined behavior
// when the real syscall takes fewer args. We now:
//   1. Only read the exact number of args each WHITELISTED syscall uses
//      (the ones we actually inspect: open/stat/lstat/access/openat).
//   2. For every other syscall, forward by re-reading 6 slots and passing
//      them through. This is still technically an over-read for short
//      syscalls, but on arm64 these slots come from registers, so it is
//      effectively benign. This path only runs when the toggle is enabled.
// Because there is no fully ABI-conforming generic forwarder for variadic
// syscall(), this hook stays EXPERIMENTAL and OFF by default.
static long (*orig_syscall)(long number, ...);

static BOOL PXJBSyscallIsInspected(int number) {
    switch (number) {
        case SYS_stat:
        case SYS_lstat:
        case SYS_access:
        case SYS_open:
        case SYS_openat:
#ifdef SYS_stat64
        case SYS_stat64:
#endif
#ifdef SYS_lstat64
        case SYS_lstat64:
#endif
            return YES;
        default:
            return NO;
    }
}

static long hook_syscall(long number, ...) {
    if (!orig_syscall) {
        errno = ENOSYS;
        return -1;
    }

    int n = (int)number;

    // Fast path: not enabled, or a syscall we never inspect. Forward by
    // capturing 6 generic slots (register-backed on arm64) and passing through.
    if (!PXJBSyscallBypassEnabled() || !PXJBSyscallIsInspected(n)) {
        uint64_t a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;
        va_list ap;
        va_start(ap, number);
        a1 = (uint64_t)va_arg(ap, uint64_t);
        a2 = (uint64_t)va_arg(ap, uint64_t);
        a3 = (uint64_t)va_arg(ap, uint64_t);
        a4 = (uint64_t)va_arg(ap, uint64_t);
        a5 = (uint64_t)va_arg(ap, uint64_t);
        a6 = (uint64_t)va_arg(ap, uint64_t);
        va_end(ap);
        return orig_syscall(number, a1, a2, a3, a4, a5, a6);
    }

    // Inspected syscalls: read only the args each one actually defines.
    va_list ap;
    va_start(ap, number);

    switch (n) {
        case SYS_stat:
        case SYS_lstat:
        case SYS_access:
#ifdef SYS_stat64
        case SYS_stat64:
#endif
#ifdef SYS_lstat64
        case SYS_lstat64:
#endif
        {
            // (const char *path, <buf|mode>)
            uint64_t a1 = (uint64_t)va_arg(ap, uint64_t);
            uint64_t a2 = (uint64_t)va_arg(ap, uint64_t);
            va_end(ap);
            const char *path = (const char *)(uintptr_t)a1;
            if (PXJBPathShouldHide(path)) {
                errno = ENOENT;
                return -1;
            }
            return orig_syscall(number, a1, a2);
        }

        case SYS_open: {
            // (const char *path, int flags, mode_t mode)
            uint64_t a1 = (uint64_t)va_arg(ap, uint64_t);
            uint64_t a2 = (uint64_t)va_arg(ap, uint64_t);
            uint64_t a3 = (uint64_t)va_arg(ap, uint64_t);
            va_end(ap);
            const char *path = (const char *)(uintptr_t)a1;
            if (PXJBPathShouldHide(path)) {
                errno = ENOENT;
                return -1;
            }
            if (PXJBWriteCheckShouldBlock(path, (int)a2)) {
                errno = EACCES;
                return -1;
            }
            return orig_syscall(number, a1, a2, a3);
        }

        case SYS_openat: {
            // (int fd, const char *path, int flags, mode_t mode)
            uint64_t a1 = (uint64_t)va_arg(ap, uint64_t);
            uint64_t a2 = (uint64_t)va_arg(ap, uint64_t);
            uint64_t a3 = (uint64_t)va_arg(ap, uint64_t);
            uint64_t a4 = (uint64_t)va_arg(ap, uint64_t);
            va_end(ap);
            const char *path = (const char *)(uintptr_t)a2;
            if (path && path[0] == '/' && PXJBPathShouldHide(path)) {
                errno = ENOENT;
                return -1;
            }
            if (path && path[0] == '/' && PXJBWriteCheckShouldBlock(path, (int)a3)) {
                errno = EACCES;
                return -1;
            }
            return orig_syscall(number, a1, a2, a3, a4);
        }

        default:
            // Unreachable (PXJBSyscallIsInspected gated above), but stay safe.
            va_end(ap);
            return orig_syscall(number);
    }
}

// Block common jailbreak probe commands executed via system()/popen().
static BOOL PXJBCommandLooksLikeProbe(NSString *cmd) {
    if (![cmd isKindOfClass:[NSString class]] || cmd.length == 0) return NO;
    NSString *c = [[cmd lowercaseString] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!c.length) return NO;

    // Avoid overly broad substring checks that can break legitimate commands.
    // Only treat as a probe when we see explicit jailbreak tool paths/binaries.
    NSArray<NSString *> *pathNeedles = @[
        @"/applications/cydia.app",
        @"/applications/sileo.app",
        @"/applications/zebra.app",
        @"/applications/filza.app",
        @"/library/mobilesubstrate",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/var/lib/apt",
        @"/var/lib/cydia",
        @"/var/jb",
        @"/private/preboot/jb",
        @"frida-server",
        @"fridagadget",
        @"cycript",
        @"uicache",
        @"ldrestart"
    ];
    for (NSString *n in pathNeedles) {
        if ([c containsString:n]) return YES;
    }

    // Token checks for package managers (match whole tokens only).
    // This avoids false positives like "capture" containing "apt".
    NSCharacterSet *seps = [NSCharacterSet characterSetWithCharactersInString:@" \t\r\n;|&()<>\"'\\"];
    NSArray<NSString *> *tokens = [c componentsSeparatedByCharactersInSet:seps];
    for (NSString *t in tokens) {
        if (!t.length) continue;
        if ([t isEqualToString:@"apt"] || [t isEqualToString:@"apt-get"] || [t isEqualToString:@"dpkg"]) {
            return YES;
        }
    }
    return NO;
}

static int (*orig_system)(const char *);
static int hook_system(const char *command) {
    if (PXJBShouldBypassCached() && command) {
        NSString *cmd = [NSString stringWithUTF8String:command] ?: @"";
        if (PXJBCommandLooksLikeProbe(cmd)) {
            errno = EPERM;
            return -1;
        }
    }
    return orig_system ? orig_system(command) : -1;
}

static FILE *(*orig_popen)(const char *, const char *);
static FILE *hook_popen(const char *command, const char *type) {
    if (PXJBShouldBypassCached() && command) {
        NSString *cmd = [NSString stringWithUTF8String:command] ?: @"";
        if (PXJBCommandLooksLikeProbe(cmd)) {
            errno = EPERM;
            return NULL;
        }
    }
    return orig_popen ? orig_popen(command, type) : NULL;
}

static BOOL PXJBSpawnPathLooksLikeProbe(const char *path) {
    if (!path || !path[0]) return NO;
    if (path[0] == '/' && PXJBPathShouldHide(path)) return YES;
    // Also block common tool names when posix_spawnp is used.
    static const char *denyTokens[] = {
        "ssh",
        "scp",
        "sshd",
        "bash",
        "zsh",
        "sh",
        "uicache",
        "ldrestart",
        "frida-server",
        "cycript",
        "dpkg",
        "apt",
        "apt-get",
        NULL
    };
    const char *base = strrchr(path, '/');
    base = base ? (base + 1) : path;
    for (int i = 0; denyTokens[i]; i++) {
        if (PXStrEqNoCase(base, denyTokens[i])) return YES;
    }
    return NO;
}

static int (*orig_posix_spawn)(pid_t *restrict, const char *restrict, const posix_spawn_file_actions_t *restrict, const posix_spawnattr_t *restrict, char *const argv[restrict], char *const envp[restrict]);
static int hook_posix_spawn(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]) {
    if (PXJBShouldBypassCached() && path && PXJBSpawnPathLooksLikeProbe(path)) {
        PXJBLogBlockedOncePerSecond("posix_spawn", path);
        errno = ENOENT;
        return -1;
    }
    return orig_posix_spawn ? orig_posix_spawn(pid, path, file_actions, attrp, argv, envp) : -1;
}

static int (*orig_posix_spawnp)(pid_t *restrict, const char *restrict, const posix_spawn_file_actions_t *restrict, const posix_spawnattr_t *restrict, char *const argv[restrict], char *const envp[restrict]);
static int hook_posix_spawnp(pid_t *restrict pid, const char *restrict file, const posix_spawn_file_actions_t *restrict file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]) {
    if (PXJBShouldBypassCached() && file && PXJBSpawnPathLooksLikeProbe(file)) {
        PXJBLogBlockedOncePerSecond("posix_spawnp", file);
        errno = ENOENT;
        return -1;
    }
    return orig_posix_spawnp ? orig_posix_spawnp(pid, file, file_actions, attrp, argv, envp) : -1;
}

// --- B2: execve / execv / execvp (direct exec, bypassing posix_spawn) ---
// Some probes fork()+exec*() directly instead of posix_spawn. We gate these
// behind jbBypassHookExecEnabled (default OFF) and reuse PXJBSpawnPathLooksLikeProbe.
// exec* are not variadic in these forms, so there is no ABI risk like fcntl/syscall.
static int (*orig_execve)(const char *, char *const[], char *const[]);
static int hook_execve(const char *path, char *const argv[], char *const envp[]) {
    if (PXJBHookExecEnabled() && path && PXJBSpawnPathLooksLikeProbe(path)) {
        PXJBLogBlockedOncePerSecond("execve", path);
        errno = ENOENT;
        return -1;
    }
    return orig_execve ? orig_execve(path, argv, envp) : -1;
}

static int (*orig_execv)(const char *, char *const[]);
static int hook_execv(const char *path, char *const argv[]) {
    if (PXJBHookExecEnabled() && path && PXJBSpawnPathLooksLikeProbe(path)) {
        PXJBLogBlockedOncePerSecond("execv", path);
        errno = ENOENT;
        return -1;
    }
    return orig_execv ? orig_execv(path, argv) : -1;
}

static int (*orig_execvp)(const char *, char *const[]);
static int hook_execvp(const char *file, char *const argv[]) {
    if (PXJBHookExecEnabled() && file && PXJBSpawnPathLooksLikeProbe(file)) {
        PXJBLogBlockedOncePerSecond("execvp", file);
        errno = ENOENT;
        return -1;
    }
    return orig_execvp ? orig_execvp(file, argv) : -1;
}

// Optional strong hook: sandbox_check
static int (*orig_sandbox_check)(pid_t pid, const char *operation, int type, ...);
static int hook_sandbox_check(pid_t pid, const char *operation, int type, ...) {
    if (!orig_sandbox_check) {
        errno = EPERM;
        return -1;
    }

    // We only support the common 1-string-argument patterns.
    const char *arg = NULL;
    va_list ap;
    va_start(ap, type);
    arg = va_arg(ap, const char *);
    va_end(ap);

    if (PXJBHookSandboxCheckEnabled() && operation && arg && arg[0] == '/') {
        // Only gate file-related operations (avoid breaking non-file sandbox queries).
        if (PXHasPrefix(operation, "file-") && PXJBPathShouldHide(arg)) {
            PXJBLogBlockedOncePerSecond("sandbox_check", arg);
            errno = EPERM;
            return -1;
        }
    }

    return orig_sandbox_check(pid, operation, type, arg);
}

// Phase 3: dylib hiding (dyld enumeration + dladdr)
static pthread_mutex_t gDyldLock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t *gVisibleToReal = NULL;
static uint32_t gVisibleCount = 0;
static uint32_t gRealCount = 0;
static CFTimeInterval gDyldLastBuild = 0;

// Declare originals before helpers to avoid implicit declarations.
static uint32_t (*orig__dyld_image_count)(void) = NULL;
static const char *(*orig__dyld_get_image_name)(uint32_t image_index) = NULL;
static const struct mach_header *(*orig__dyld_get_image_header)(uint32_t image_index) = NULL;
static intptr_t (*orig__dyld_get_image_vmaddr_slide)(uint32_t image_index) = NULL;

// Real function pointers captured before hooking, to avoid recursion issues.
static uint32_t (*real__dyld_image_count)(void) = NULL;
static const char *(*real__dyld_get_image_name)(uint32_t image_index) = NULL;
static const struct mach_header *(*real__dyld_get_image_header)(uint32_t image_index) = NULL;
static intptr_t (*real__dyld_get_image_vmaddr_slide)(uint32_t image_index) = NULL;

static uint32_t PXDyldRealImageCount(void) {
    if (real__dyld_image_count) return real__dyld_image_count();
    if (orig__dyld_image_count) return orig__dyld_image_count();
    return 0;
}

static const char *PXDyldRealImageName(uint32_t idx) {
    if (real__dyld_get_image_name) return real__dyld_get_image_name(idx);
    if (orig__dyld_get_image_name) return orig__dyld_get_image_name(idx);
    return NULL;
}

static const struct mach_header *PXDyldRealImageHeader(uint32_t idx) {
    if (real__dyld_get_image_header) return real__dyld_get_image_header(idx);
    if (orig__dyld_get_image_header) return orig__dyld_get_image_header(idx);
    return NULL;
}

static intptr_t PXDyldRealImageSlide(uint32_t idx) {
    if (real__dyld_get_image_vmaddr_slide) return real__dyld_get_image_vmaddr_slide(idx);
    if (orig__dyld_get_image_vmaddr_slide) return orig__dyld_get_image_vmaddr_slide(idx);
    return 0;
}

static BOOL PXStrContainsNoCase(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NO;
    size_t nlen = strlen(needle);
    if (nlen == 0) return YES;

    for (const char *h = haystack; *h; h++) {
        const char *p = h;
        size_t i = 0;
        while (p[i] && i < nlen) {
            char a = p[i];
            char b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
            i++;
        }
        if (i == nlen) return YES;
    }
    return NO;
}

static BOOL PXJBShouldHideImageName(const char *name) {
    if (!name) return NO;
    // Substrings frequently used by jailbreak tooling / injection.
    static const char *deny[] = {
        // Substrate family
        "mobilesubstrate",
        "substrateloader",
        "substratebootstrap",
        "libsubstrate",
        "substrate",
        
        // ElleKit (modern jailbreaks)
        "ellekit",
        "libellekit",
        
        // libhooker
        "libhooker",
        
        // Substitute
        "substitute",
        
        // TweakInject
        "tweakinject",
        
        // Common ecosystem libs
        "rocketbootstrap",
        "libmryipc",
        "libblackjack",
        "applist",
        "cephei",
        "libcolorpicker",
        "libflex",
        "libactivator",
        "preferenceloader",
        "preferencebundles",
        
        // Security tools
        "frida",
        "fridagadget",
        "cycript",
        "ssl_logger",
        "objection",
        
        // Common tweak names
        "shadow",
        "liberty",
        "vnodebypass",
        "unsub",
        "a-bypass",
        "hestia",
        "choicy",
        "kernbypass",
        "hidejb",
        "jailprotect",
        "detectordeter",
        
        // Jailbreak specific
        "libjailbreak",
        "jailbreakd",
        "cy-",
        "dopamine",
        "palera1n",
        "procursus",
        "checkra1n",
        "unc0ver",
        "taurine",
        "odyssey",
        "chimera",
        "electra",
        
        NULL
    };
    for (int i = 0; deny[i]; i++) {
        if (PXStrContainsNoCase(name, deny[i])) return YES;
    }
    // Common rootless prefixes.
    if (PXStrContainsNoCase(name, "/var/jb")) return YES;
    if (PXStrContainsNoCase(name, "/private/preboot/jb")) return YES;
    if (PXStrContainsNoCase(name, "/private/preboot/")) return YES;
    // Common jailbreak cache-injected dylib pattern.
    if (PXStrContainsNoCase(name, "/library/caches/cy-")) return YES;
    // MobileSubstrate injection path.
    if (PXStrContainsNoCase(name, "/library/mobilesubstrate/")) return YES;
    return NO;
}

// Phase 3 strong option: hide libproc-based region filename queries
static int (*orig_proc_regionfilename)(int pid, uint64_t address, void *buffer, uint32_t buffersize);
static int hook_proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t buffersize) {
    if (!orig_proc_regionfilename) return 0;
    int r = orig_proc_regionfilename(pid, address, buffer, buffersize);
    if (r <= 0) return r;
    if (!PXJBHideProcMapsEnabled()) return r;
    if (pid != getpid()) return r;
    if (!buffer || buffersize == 0) return r;

    // Ensure NUL-termination for scanning.
    char *cbuf = (char *)buffer;
    cbuf[buffersize - 1] = '\0';
    if (PXJBShouldHideImageName(cbuf) || PXJBPathShouldHide(cbuf)) {
        cbuf[0] = '\0';
        return 0;
    }
    return r;
}

// --- B3: proc_pidpath / proc_pidinfo (libproc) ---
// Detectors use these to read a process's executable path or info; the path
// can leak jailbreak dylib/app locations. We only sanitize our own process
// (pid == getpid()) and only when jbBypassHideProcInfoEnabled is set.
// libproc.h may not ship in all Theos SDKs, so declare prototypes manually.
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
static int (*orig_proc_pidpath)(int, void *, uint32_t);
static int hook_proc_pidpath(int pid, void *buffer, uint32_t buffersize) {
    if (!orig_proc_pidpath) return -1;
    int r = orig_proc_pidpath(pid, buffer, buffersize);
    if (r <= 0) return r;
    if (!PXJBHideProcInfoEnabled()) return r;
    if (pid != getpid()) return r;
    if (!buffer || buffersize == 0) return r;
    char *cbuf = (char *)buffer;
    cbuf[buffersize - 1] = '\0';
    if (PXJBShouldHideImageName(cbuf) || PXJBPathShouldHide(cbuf)) {
        // Returning the real path would expose a JB location; report failure.
        errno = ESRCH;
        return -1;
    }
    return r;
}

// Phase 3 strong option: hide ObjC runtime image list
static const char **(*orig_objc_copyImageNames)(unsigned int *outCount);
static const char **hook_objc_copyImageNames(unsigned int *outCount) {
    const char **list = orig_objc_copyImageNames ? orig_objc_copyImageNames(outCount) : NULL;
    if (!PXJBHideObjcImagesEnabled()) {
        return list;
    }
    if (!list || !outCount || *outCount == 0) {
        return list;
    }

    unsigned int inCount = *outCount;
    // Allocate a new list and free the original (caller will free what we return).
    const char **out = (const char **)calloc(inCount + 1, sizeof(char *));
    if (!out) {
        return list;
    }

    unsigned int j = 0;
    for (unsigned int i = 0; i < inCount; i++) {
        const char *nm = list[i];
        if (PXJBShouldHideImageName(nm)) continue;
        out[j++] = nm;
    }
    out[j] = NULL;
    *outCount = j;
    free((void *)list);
    return out;
}

static const char *(*orig_class_getImageName)(Class cls);
static const char *hook_class_getImageName(Class cls) {
    const char *nm = orig_class_getImageName ? orig_class_getImageName(cls) : NULL;
    if (!PXJBHideObjcImagesEnabled()) return nm;
    if (PXJBShouldHideImageName(nm)) return NULL;
    return nm;
}

static BOOL PXJBShouldBlockDlopenPath(const char *path) {
    if (!path || !path[0]) return NO;
    // Block direct probes for common injection/jailbreak libraries.
    static const char *deny[] = {
        "/usr/lib/substrate/",
        "substratebootstrap",
        "mobilesubstrate",
        "substrate",
        "ellekit",
        "libhooker",
        "rocketbootstrap",
        "substitute",
        "frida",
        "/library/caches/cy-",
        NULL
    };
    for (int i = 0; deny[i]; i++) {
        if (PXStrContainsNoCase(path, deny[i])) return YES;
    }
    return NO;
}

static BOOL PXJBShouldBlockDlsymName(const char *sym) {
    if (!sym || !sym[0]) return NO;
    // Only block extremely fingerprintable hooking symbols.
    static const char *deny[] = {
        "MSHookFunction",
        "MSHookMessageEx",
        "MSGetImageByName",
        "MSFindSymbol",
        "EKHook",
        "EKHookFunction",
        "LHHookFunction",
        "SubHookFunction",
        "fishhook_rebind_symbols",
        NULL
    };
    for (int i = 0; deny[i]; i++) {
        if (strcmp(sym, deny[i]) == 0) return YES;
    }
    return NO;
}

// Phase 3 strong option: hide dl_iterate_phdr enumeration
static int (*orig_dl_iterate_phdr)(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data);

typedef struct {
    int (*cb)(struct dl_phdr_info *info, size_t size, void *data);
    void *data;
} PXJBPhdrIterCtx;

static int px_dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    PXJBPhdrIterCtx *ctx = (PXJBPhdrIterCtx *)data;
    if (!ctx || !ctx->cb) return 0;

    if (PXJBHideDlIteratePhdrEnabled() && info) {
        const char *nm = info->dlpi_name;
        if (PXJBShouldHideImageName(nm)) {
            return 0; // skip
        }
    }
    return ctx->cb(info, size, ctx->data);
}

static int hook_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data) {
    if (!orig_dl_iterate_phdr) return 0;
    if (!PXJBHideDlIteratePhdrEnabled() || !callback) {
        return orig_dl_iterate_phdr(callback, data);
    }

    PXJBPhdrIterCtx ctx;
    ctx.cb = callback;
    ctx.data = data;
    return orig_dl_iterate_phdr(px_dl_iterate_phdr_cb, &ctx);
}

// Phase 3 strong option: block dlopen/dlsym probes
static void *(*orig_dlopen)(const char *path, int mode);
static void *hook_dlopen(const char *path, int mode) {
    if (PXJBBlockDlopenDlsymProbesEnabled() && path) {
        if (PXJBShouldBlockDlopenPath(path)) {
            errno = ENOENT;
            return NULL;
        }
    }
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

static void *(*orig_dlsym)(void *handle, const char *symbol);
static void *hook_dlsym(void *handle, const char *symbol) {
    if (PXJBBlockDlopenDlsymProbesEnabled() && symbol) {
        if (PXJBShouldBlockDlsymName(symbol)) {
            return NULL;
        }
    }
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

// Phase 3 strong option: sysctl/sysctlbyname sanitization
static int (*orig_sysctl_jb)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int (*orig_sysctlbyname_jb)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

static void PXJBSanitizeBootArgs(void *oldp, size_t *oldlenp) {
    if (!oldp || !oldlenp || *oldlenp == 0) return;
    char *buf = (char *)oldp;
    size_t n = *oldlenp;
    // Ensure NUL-termination for scanning.
    buf[n - 1] = '\0';
    if (strstr(buf, "checkra1n") || strstr(buf, "cs_enforcement_disable") || strstr(buf, "amfid") || strstr(buf, "jailbreak")) {
        memset(buf, 0, n);
        // Keep it plausible.
        const char *clean = "root_device=md0";
        strncpy(buf, clean, n - 1);
    }
}

static void PXJBSanitizeKinfoProc(void *oldp, size_t *oldlenp) {
    if (!oldp || !oldlenp || *oldlenp == 0) return;
#if __has_include(<sys/user.h>)
    // Clear P_TRACED if present.
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
    size_t len = *oldlenp;
    if (len < sizeof(struct kinfo_proc)) return;
    size_t count = len / sizeof(struct kinfo_proc);
    struct kinfo_proc *procs = (struct kinfo_proc *)oldp;
    for (size_t i = 0; i < count; i++) {
        procs[i].kp_proc.p_flag &= ~P_TRACED;
    }
#else
    (void)oldp; (void)oldlenp;
#endif
}

static int hook_sysctl_jb(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = orig_sysctl_jb ? orig_sysctl_jb(name, namelen, oldp, oldlenp, newp, newlen) : -1;
    if (r != 0 || !PXJBSysctlProcSanitizeEnabled()) return r;
    if (!name || namelen < 2) return r;

    if (name[0] == CTL_KERN) {
#ifdef KERN_BOOTARGS
        if (name[1] == KERN_BOOTARGS) {
            PXJBSanitizeBootArgs(oldp, oldlenp);
        }
#endif
        if (name[1] == KERN_PROC) {
            PXJBSanitizeKinfoProc(oldp, oldlenp);
        }
    }
    return r;
}

static int hook_sysctlbyname_jb(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = orig_sysctlbyname_jb ? orig_sysctlbyname_jb(name, oldp, oldlenp, newp, newlen) : -1;
    if (r != 0 || !PXJBSysctlProcSanitizeEnabled()) return r;
    if (!name) return r;
    if (strcmp(name, "kern.bootargs") == 0) {
        PXJBSanitizeBootArgs(oldp, oldlenp);
    } else if (strcmp(name, "kern.proc.pid") == 0 || strcmp(name, "kern.proc") == 0) {
        PXJBSanitizeKinfoProc(oldp, oldlenp);
    }
    return r;
}

static void PXDyldRebuildVisibleMapLocked(void) {
    uint32_t count = PXDyldRealImageCount();
    if (count == 0) {
        gRealCount = 0;
        gVisibleCount = 0;
        return;
    }

    if (gVisibleToReal) {
        free(gVisibleToReal);
        gVisibleToReal = NULL;
    }

    gVisibleToReal = (uint32_t *)calloc(count, sizeof(uint32_t));
    if (!gVisibleToReal) {
        gRealCount = count;
        gVisibleCount = count;
        return;
    }

    uint32_t visible = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *nm = PXDyldRealImageName(i);
        if (PXJBShouldHideImageName(nm)) {
            continue;
        }
        gVisibleToReal[visible++] = i;
    }
    gRealCount = count;
    gVisibleCount = visible;
    gDyldLastBuild = CFAbsoluteTimeGetCurrent();
}

static void PXDyldEnsureVisibleMap(void) {
    if (!PXJBHideDylibsEnabled()) return;

    CFTimeInterval now = CFAbsoluteTimeGetCurrent();
    // Rebuild at most once per second, or when dyld image count changes.
    uint32_t countNow = PXDyldRealImageCount();

    pthread_mutex_lock(&gDyldLock);
    BOOL needs = (gVisibleToReal == NULL) || (gRealCount != countNow) || ((now - gDyldLastBuild) > 1.0);
    if (needs) {
        PXDyldRebuildVisibleMapLocked();
    }
    pthread_mutex_unlock(&gDyldLock);
}

static uint32_t hook__dyld_image_count(void) {
    uint32_t count = orig__dyld_image_count ? orig__dyld_image_count() : 0;
    if (!PXJBHideDylibsEnabled()) return count;
    PXDyldEnsureVisibleMap();
    pthread_mutex_lock(&gDyldLock);
    uint32_t out = gVisibleToReal ? gVisibleCount : count;
    pthread_mutex_unlock(&gDyldLock);
    return out;
}

static const char *hook__dyld_get_image_name(uint32_t image_index) {
    if (!PXJBHideDylibsEnabled()) {
        return orig__dyld_get_image_name ? orig__dyld_get_image_name(image_index) : NULL;
    }
    PXDyldEnsureVisibleMap();

    pthread_mutex_lock(&gDyldLock);
    if (!gVisibleToReal || image_index >= gVisibleCount) {
        pthread_mutex_unlock(&gDyldLock);
        return NULL;
    }
    uint32_t realIndex = gVisibleToReal[image_index];
    pthread_mutex_unlock(&gDyldLock);

    return orig__dyld_get_image_name ? orig__dyld_get_image_name(realIndex) : NULL;
}

static const struct mach_header *hook__dyld_get_image_header(uint32_t image_index) {
    if (!PXJBHideDylibsEnabled()) {
        return orig__dyld_get_image_header ? orig__dyld_get_image_header(image_index) : NULL;
    }
    PXDyldEnsureVisibleMap();

    pthread_mutex_lock(&gDyldLock);
    if (!gVisibleToReal || image_index >= gVisibleCount) {
        pthread_mutex_unlock(&gDyldLock);
        return NULL;
    }
    uint32_t realIndex = gVisibleToReal[image_index];
    pthread_mutex_unlock(&gDyldLock);

    return orig__dyld_get_image_header ? orig__dyld_get_image_header(realIndex) : NULL;
}

static intptr_t hook__dyld_get_image_vmaddr_slide(uint32_t image_index) {
    if (!PXJBHideDylibsEnabled()) {
        return orig__dyld_get_image_vmaddr_slide ? orig__dyld_get_image_vmaddr_slide(image_index) : 0;
    }
    PXDyldEnsureVisibleMap();

    pthread_mutex_lock(&gDyldLock);
    if (!gVisibleToReal || image_index >= gVisibleCount) {
        pthread_mutex_unlock(&gDyldLock);
        return 0;
    }
    uint32_t realIndex = gVisibleToReal[image_index];
    pthread_mutex_unlock(&gDyldLock);

    return orig__dyld_get_image_vmaddr_slide ? orig__dyld_get_image_vmaddr_slide(realIndex) : 0;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int hook_dladdr(const void *addr, Dl_info *info) {
    int r = orig_dladdr ? orig_dladdr(addr, info) : 0;
    if (r == 0 || !info) return r;
    if (!PXJBHideDylibsEnabled()) return r;
    if (info->dli_fname && PXJBShouldHideImageName(info->dli_fname)) {
        // Fail lookup so callers can't attribute symbols to jailbreak dylibs.
        return 0;
    }
    return r;
}

// Phase 2 extension: mount/volume checks (statfs/statvfs)
static BOOL PXJBIsSensitiveMountPath(const char *path) {
    if (!path) return NO;
    // Most detectors check "/" and sometimes "/private" or "/var".
    if (strcmp(path, "/") == 0) return YES;
    if (strcmp(path, "/var") == 0) return YES;
    if (strcmp(path, "/private") == 0) return YES;
    if (strcmp(path, "/private/var") == 0) return YES;
    return NO;
}

static void PXJBNormalizeStatfs(struct statfs *buf) {
    if (!buf) return;
    // Ensure rootfs looks read-only (common non-JB expectation).
#ifdef MNT_RDONLY
    buf->f_flags |= MNT_RDONLY;
#endif
}

static void PXJBNormalizeStatvfs(struct statvfs *buf) {
    if (!buf) return;
#ifdef ST_RDONLY
    buf->f_flag |= ST_RDONLY;
#endif
}

static int (*orig_statfs)(const char *, struct statfs *);
static int hook_statfs(const char *path, struct statfs *buf) {
    int r = orig_statfs ? orig_statfs(path, buf) : -1;
    if (r == 0 && PXJBStatfsBypassEnabled() && PXJBIsSensitiveMountPath(path)) {
        PXJBNormalizeStatfs(buf);
    }
    return r;
}

static int (*orig_fstatfs)(int, struct statfs *);
static int hook_fstatfs(int fd, struct statfs *buf) {
    int r = orig_fstatfs ? orig_fstatfs(fd, buf) : -1;
    if (r == 0 && PXJBStatfsBypassEnabled()) {
        // We can't reliably map fd->path cheaply; normalize anyway (best-effort).
        PXJBNormalizeStatfs(buf);
    }
    return r;
}

static int (*orig_statvfs)(const char *, struct statvfs *);
static int hook_statvfs(const char *path, struct statvfs *buf) {
    int r = orig_statvfs ? orig_statvfs(path, buf) : -1;
    if (r == 0 && PXJBStatfsBypassEnabled() && PXJBIsSensitiveMountPath(path)) {
        PXJBNormalizeStatvfs(buf);
    }
    return r;
}

static int (*orig_fstatvfs)(int, struct statvfs *);
static int hook_fstatvfs(int fd, struct statvfs *buf) {
    int r = orig_fstatvfs ? orig_fstatvfs(fd, buf) : -1;
    if (r == 0 && PXJBStatfsBypassEnabled()) {
        PXJBNormalizeStatvfs(buf);
    }
    return r;
}

// --- Priority 1: UID/GID spoofing ---
// Many apps check getuid()==0 to detect root access on jailbroken devices.
// Return 501 (mobile user) to appear non-jailbroken.

static uid_t (*orig_getuid)(void);
static uid_t hook_getuid(void) {
    if (PXJBShouldBypassCached()) return 501;
    return orig_getuid ? orig_getuid() : 501;
}

static uid_t (*orig_geteuid)(void);
static uid_t hook_geteuid(void) {
    if (PXJBShouldBypassCached()) return 501;
    return orig_geteuid ? orig_geteuid() : 501;
}

static gid_t (*orig_getgid)(void);
static gid_t hook_getgid(void) {
    if (PXJBShouldBypassCached()) return 501;
    return orig_getgid ? orig_getgid() : 501;
}

static gid_t (*orig_getegid)(void);
static gid_t hook_getegid(void) {
    if (PXJBShouldBypassCached()) return 501;
    return orig_getegid ? orig_getegid() : 501;
}

static int (*orig_setuid)(uid_t);
static int hook_setuid(uid_t uid) {
    if (PXJBShouldBypassCached() && uid == 0) {
        errno = EPERM;
        return -1;
    }
    return orig_setuid ? orig_setuid(uid) : -1;
}

static int (*orig_seteuid)(uid_t);
static int hook_seteuid(uid_t uid) {
    if (PXJBShouldBypassCached() && uid == 0) {
        errno = EPERM;
        return -1;
    }
    return orig_seteuid ? orig_seteuid(uid) : -1;
}

static int (*orig_setgid)(gid_t);
static int hook_setgid(gid_t gid) {
    if (PXJBShouldBypassCached() && gid == 0) {
        errno = EPERM;
        return -1;
    }
    return orig_setgid ? orig_setgid(gid) : -1;
}

static int (*orig_setegid)(gid_t);
static int hook_setegid(gid_t gid) {
    if (PXJBShouldBypassCached() && gid == 0) {
        errno = EPERM;
        return -1;
    }
    return orig_setegid ? orig_setegid(gid) : -1;
}

static int (*orig_setreuid)(uid_t, uid_t);
static int hook_setreuid(uid_t ruid, uid_t euid) {
    if (PXJBShouldBypassCached() && (ruid == 0 || euid == 0)) {
        errno = EPERM;
        return -1;
    }
    return orig_setreuid ? orig_setreuid(ruid, euid) : -1;
}

static int (*orig_setregid)(gid_t, gid_t);
static int hook_setregid(gid_t rgid, gid_t egid) {
    if (PXJBShouldBypassCached() && (rgid == 0 || egid == 0)) {
        errno = EPERM;
        return -1;
    }
    return orig_setregid ? orig_setregid(rgid, egid) : -1;
}

// --- Priority 1: getppid spoofing ---
// On non-jailbroken devices, parent PID is always 1 (launchd).
static pid_t (*orig_getppid)(void);
static pid_t hook_getppid(void) {
    if (PXJBShouldBypassCached()) return 1;
    return orig_getppid ? orig_getppid() : 1;
}

// --- Priority 1: csops — hide CS_PLATFORM_BINARY ---
// Some detectors check if the process has the platform binary flag set,
// which can happen on jailbroken devices.
static int (*orig_csops)(pid_t, unsigned int, void *, size_t);
static int hook_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int ret = orig_csops ? orig_csops(pid, ops, useraddr, usersize) : -1;
    if (ret == 0 && PXJBShouldBypassCached() && ops == CS_OPS_STATUS && pid == getpid()) {
        // Clear CS_PLATFORM_BINARY flag from the returned status.
        if (useraddr && usersize >= sizeof(uint32_t)) {
            uint32_t *flags = (uint32_t *)useraddr;
            *flags &= ~CS_PLATFORM_BINARY;
        }
    }
    return ret;
}

// --- Priority 3: dlopen_preflight ---
static bool (*orig_dlopen_preflight)(const char *);
static bool hook_dlopen_preflight(const char *path) {
    if (PXJBShouldBypassCached() && path) {
        if (PXJBShouldBlockDlopenPath(path)) return false;
    }
    return orig_dlopen_preflight ? orig_dlopen_preflight(path) : false;
}

// --- Priority 3: objc_copyClassNamesForImage ---
static const char **(*orig_objc_copyClassNamesForImage)(const char *, unsigned int *);
static const char **hook_objc_copyClassNamesForImage(const char *image, unsigned int *outCount) {
    if (PXJBShouldBypassCached() && image) {
        if (PXJBShouldHideImageName(image)) {
            if (outCount) *outCount = 0;
            return NULL;
        }
    }
    return orig_objc_copyClassNamesForImage ? orig_objc_copyClassNamesForImage(image, outCount) : NULL;
}

// --- Priority 3: NSVersionOfRunTimeLibrary / NSVersionOfLinkTimeLibrary ---
static int32_t (*orig_NSVersionOfRunTimeLibrary)(const char *);
static int32_t hook_NSVersionOfRunTimeLibrary(const char *libraryName) {
    if (PXJBShouldBypassCached() && libraryName) {
        if (PXJBShouldHideImageName(libraryName)) return -1;
    }
    return orig_NSVersionOfRunTimeLibrary ? orig_NSVersionOfRunTimeLibrary(libraryName) : -1;
}

static int32_t (*orig_NSVersionOfLinkTimeLibrary)(const char *);
static int32_t hook_NSVersionOfLinkTimeLibrary(const char *libraryName) {
    if (PXJBShouldBypassCached() && libraryName) {
        if (PXJBShouldHideImageName(libraryName)) return -1;
    }
    return orig_NSVersionOfLinkTimeLibrary ? orig_NSVersionOfLinkTimeLibrary(libraryName) : -1;
}

// --- Priority 3: creat ---
static int (*orig_creat)(const char *, mode_t);
static int hook_creat(const char *path, mode_t mode) {
    if (PXJBShouldBypassCached() && PXJBPathShouldHide(path)) {
        errno = EACCES;
        return -1;
    }
    return orig_creat ? orig_creat(path, mode) : -1;
}

// --- Priority 3: fstat (fd-based, resolve via fcntl F_GETPATH) ---
// RISK NOTE: fstat is an extremely hot path. Resolving fd->path via
// fcntl(F_GETPATH) on EVERY call adds one syscall + a PATH_MAX (1KB) stack
// buffer per invocation, even for fds unrelated to jailbreak detection.
// Very few detectors use fstat to probe JB, so the path-resolve branch is
// gated behind its own toggle (jbBypassHookFstatPathEnabled, default OFF).
// When the toggle is off, this hook forwards with zero added cost.
static int (*orig_fstat)(int, struct stat *);
static int hook_fstat(int fd, struct stat *buf) {
    if (PXJBHookFstatPathEnabled() && fd >= 0) {
        char fdpath[PATH_MAX];
        if (fcntl(fd, F_GETPATH, fdpath) != -1) {
            if (PXJBPathShouldHide(fdpath)) {
                errno = EBADF;
                return -1;
            }
        }
    }
    return orig_fstat ? orig_fstat(fd, buf) : -1;
}

// --- Priority 3: fstatat ---
static int (*orig_fstatat)(int, const char *, struct stat *, int);
static int hook_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (PXJBShouldBypassCached() && pathname) {
        // If pathname is relative, resolve against dirfd
        if (pathname[0] != '/' && dirfd != AT_FDCWD) {
            char dirpath[PATH_MAX];
            if (fcntl(dirfd, F_GETPATH, dirpath) != -1) {
                NSString *base = [NSString stringWithUTF8String:dirpath];
                NSString *rel = [NSString stringWithUTF8String:pathname];
                NSString *full = [base stringByAppendingPathComponent:rel];
                if (PXJBPathShouldHide([full fileSystemRepresentation])) {
                    errno = ENOENT;
                    return -1;
                }
            }
        } else {
            if (PXJBPathShouldHide(pathname)) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return orig_fstatat ? orig_fstatat(dirfd, pathname, buf, flags) : -1;
}

// --- B1: getattrlist / getattrlistat (path-based) ---
// getattrlist/getattrlistat exposes file metadata; if not hidden here, a
// detection routine can probe a path's attributes even when stat/access are
// already covered. Gated behind the shared bypass toggle and reuses
// PXJBPathShouldHide so the hide-list stays single-sourced.
static int (*orig_getattrlist)(const char *, struct attrlist *, void *, size_t, unsigned long);
static int hook_getattrlist(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options) {
    if (PXJBShouldBypassCached() && path && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_getattrlist ? orig_getattrlist(path, attrList, attrBuf, attrBufSize, options) : -1;
}

static int (*orig_getattrlistat)(int, const char *, struct attrlist *, void *, size_t, unsigned long);
static int hook_getattrlistat(int dirfd, const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options) {
    if (PXJBShouldBypassCached() && path) {
        if (path[0] != '/' && dirfd != AT_FDCWD) {
            char dirpath[PATH_MAX];
            if (fcntl(dirfd, F_GETPATH, dirpath) != -1) {
                NSString *base = [NSString stringWithUTF8String:dirpath];
                NSString *rel = [NSString stringWithUTF8String:path];
                NSString *full = [base stringByAppendingPathComponent:rel];
                if (PXJBPathShouldHide([full fileSystemRepresentation])) {
                    errno = ENOENT;
                    return -1;
                }
            }
        } else {
            if (PXJBPathShouldHide(path)) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return orig_getattrlistat ? orig_getattrlistat(dirfd, path, attrList, attrBuf, attrBufSize, options) : -1;
}

// --- Priority 3: faccessat ---
static int (*orig_faccessat)(int, const char *, int, int);
static int hook_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (PXJBShouldBypassCached() && pathname) {
        if (pathname[0] != '/' && dirfd != AT_FDCWD) {
            char dirpath[PATH_MAX];
            if (fcntl(dirfd, F_GETPATH, dirpath) != -1) {
                NSString *base = [NSString stringWithUTF8String:dirpath];
                NSString *rel = [NSString stringWithUTF8String:pathname];
                NSString *full = [base stringByAppendingPathComponent:rel];
                if (PXJBPathShouldHide([full fileSystemRepresentation])) {
                    errno = ENOENT;
                    return -1;
                }
            }
        } else {
            if (PXJBPathShouldHide(pathname)) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return orig_faccessat ? orig_faccessat(dirfd, pathname, mode, flags) : -1;
}

// --- Priority 3: readlinkat ---
static ssize_t (*orig_readlinkat)(int, const char *, char *, size_t);
static ssize_t hook_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    if (PXJBShouldBypassCached() && pathname) {
        if (pathname[0] != '/' && dirfd != AT_FDCWD) {
            char dirpath[PATH_MAX];
            if (fcntl(dirfd, F_GETPATH, dirpath) != -1) {
                NSString *base = [NSString stringWithUTF8String:dirpath];
                NSString *rel = [NSString stringWithUTF8String:pathname];
                NSString *full = [base stringByAppendingPathComponent:rel];
                if (PXJBPathShouldHide([full fileSystemRepresentation])) {
                    errno = ENOENT;
                    return -1;
                }
            }
        } else {
            if (PXJBPathShouldHide(pathname)) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return orig_readlinkat ? orig_readlinkat(dirfd, pathname, buf, bufsiz) : -1;
}

// --- Priority 3: Filesystem mutation hooks ---
static int (*orig_symlink)(const char *, const char *);
static int hook_symlink(const char *path1, const char *path2) {
    if (PXJBShouldBypassCached()) {
        if ((path1 && PXJBPathShouldHide(path1)) || (path2 && PXJBPathShouldHide(path2))) {
            errno = EACCES;
            return -1;
        }
    }
    return orig_symlink ? orig_symlink(path1, path2) : -1;
}

static int (*orig_rename)(const char *, const char *);
static int hook_rename(const char *old, const char *new_path) {
    if (PXJBShouldBypassCached()) {
        if ((old && PXJBPathShouldHide(old)) || (new_path && PXJBPathShouldHide(new_path))) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_rename ? orig_rename(old, new_path) : -1;
}

static int (*orig_link)(const char *, const char *);
static int hook_link(const char *path1, const char *path2) {
    if (PXJBShouldBypassCached()) {
        if ((path1 && PXJBPathShouldHide(path1)) || (path2 && PXJBPathShouldHide(path2))) {
            errno = ENOENT;
            return -1;
        }
    }
    return orig_link ? orig_link(path1, path2) : -1;
}

static int (*orig_unlink)(const char *);
static int hook_unlink(const char *path) {
    if (PXJBShouldBypassCached() && path && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_unlink ? orig_unlink(path) : -1;
}

static int (*orig_remove_func)(const char *);
static int hook_remove_func(const char *path) {
    if (PXJBShouldBypassCached() && path && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_remove_func ? orig_remove_func(path) : -1;
}

static int (*orig_rmdir)(const char *);
static int hook_rmdir(const char *path) {
    if (PXJBShouldBypassCached() && path && PXJBPathShouldHide(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_rmdir ? orig_rmdir(path) : -1;
}

// --- JailbreakDetector bypass: getmntinfo ---
// Filters out bind mounts and suspicious APFS snapshot mounts from mount enumeration.
static int (*orig_getmntinfo)(struct statfs **, int);
static int hook_getmntinfo(struct statfs **mntbufp, int flags) {
    int n = orig_getmntinfo ? orig_getmntinfo(mntbufp, flags) : 0;
    if (!PXJBShouldBypassCached() || n <= 0 || !mntbufp || !*mntbufp) return n;

    struct statfs *buf = *mntbufp;
    int out = 0;
    for (int i = 0; i < n; i++) {
        // Hide bindfs mounts (used by some JBs for fakefs/fakelib)
        if (strcmp(buf[i].f_fstypename, "bindfs") == 0) {
            // Only allow known Apple bind mounts
            static const char *knownBinds[] = {
                "/usr/standalone/firmware",
                "/System/Library/Pearl/ReferenceFrames",
                "/System/Library/Caches/com.apple.factorydata",
                NULL
            };
            BOOL known = NO;
            for (int j = 0; knownBinds[j]; j++) {
                if (strcmp(buf[i].f_mntonname, knownBinds[j]) == 0) { known = YES; break; }
            }
            if (!known) continue; // hide unknown bindfs
        }
        // Hide unexpected APFS snapshot mounts (JB rootfs remounts)
        if (strcmp(buf[i].f_mntonname, "/") != 0 &&
            strcmp(buf[i].f_fstypename, "apfs") == 0 &&
            strstr(buf[i].f_mntfromname, "@") != NULL) {
            // Optional: hide suspicious snapshot mounts not on /
            // Only hide if mount point looks JB-related
            if (PXJBPathShouldHide(buf[i].f_mntonname)) continue;
        }
        if (out != i) buf[out] = buf[i];
        out++;
    }
    return out;
}

// --- JailbreakDetector bypass: bootstrap_look_up ---
// Blocks Mach service lookups for known JB daemons.
static kern_return_t (*orig_bootstrap_look_up)(mach_port_t, const char *, mach_port_t *);
static kern_return_t hook_bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp) {
    if (PXJBShouldBypassCached() && service_name) {
        static const char *deny[] = {
            "cy:com.saurik.substrated",
            "org.coolstar.jailbreakd",
            "jailbreakd",
            "cy:com.opa334.jailbreakd",
            "lh:com.opa334.jailbreakd",
            "com.opa334.jailbreakd",
            NULL
        };
        for (int i = 0; deny[i]; i++) {
            if (strcmp(service_name, deny[i]) == 0) {
                if (sp) *sp = MACH_PORT_NULL;
                return BOOTSTRAP_UNKNOWN_SERVICE;
            }
        }
        // Also block cy: and lh: prefixed probes generically
        if (strncmp(service_name, "cy:", 3) == 0 || strncmp(service_name, "lh:", 3) == 0) {
            if (sp) *sp = MACH_PORT_NULL;
            return BOOTSTRAP_UNKNOWN_SERVICE;
        }
    }
    return orig_bootstrap_look_up ? orig_bootstrap_look_up(bp, service_name, sp) : BOOTSTRAP_UNKNOWN_SERVICE;
}

// --- JailbreakDetector bypass: vm_region_64 ---
// Sanitize protection flags so injected code regions look normal.
static kern_return_t (*orig_vm_region_64)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
static kern_return_t hook_vm_region_64(vm_map_t target_task, vm_address_t *address, vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name) {
    kern_return_t kr = orig_vm_region_64 ? orig_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name) : KERN_FAILURE;
    if (kr != KERN_SUCCESS) return kr;
    if (!PXJBShouldBypassCached()) return kr;

    // For basic info, ensure protection looks like read-only for system library regions
    if (flavor == VM_REGION_BASIC_INFO_64 && info) {
        vm_region_basic_info_data_64_t *binfo = (vm_region_basic_info_data_64_t *)info;
        // If protection has execute+write on what should be read-only, fix it
        if ((binfo->protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            // Injected regions typically have RWX; sanitize to RX
            binfo->protection &= ~VM_PROT_WRITE;
        }
        // If it's RW on a region that should be RO (system lib text), sanitize to R
        if (binfo->protection == (VM_PROT_READ | VM_PROT_WRITE)) {
            // Check if it looks like it should be read-only
            if (binfo->max_protection == VM_PROT_READ) {
                binfo->protection = VM_PROT_READ;
            }
        }
    }
    return kr;
}

// --- JailbreakDetector bypass: task_get_exception_ports ---
// Return clean exception port state (no JB-inherited ports).
static kern_return_t (*orig_task_get_exception_ports)(task_t, exception_mask_t, exception_mask_array_t, mach_msg_type_number_t *, exception_handler_array_t, exception_behavior_array_t, exception_flavor_array_t);
static kern_return_t hook_task_get_exception_ports(task_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t old_handlers, exception_behavior_array_t old_behaviors, exception_flavor_array_t old_flavors) {
    kern_return_t kr = orig_task_get_exception_ports ? orig_task_get_exception_ports(task, exception_mask, masks, masksCnt, old_handlers, old_behaviors, old_flavors) : KERN_FAILURE;
    if (kr != KERN_SUCCESS) return kr;
    if (!PXJBShouldBypassCached()) return kr;

    // Sanitize: set all ports/behaviors/flavors to 0 (clean state)
    // The detector checks if count != 1 or if any ports/behaviors/flavors are non-zero
    if (masksCnt && masks && old_handlers && old_behaviors && old_flavors) {
        for (mach_msg_type_number_t i = 0; i < *masksCnt; i++) {
            old_handlers[i] = MACH_PORT_NULL;
            old_behaviors[i] = 0;
            old_flavors[i] = 0;
        }
    }
    return kr;
}

// --- JailbreakDetector bypass: fcntl (F_ADDSIGS / F_GETSIGSINFO) ---
// Block code signature injection probing and lie about platform binary status.
// fcntl arg classification.
// fcntl's third argument depends on cmd: some take no arg, some an int,
// some a pointer. Reading the wrong type via va_arg and forwarding it is
// ABI-unsafe. We classify known cmds and forward with the correct type.
//
// RISK NOTE: fcntl is an ABI-sensitive variadic hook. Any cmd not classified
// here falls back to the pointer-arg path (matches the previous behavior).
// On arm64 the third slot is passed in a register, so an over-read is
// typically benign, but misclassification of an int-arg cmd as pointer is
// still technically non-conforming. Keep this table in sync with <fcntl.h>.
static BOOL PXJBFcntlIsNoArgCmd(int cmd) {
    switch (cmd) {
        case F_GETFD:
        case F_GETFL:
        case F_GETOWN:
#ifdef F_GETLEASE
        case F_GETLEASE:
#endif
#ifdef F_FULLFSYNC
        case F_FULLFSYNC:
#endif
#ifdef F_FREEZE_FS
        case F_FREEZE_FS:
#endif
#ifdef F_THAW_FS
        case F_THAW_FS:
#endif
#ifdef F_FLUSH_DATA
        case F_FLUSH_DATA:
#endif
#ifdef F_CHKCLEAN
        case F_CHKCLEAN:
#endif
#ifdef F_NODIRECT
        case F_NODIRECT:
#endif
            return YES;
        default:
            return NO;
    }
}

static BOOL PXJBFcntlIsIntArgCmd(int cmd) {
    switch (cmd) {
        case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
        case F_DUPFD_CLOEXEC:
#endif
        case F_SETFD:
        case F_SETFL:
        case F_SETOWN:
#ifdef F_RDAHEAD
        case F_RDAHEAD:
#endif
#ifdef F_NOCACHE
        case F_NOCACHE:
#endif
#ifdef F_GLOBAL_NOCACHE
        case F_GLOBAL_NOCACHE:
#endif
#ifdef F_SETLEASE
        case F_SETLEASE:
#endif
#ifdef F_SINGLE_WRITER
        case F_SINGLE_WRITER:
#endif
#ifdef F_SETNOSIGPIPE
        case F_SETNOSIGPIPE:
#endif
#ifdef F_GETNOSIGPIPE
        case F_GETNOSIGPIPE:
#endif
            return YES;
        default:
            return NO;
    }
}

static int (*orig_fcntl)(int, int, ...);
static int hook_fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);

    if (PXJBShouldBypassCached()) {
        // Block F_ADDSIGS: prevents testing JB code signatures on kernel
        if (cmd == F_ADDSIGS) {
            va_end(ap);
            errno = EPERM;
            return -1;
        }
        // Sanitize F_GETSIGSINFO: always return "not platform binary"
        if (cmd == F_GETSIGSINFO) {
            fgetsigsinfo *siginfo = va_arg(ap, fgetsigsinfo *);
            va_end(ap);
            if (siginfo) {
                siginfo->fg_sig_is_platform = 0;
            }
            return 0;
        }
    }

    // Forward all other fcntl commands with the correctly-typed third arg.
    if (PXJBFcntlIsNoArgCmd(cmd)) {
        va_end(ap);
        return orig_fcntl ? orig_fcntl(fd, cmd) : -1;
    }
    if (PXJBFcntlIsIntArgCmd(cmd)) {
        int iarg = va_arg(ap, int);
        va_end(ap);
        return orig_fcntl ? orig_fcntl(fd, cmd, iarg) : -1;
    }
    // Default: pointer-arg cmds (F_GETPATH, F_PREALLOCATE, F_LOG2PHYS,
    // F_SETLK/F_GETLK struct flock*, etc.) and any unclassified cmd.
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return orig_fcntl ? orig_fcntl(fd, cmd, arg) : -1;
}

// --- JailbreakDetector bypass: xpc_pipe_routine ---
// Block JB-server XPC queries (Dopamine jb-domain, launchd deplatformization probes).
static int (*orig_xpc_pipe_routine)(xpc_object_t, xpc_object_t, xpc_object_t *);
static int hook_xpc_pipe_routine(xpc_object_t pipe, xpc_object_t request, xpc_object_t *reply) {
    if (PXJBShouldBypassCached() && request) {
        // Block launchd deplatformization probe (subsystem=3, routine=815)
        if (xpc_get_type(request) == XPC_TYPE_DICTIONARY) {
            uint64_t subsystem = xpc_dictionary_get_uint64(request, "subsystem");
            uint64_t routine = xpc_dictionary_get_uint64(request, "routine");
            if (subsystem == 3 && routine == 815) {
                if (reply) *reply = NULL;
                return 154; // Expected error code for non-jailbroken device
            }
        }
    }
    return orig_xpc_pipe_routine ? orig_xpc_pipe_routine(pipe, request, reply) : -1;
}

static int (*orig_xpc_pipe_routine_with_flags)(xpc_object_t, xpc_object_t, xpc_object_t *, uint64_t);
static int hook_xpc_pipe_routine_with_flags(xpc_object_t pipe, xpc_object_t request, xpc_object_t *reply, uint64_t flags) {
    if (PXJBShouldBypassCached() && request) {
        // Block jb-domain XPC queries (Dopamine jb server)
        if (xpc_get_type(request) == XPC_TYPE_DICTIONARY) {
            uint64_t jb_domain = xpc_dictionary_get_uint64(request, "jb-domain");
            if (jb_domain != 0) {
                if (reply) *reply = NULL;
                return -1; // Simulate no JB server
            }
        }
    }
    return orig_xpc_pipe_routine_with_flags ? orig_xpc_pipe_routine_with_flags(pipe, request, reply, flags) : -1;
}

// --- ObjC hooks ---
%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (isDirectory) *isDirectory = NO;
            return NO;
        }
    }
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) {
                *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            }
            return nil;
        }
    }
    return %orig;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    NSArray<NSString *> *orig = %orig;
    if (!PXJBShouldBypassCached()) return orig;
    if (![orig isKindOfClass:[NSArray class]] || orig.count == 0) return orig;

    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithCapacity:orig.count];
    for (NSString *item in orig) {
        if (![item isKindOfClass:[NSString class]]) continue;
        if ([item caseInsensitiveCompare:@"Cydia.app"] == NSOrderedSame) continue;
        if ([item caseInsensitiveCompare:@"Sileo.app"] == NSOrderedSame) continue;
        if ([item caseInsensitiveCompare:@"Zebra.app"] == NSOrderedSame) continue;
        if ([item caseInsensitiveCompare:@"Filza.app"] == NSOrderedSame) continue;
        [out addObject:item];
    }
    return out;
}

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError **)error {
    NSString *dest = %orig;
    if (!PXJBShouldBypassCached()) return dest;
    if (![dest isKindOfClass:[NSString class]] || dest.length == 0) return dest;
    const char *p = [dest fileSystemRepresentation];
    if (PXJBPathShouldHide(p)) {
        if (error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        }
        return nil;
    }
    return dest;
}

// --- Priority 2: Extended NSFileManager methods ---

- (NSDictionary *)attributesOfFileSystemForPath:(NSString *)path error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError **)error {
    NSArray *ret = %orig;
    if (!PXJBShouldBypassCached()) return ret;
    if (![ret isKindOfClass:[NSArray class]] || ret.count == 0) return ret;

    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:ret.count];
    for (NSURL *retURL in ret) {
        if ([retURL isKindOfClass:[NSURL class]] && [retURL isFileURL]) {
            const char *p = [[retURL path] fileSystemRepresentation];
            if (PXJBPathShouldHide(p)) continue;
        }
        [filtered addObject:retURL];
    }
    return [filtered copy];
}

- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory inDomains:(NSSearchPathDomainMask)domainMask {
    NSArray *ret = %orig;
    if (!PXJBShouldBypassCached()) return ret;
    if (![ret isKindOfClass:[NSArray class]] || ret.count == 0) return ret;

    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:ret.count];
    for (NSURL *u in ret) {
        if ([u isKindOfClass:[NSURL class]] && [u isFileURL]) {
            const char *p = [[u path] fileSystemRepresentation];
            if (PXJBPathShouldHide(p)) continue;
        }
        [filtered addObject:u];
    }
    return [filtered copy];
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return %orig(@"/.file");
    }
    return %orig;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    NSArray *ret = %orig;
    if (!PXJBShouldBypassCached()) return ret;
    if (![ret isKindOfClass:[NSArray class]] || ret.count == 0) return ret;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:ret.count];
    for (NSString *sub in ret) {
        if ([sub isKindOfClass:[NSString class]]) {
            NSString *full = [path stringByAppendingPathComponent:sub];
            const char *fp = [full fileSystemRepresentation];
            if (PXJBPathShouldHide(fp)) continue;
        }
        [filtered addObject:sub];
    }
    return [filtered copy];
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error {
    if (PXJBShouldBypassCached()) {
        BOOL srcHide = [srcPath isKindOfClass:[NSString class]] && PXJBPathShouldHide([srcPath fileSystemRepresentation]);
        BOOL dstHide = [dstPath isKindOfClass:[NSString class]] && PXJBPathShouldHide([dstPath fileSystemRepresentation]);
        if (srcHide || dstHide) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError **)error {
    if (PXJBShouldBypassCached()) {
        BOOL srcHide = [srcURL isKindOfClass:[NSURL class]] && [srcURL isFileURL] && PXJBPathShouldHide([[srcURL path] fileSystemRepresentation]);
        BOOL dstHide = [dstURL isKindOfClass:[NSURL class]] && [dstURL isFileURL] && PXJBPathShouldHide([[dstURL path] fileSystemRepresentation]);
        if (srcHide || dstHide) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error {
    if (PXJBShouldBypassCached()) {
        BOOL srcHide = [srcPath isKindOfClass:[NSString class]] && PXJBPathShouldHide([srcPath fileSystemRepresentation]);
        BOOL dstHide = [dstPath isKindOfClass:[NSString class]] && PXJBPathShouldHide([dstPath fileSystemRepresentation]);
        if (srcHide || dstHide) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError **)error {
    if (PXJBShouldBypassCached()) {
        BOOL srcHide = [srcURL isKindOfClass:[NSURL class]] && [srcURL isFileURL] && PXJBPathShouldHide([[srcURL path] fileSystemRepresentation]);
        BOOL dstHide = [dstURL isKindOfClass:[NSURL class]] && [dstURL isFileURL] && PXJBPathShouldHide([[dstURL path] fileSystemRepresentation]);
        if (srcHide || dstHide) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary *)attributes error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary *)attributes error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)removeItemAtURL:(NSURL *)URL error:(NSError **)error {
    if (PXJBShouldBypassCached() && [URL isKindOfClass:[NSURL class]] && [URL isFileURL]) {
        const char *p = [[URL path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error {
    if (PXJBShouldBypassCached()) {
        BOOL srcHide = [srcPath isKindOfClass:[NSString class]] && PXJBPathShouldHide([srcPath fileSystemRepresentation]);
        BOOL dstHide = [dstPath isKindOfClass:[NSString class]] && PXJBPathShouldHide([dstPath fileSystemRepresentation]);
        if (srcHide || dstHide) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path withDestinationPath:(NSString *)destPath error:(NSError **)error {
    if (PXJBShouldBypassCached()) {
        BOOL srcHide = [path isKindOfClass:[NSString class]] && PXJBPathShouldHide([path fileSystemRepresentation]);
        BOOL dstHide = [destPath isKindOfClass:[NSString class]] && PXJBPathShouldHide([destPath fileSystemRepresentation]);
        if (srcHide || dstHide) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

%end

%hook NSProcessInfo

- (NSDictionary<NSString *, NSString *> *)environment {
    NSDictionary *env = %orig;
    if (!PXJBShouldBypassCached()) return env;
    if (![env isKindOfClass:[NSDictionary class]] || env.count == 0) return env;

    NSMutableDictionary *out = [env mutableCopy];
    NSArray<NSString *> *deny = @[
        @"DYLD_INSERT_LIBRARIES",
        @"DYLD_LIBRARY_PATH",
        @"DYLD_FRAMEWORK_PATH",
        @"DYLD_FALLBACK_LIBRARY_PATH",
        @"DYLD_FALLBACK_FRAMEWORK_PATH",
        @"DYLD_ROOT_PATH",
        @"DYLD_SHARED_CACHE_DIR",
        @"DYLD_PRINT_TO_FILE",
        @"DYLD_PRINT_LIBRARIES",
        @"DYLD_PRINT_APIS",
        @"DYLD_PRINT_OPTS",
        @"DYLD_PRINT_ENV",
        @"LD_PRELOAD",
        @"_MSSafeMode",
        @"MSDebug",
        @"JB_SANDBOX_EXTENSIONS",
        @"SHELL"
    ];
    [out removeObjectsForKeys:deny];
    return [out copy];
}

%end

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]]) {
        NSString *scheme = [[url scheme] lowercaseString];
        if (scheme.length) {
            if ([scheme isEqualToString:@"cydia"] ||
                [scheme isEqualToString:@"sileo"] ||
                [scheme isEqualToString:@"zbra"] ||
                [scheme isEqualToString:@"filza"] ||
                [scheme isEqualToString:@"undecimus"] ||
                [scheme isEqualToString:@"checkra1n"] ||
                [scheme isEqualToString:@"odyssey"] ||
                [scheme isEqualToString:@"taurine"] ||
                [scheme isEqualToString:@"electra"]) {
                return NO;
            }
        }
    }
    return %orig;
}

%end

%hook LSApplicationWorkspace

- (NSArray *)allInstalledApplications {
    NSArray *apps = %orig;
    if (!PXJBShouldBypassCached()) return apps;
    if (![apps isKindOfClass:[NSArray class]] || apps.count == 0) return apps;

    static NSSet<NSString *> *deny = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        deny = [NSSet setWithArray:@[
            @"com.saurik.Cydia",
            @"org.coolstar.SileoStore",
            @"com.opa334.Sileo",
            @"xyz.willy.Zebra",
            @"com.tigisoftware.Filza",
        ]];
    });

    NSMutableArray *out = [NSMutableArray arrayWithCapacity:apps.count];
    for (id proxy in apps) {
        NSString *bid = nil;
        if ([proxy respondsToSelector:@selector(bundleIdentifier)]) {
            bid = [proxy performSelector:@selector(bundleIdentifier)];
        }
        if ([bid isKindOfClass:[NSString class]] && [deny containsObject:bid]) {
            continue;
        }
        [out addObject:proxy];
    }
    return out;
}

- (NSArray *)installedApplications {
    return [self allInstalledApplications];
}

- (NSArray *)allApplications {
    return [self allInstalledApplications];
}

%end

// --- Priority 1: NSBundle SignerIdentity ---
%hook NSBundle

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if (PXJBShouldBypassCached() && [key isKindOfClass:[NSString class]]) {
        if ([key isEqualToString:@"SignerIdentity"]) {
            return nil;
        }
    }
    return %orig;
}

+ (instancetype)bundleWithPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (instancetype)initWithPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

%end

// --- Priority 2: NSFileHandle hooks ---
%hook NSFileHandle

+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

%end

// --- Priority 2: UIImage hooks ---
%hook UIImage

- (instancetype)initWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

%end

// --- Priority 2: NSString file read/write hooks ---
%hook NSString

- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

%end

// --- Priority 2: NSArray file read/write hooks ---
%hook NSArray

- (id)initWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

%end

%hook NSMutableArray

- (id)initWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

%end

// --- Priority 2: NSDictionary file read/write hooks ---
%hook NSDictionary

- (id)initWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

%end

%hook NSMutableDictionary

- (id)initWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

%end

// --- Priority 2: NSData file read/write hooks ---
%hook NSData

- (instancetype)initWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)writeToFile:(NSString *)path options:(NSDataWritingOptions)writeOptionsMask error:(NSError **)error {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return NO;
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSDataWritingOptions)writeOptionsMask error:(NSError **)error {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

%end

// --- Priority 2: Known JB detection library class hooks ---
// These classes are from popular SDKs that apps embed for jailbreak detection.

%hook UIDevice
+ (BOOL)isJailbroken { return NO; }
- (BOOL)isJailBreak { return NO; }
- (BOOL)isJailBroken { return NO; }
%end

%hook JailbreakDetectionVC
- (BOOL)isJailbroken { return NO; }
%end

%hook DTTJailbreakDetection
+ (BOOL)isJailbroken { return NO; }
%end

%hook ANSMetadata
- (BOOL)computeIsJailbroken { return NO; }
- (BOOL)isJailbroken { return NO; }
%end

%hook AppsFlyerUtils
+ (BOOL)isJailBreakon { return NO; }
%end

%hook GBDeviceInfo
- (BOOL)isJailbroken { return NO; }
%end

%hook CMARAppRestrictionsDelegate
- (bool)isDeviceNonCompliant { return false; }
%end

%hook ADYSecurityChecks
+ (bool)isDeviceJailbroken { return false; }
%end

%hook UBReportMetadataDevice
- (void *)is_rooted { return NULL; }
%end

%hook UtilitySystem
+ (bool)isJailbreak { return false; }
%end

%hook GemaltoConfiguration
+ (bool)isJailbreak { return false; }
%end

%hook CPWRDeviceInfo
- (bool)isJailbroken { return false; }
%end

%hook CPWRSessionInfo
- (bool)isJailbroken { return false; }
%end

%hook KSSystemInfo
+ (bool)isJailbroken { return false; }
%end

%hook EMDSKPPConfiguration
- (bool)jailBroken { return false; }
%end

%hook EnrollParameters
- (void *)jailbroken { return NULL; }
%end

%hook EMDskppConfigurationBuilder
- (bool)jailbreakStatus { return false; }
%end

%hook FCRSystemMetadata
- (bool)isJailbroken { return false; }
%end

%hook v_VDMap
- (bool)isJailBrokenDetectedByVOS { return false; }
- (bool)isDFPHookedDetecedByVOS { return false; }
- (bool)isCodeInjectionDetectedByVOS { return false; }
- (bool)isDebuggerCheckDetectedByVOS { return false; }
- (bool)isAppSignerCheckDetectedByVOS { return false; }
- (bool)v_checkAModified { return false; }
%end

%hook SDMUtils
- (BOOL)isJailBroken { return NO; }
%end

%hook OneSignalJailbreakDetection
+ (BOOL)isJailbroken { return NO; }
%end

%hook DigiPassHandler
- (BOOL)rootedDeviceTestResult { return NO; }
%end

%hook AWMyDeviceGeneralInfo
- (bool)isCompliant { return true; }
%end

// --- Priority 3: NSDirectoryEnumerator filtering ---
%hook NSDirectoryEnumerator

- (id)nextObject {
    if (!PXJBShouldBypassCached()) return %orig;

    id obj = %orig;
    while (obj != nil) {
        NSString *path = nil;
        if ([obj isKindOfClass:[NSURL class]]) {
            NSURL *url = (NSURL *)obj;
            if ([url isFileURL]) path = [url path];
        } else if ([obj isKindOfClass:[NSString class]]) {
            path = (NSString *)obj;
        }
        if (path) {
            const char *p = [path fileSystemRepresentation];
            if (PXJBPathShouldHide(p)) {
                obj = %orig;
                continue;
            }
        }
        break;
    }
    return obj;
}

%end

// --- Priority 3: NSFileWrapper hooks ---
%hook NSFileWrapper

- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError **)outError {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (outError) *outError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return nil;
        }
    }
    return %orig;
}

- (instancetype)initWithPath:(NSString *)path {
    if (PXJBShouldBypassCached() && [path isKindOfClass:[NSString class]]) {
        const char *p = [path fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError **)outError {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (outError) *outError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError **)outError {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) {
            if (outError) *outError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
            return NO;
        }
    }
    return %orig;
}

%end

// --- Priority 3: NSFileVersion hooks ---
%hook NSFileVersion

+ (NSFileVersion *)currentVersionOfItemAtURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

+ (NSArray<NSFileVersion *> *)otherVersionsOfItemAtURL:(NSURL *)url {
    if (PXJBShouldBypassCached() && [url isKindOfClass:[NSURL class]] && [url isFileURL]) {
        const char *p = [[url path] fileSystemRepresentation];
        if (PXJBPathShouldHide(p)) return nil;
    }
    return %orig;
}

%end

// --- JailbreakDetector bypass: NSUserDefaults cfprefsd hook detection ---
// Block attempts to read JB plists via NSUserDefaults initWithSuiteName:.
static BOOL PXJBIsJBPlistSuiteName(NSString *suiteName) {
    if (!suiteName || ![suiteName isKindOfClass:[NSString class]]) return NO;
    static NSArray *jbPlistPrefixes = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        jbPlistPrefixes = @[
            @"/basebin/",
            @"com.opa334.",
            @"com.xina.",
            @"org.coolstar.",
            @"com.tigisoftware.",
            @"ws.hbang.",
            @"xyz.willy.",
            @"ru.domo.cocoatop",
            @"com.spark.snowboard",
            @"us.diatr.shshd",
            @"com.openssh.",
        ];
    });
    for (NSString *prefix in jbPlistPrefixes) {
        if ([suiteName hasPrefix:prefix]) return YES;
    }
    // Also block suite names that look like absolute JB paths
    if ([suiteName hasPrefix:@"/"] && PXJBPathShouldHide([suiteName fileSystemRepresentation])) return YES;
    return NO;
}

%hook NSUserDefaults

- (instancetype)initWithSuiteName:(NSString *)suitename {
    if (PXJBShouldBypassCached() && PXJBIsJBPlistSuiteName(suitename)) {
        // Return a blank defaults that has no stored keys
        return %orig(@"com.apple.does.not.exist.sentinel");
    }
    return %orig;
}

%end

// --- JailbreakDetector bypass: LSApplicationWorkspace installedPlugins ---
// Filter plugins belonging to known JB apps from the enumeration.
%hook LSApplicationWorkspace

- (NSArray *)installedPlugins {
    NSArray *plugins = %orig;
    if (!PXJBShouldBypassCached() || !plugins) return plugins;

    static NSSet *jbAppIDs = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        jbAppIDs = [NSSet setWithArray:@[
            @"com.xina.jailbreak",
            @"com.opa334.Dopamine",
            @"com.tigisoftware.Filza",
            @"org.coolstar.SileoStore",
            @"org.coolstar.Sileo",
            @"ws.hbang.Terminal",
            @"xyz.willy.Zebra",
            @"shshd",
            @"com.saurik.Cydia",
        ]];
    });

    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:plugins.count];
    for (id plugin in plugins) {
        if ([plugin respondsToSelector:@selector(containingBundle)]) {
            id appBundle = [plugin performSelector:@selector(containingBundle)];
            if (appBundle && [appBundle respondsToSelector:@selector(bundleIdentifier)]) {
                NSString *appID = [appBundle performSelector:@selector(bundleIdentifier)];
                if (appID && [jbAppIDs containsObject:appID]) continue; // skip JB plugin
            }
        }
        // Also check plugin identifier hash for obfuscated detection
        if ([plugin respondsToSelector:@selector(pluginIdentifier)]) {
            NSString *pluginID = [plugin performSelector:@selector(pluginIdentifier)];
            if (pluginID && [jbAppIDs containsObject:pluginID]) continue;
        }
        [filtered addObject:plugin];
    }
    return [filtered copy];
}

%end

%ctor {
    @autoreleasepool {
        // Install C hooks unconditionally; gate inside hooks for scoped apps.
        if (PXJBIsCriticalProcess()) return;

        // Install-time toggles (take effect after app relaunch).
        NSUserDefaults *ss = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
        BOOL wantSyscallHook = [ss boolForKey:@"jbBypassHookSyscallFallbackEnabled"]; // experimental
        BOOL wantDyldHide = [ss boolForKey:@"jbBypassHideDylibsEnabled"]; // experimental
        BOOL wantBlockAddImage = [ss boolForKey:@"jbBypassBlockDyldAddImageCallbacksEnabled"]; // experimental
        BOOL wantHideTaskDyldInfo = [ss boolForKey:@"jbBypassHideTaskDyldInfoEnabled"]; // experimental
        BOOL wantHideDlIteratePhdr = [ss boolForKey:@"jbBypassHideDlIteratePhdrEnabled"]; // experimental
        BOOL wantBlockDlopenDlsym = [ss boolForKey:@"jbBypassBlockDlopenDlsymProbesEnabled"]; // experimental
        BOOL wantSysctlSanitize = [ss boolForKey:@"jbBypassSysctlProcSanitizeEnabled"]; // experimental
        BOOL wantHideProcMaps = [ss boolForKey:@"jbBypassHideProcMapsEnabled"]; // experimental
        BOOL wantHideObjcImages = [ss boolForKey:@"jbBypassHideObjcImagesEnabled"]; // experimental
        BOOL wantSandboxCheck = [ss boolForKey:@"jbBypassHookSandboxCheckEnabled"]; // experimental
        void *libSystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
        if (libSystem) {
            void *sym = NULL;

            sym = FindSymbol(NULL, "stat");
            if (sym) MSHookFunction(sym, (void *)hook_stat, (void **)&orig_stat);

            sym = FindSymbol(NULL, "stat64");
            if (sym) MSHookFunction(sym, (void *)hook_stat64, (void **)&orig_stat64);

            sym = FindSymbol(NULL, "lstat");
            if (sym) MSHookFunction(sym, (void *)hook_lstat, (void **)&orig_lstat);

            sym = FindSymbol(NULL, "lstat64");
            if (sym) MSHookFunction(sym, (void *)hook_lstat64, (void **)&orig_lstat64);

            sym = FindSymbol(NULL, "access");
            if (sym) MSHookFunction(sym, (void *)hook_access, (void **)&orig_access);

            sym = FindSymbol(NULL, "open");
            if (sym) MSHookFunction(sym, (void *)hook_open, (void **)&orig_open);

            sym = FindSymbol(NULL, "openat");
            if (sym) MSHookFunction(sym, (void *)hook_openat, (void **)&orig_openat);

            sym = FindSymbol(NULL, "fopen");
            if (sym) MSHookFunction(sym, (void *)hook_fopen, (void **)&orig_fopen);

            sym = FindSymbol(NULL, "opendir");
            if (sym) MSHookFunction(sym, (void *)hook_opendir, (void **)&orig_opendir);

            sym = FindSymbol(NULL, "readdir");
            if (sym) MSHookFunction(sym, (void *)hook_readdir, (void **)&orig_readdir);

            sym = FindSymbol(NULL, "readlink");
            if (sym) MSHookFunction(sym, (void *)hook_readlink, (void **)&orig_readlink);

            sym = FindSymbol(NULL, "realpath");
            if (sym) MSHookFunction(sym, (void *)hook_realpath, (void **)&orig_realpath);

            sym = FindSymbol(NULL, "connect");
            if (sym) MSHookFunction(sym, (void *)hook_connect, (void **)&orig_connect);

            sym = FindSymbol(NULL, "getenv");
            if (sym) MSHookFunction(sym, (void *)hook_getenv, (void **)&orig_getenv);

            // Phase 2
            sym = FindSymbol(NULL, "ptrace");
            if (sym) MSHookFunction(sym, (void *)hook_ptrace, (void **)&orig_ptrace);

            sym = FindSymbol(NULL, "fork");
            if (sym) MSHookFunction(sym, (void *)hook_fork, (void **)&orig_fork);

            sym = FindSymbol(NULL, "vfork");
            if (sym) MSHookFunction(sym, (void *)hook_vfork, (void **)&orig_vfork);

            // Priority 1: UID/GID spoofing - hide root access.
            sym = FindSymbol(NULL, "getuid");
            if (sym) MSHookFunction(sym, (void *)hook_getuid, (void **)&orig_getuid);

            sym = FindSymbol(NULL, "geteuid");
            if (sym) MSHookFunction(sym, (void *)hook_geteuid, (void **)&orig_geteuid);

            sym = FindSymbol(NULL, "getgid");
            if (sym) MSHookFunction(sym, (void *)hook_getgid, (void **)&orig_getgid);

            sym = FindSymbol(NULL, "getegid");
            if (sym) MSHookFunction(sym, (void *)hook_getegid, (void **)&orig_getegid);

            sym = FindSymbol(NULL, "setuid");
            if (sym) MSHookFunction(sym, (void *)hook_setuid, (void **)&orig_setuid);

            sym = FindSymbol(NULL, "seteuid");
            if (sym) MSHookFunction(sym, (void *)hook_seteuid, (void **)&orig_seteuid);

            sym = FindSymbol(NULL, "setgid");
            if (sym) MSHookFunction(sym, (void *)hook_setgid, (void **)&orig_setgid);

            sym = FindSymbol(NULL, "setegid");
            if (sym) MSHookFunction(sym, (void *)hook_setegid, (void **)&orig_setegid);

            sym = FindSymbol(NULL, "setreuid");
            if (sym) MSHookFunction(sym, (void *)hook_setreuid, (void **)&orig_setreuid);

            sym = FindSymbol(NULL, "setregid");
            if (sym) MSHookFunction(sym, (void *)hook_setregid, (void **)&orig_setregid);

            // Priority 1: getppid spoofing.
            sym = FindSymbol(NULL, "getppid");
            if (sym) MSHookFunction(sym, (void *)hook_getppid, (void **)&orig_getppid);

            // Priority 1: csops — clear CS_PLATFORM_BINARY.
            sym = FindSymbol(NULL, "csops");
            if (sym) MSHookFunction(sym, (void *)hook_csops, (void **)&orig_csops);

            if (wantSyscallHook) {
                sym = FindSymbol(NULL, "syscall");
                if (sym) MSHookFunction(sym, (void *)hook_syscall, (void **)&orig_syscall);
            }

            sym = FindSymbol(NULL, "system");
            if (sym) MSHookFunction(sym, (void *)hook_system, (void **)&orig_system);

            sym = FindSymbol(NULL, "popen");
            if (sym) MSHookFunction(sym, (void *)hook_popen, (void **)&orig_popen);

            // Block probe spawns (safe default; gate inside hook).
            sym = FindSymbol(NULL, "posix_spawn");
            if (sym) MSHookFunction(sym, (void *)hook_posix_spawn, (void **)&orig_posix_spawn);

            sym = FindSymbol(NULL, "posix_spawnp");
            if (sym) MSHookFunction(sym, (void *)hook_posix_spawnp, (void **)&orig_posix_spawnp);

            // Optional: sandbox_check hook (default OFF)
            if (wantSandboxCheck) {
                sym = FindSymbol(NULL, "sandbox_check");
                if (sym) MSHookFunction(sym, (void *)hook_sandbox_check, (void **)&orig_sandbox_check);
            }

            // Phase 2 extension (toggle: jbBypassStatfsEnabled)
            sym = FindSymbol(NULL, "statfs");
            if (sym) MSHookFunction(sym, (void *)hook_statfs, (void **)&orig_statfs);

            sym = FindSymbol(NULL, "fstatfs");
            if (sym) MSHookFunction(sym, (void *)hook_fstatfs, (void **)&orig_fstatfs);

            sym = FindSymbol(NULL, "statvfs");
            if (sym) MSHookFunction(sym, (void *)hook_statvfs, (void **)&orig_statvfs);

            sym = FindSymbol(NULL, "fstatvfs");
            if (sym) MSHookFunction(sym, (void *)hook_fstatvfs, (void **)&orig_fstatvfs);

            // Priority 3: dlopen_preflight, creat, fstat variants, fs mutation hooks.
            sym = FindSymbol(NULL, "dlopen_preflight");
            if (sym) MSHookFunction(sym, (void *)hook_dlopen_preflight, (void **)&orig_dlopen_preflight);

            sym = FindSymbol(NULL, "creat");
            if (sym) MSHookFunction(sym, (void *)hook_creat, (void **)&orig_creat);

            sym = FindSymbol(NULL, "fstat");
            if (sym) MSHookFunction(sym, (void *)hook_fstat, (void **)&orig_fstat);

            sym = FindSymbol(NULL, "fstatat");
            if (sym) MSHookFunction(sym, (void *)hook_fstatat, (void **)&orig_fstatat);

            sym = FindSymbol(NULL, "faccessat");
            if (sym) MSHookFunction(sym, (void *)hook_faccessat, (void **)&orig_faccessat);

            sym = FindSymbol(NULL, "readlinkat");
            if (sym) MSHookFunction(sym, (void *)hook_readlinkat, (void **)&orig_readlinkat);

            sym = FindSymbol(NULL, "symlink");
            if (sym) MSHookFunction(sym, (void *)hook_symlink, (void **)&orig_symlink);

            sym = FindSymbol(NULL, "rename");
            if (sym) MSHookFunction(sym, (void *)hook_rename, (void **)&orig_rename);

            sym = FindSymbol(NULL, "link");
            if (sym) MSHookFunction(sym, (void *)hook_link, (void **)&orig_link);

            sym = FindSymbol(NULL, "unlink");
            if (sym) MSHookFunction(sym, (void *)hook_unlink, (void **)&orig_unlink);

            sym = FindSymbol(NULL, "remove");
            if (sym) MSHookFunction(sym, (void *)hook_remove_func, (void **)&orig_remove_func);

            sym = FindSymbol(NULL, "rmdir");
            if (sym) MSHookFunction(sym, (void *)hook_rmdir, (void **)&orig_rmdir);

            // Priority 3: objc_copyClassNamesForImage, NSVersionOf*.
            sym = FindSymbol(NULL, "objc_copyClassNamesForImage");
            if (sym) MSHookFunction(sym, (void *)hook_objc_copyClassNamesForImage, (void **)&orig_objc_copyClassNamesForImage);

            sym = FindSymbol(NULL, "NSVersionOfRunTimeLibrary");
            if (sym) MSHookFunction(sym, (void *)hook_NSVersionOfRunTimeLibrary, (void **)&orig_NSVersionOfRunTimeLibrary);

            sym = FindSymbol(NULL, "NSVersionOfLinkTimeLibrary");
            if (sym) MSHookFunction(sym, (void *)hook_NSVersionOfLinkTimeLibrary, (void **)&orig_NSVersionOfLinkTimeLibrary);

            // JailbreakDetector bypass hooks.
            sym = FindSymbol(NULL, "getmntinfo");
            if (sym) MSHookFunction(sym, (void *)hook_getmntinfo, (void **)&orig_getmntinfo);

            sym = FindSymbol(NULL, "bootstrap_look_up");
            if (sym) MSHookFunction(sym, (void *)hook_bootstrap_look_up, (void **)&orig_bootstrap_look_up);

            sym = FindSymbol(NULL, "vm_region_64");
            if (sym) MSHookFunction(sym, (void *)hook_vm_region_64, (void **)&orig_vm_region_64);

            sym = FindSymbol(NULL, "task_get_exception_ports");
            if (sym) MSHookFunction(sym, (void *)hook_task_get_exception_ports, (void **)&orig_task_get_exception_ports);

            sym = FindSymbol(NULL, "fcntl");
            if (sym) MSHookFunction(sym, (void *)hook_fcntl, (void **)&orig_fcntl);

            sym = FindSymbol(NULL, "xpc_pipe_routine");
            if (sym) MSHookFunction(sym, (void *)hook_xpc_pipe_routine, (void **)&orig_xpc_pipe_routine);

            sym = FindSymbol(NULL, "xpc_pipe_routine_with_flags");
            if (sym) MSHookFunction(sym, (void *)hook_xpc_pipe_routine_with_flags, (void **)&orig_xpc_pipe_routine_with_flags);

            // Phase 3 (toggle: jbBypassHideDylibsEnabled). Install only when explicitly enabled.
            if (wantDyldHide) {
                sym = FindSymbol(NULL, "_dyld_image_count");
                if (sym) {
                    if (!real__dyld_image_count) {
                        real__dyld_image_count = (uint32_t (*)(void))sym;
                    }
                    MSHookFunction(sym, (void *)hook__dyld_image_count, (void **)&orig__dyld_image_count);
                }

                sym = FindSymbol(NULL, "_dyld_get_image_name");
                if (sym) {
                    if (!real__dyld_get_image_name) {
                        real__dyld_get_image_name = (const char *(*)(uint32_t))sym;
                    }
                    MSHookFunction(sym, (void *)hook__dyld_get_image_name, (void **)&orig__dyld_get_image_name);
                }

                sym = FindSymbol(NULL, "_dyld_get_image_header");
                if (sym) {
                    if (!real__dyld_get_image_header) {
                        real__dyld_get_image_header = (const struct mach_header *(*)(uint32_t))sym;
                    }
                    MSHookFunction(sym, (void *)hook__dyld_get_image_header, (void **)&orig__dyld_get_image_header);
                }

                sym = FindSymbol(NULL, "_dyld_get_image_vmaddr_slide");
                if (sym) {
                    if (!real__dyld_get_image_vmaddr_slide) {
                        real__dyld_get_image_vmaddr_slide = (intptr_t (*)(uint32_t))sym;
                    }
                    MSHookFunction(sym, (void *)hook__dyld_get_image_vmaddr_slide, (void **)&orig__dyld_get_image_vmaddr_slide);
                }

                sym = FindSymbol(NULL, "dladdr");
                if (sym) MSHookFunction(sym, (void *)hook_dladdr, (void **)&orig_dladdr);
            }

            // Phase 3 extension: block suspicious add_image callback registrations.
            if (wantBlockAddImage) {
                // _dyld_register_func_for_add_image is in libdyld/dyld; dlsym RTLD_DEFAULT works.
                sym = FindSymbol(NULL, "_dyld_register_func_for_add_image");
                if (sym) {
                    // See hook implementation below (near dyld helpers).
                    extern void PXJBInstallDyldAddImageBlocker(void *sym);
                    PXJBInstallDyldAddImageBlocker(sym);
                }
            }

            // Phase 3 extension: hide TASK_DYLD_INFO via task_info.
            if (wantHideTaskDyldInfo) {
                sym = FindSymbol(NULL, "task_info");
                if (sym) {
                    extern void PXJBInstallTaskInfoHook(void *sym);
                    PXJBInstallTaskInfoHook(sym);
                }
            }

            // Phase 3 extension: hide dl_iterate_phdr enumeration.
            if (wantHideDlIteratePhdr) {
                sym = FindSymbol(NULL, "dl_iterate_phdr");
                if (sym) {
                    MSHookFunction(sym, (void *)hook_dl_iterate_phdr, (void **)&orig_dl_iterate_phdr);
                }
            }

            // Phase 4: block dlopen/dlsym probes.
            if (wantBlockDlopenDlsym) {
                sym = FindSymbol(NULL, "dlopen");
                if (sym) MSHookFunction(sym, (void *)hook_dlopen, (void **)&orig_dlopen);
                sym = FindSymbol(NULL, "dlsym");
                if (sym) MSHookFunction(sym, (void *)hook_dlsym, (void **)&orig_dlsym);
            }

            // Phase 5: sysctl/sysctlbyname sanitize.
            if (wantSysctlSanitize) {
                sym = FindSymbol(NULL, "sysctl");
                if (sym) MSHookFunction(sym, (void *)hook_sysctl_jb, (void **)&orig_sysctl_jb);
                sym = FindSymbol(NULL, "sysctlbyname");
                if (sym) MSHookFunction(sym, (void *)hook_sysctlbyname_jb, (void **)&orig_sysctlbyname_jb);
            }

            // Phase 6: hide proc map filenames (libproc).
            if (wantHideProcMaps) {
                sym = FindSymbol(NULL, "proc_regionfilename");
                if (sym) {
                    MSHookFunction(sym, (void *)hook_proc_regionfilename, (void **)&orig_proc_regionfilename);
                }
            }

            // Phase 7: hide ObjC runtime image list.
            if (wantHideObjcImages) {
                sym = FindSymbol(NULL, "objc_copyImageNames");
                if (sym) {
                    MSHookFunction(sym, (void *)hook_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
                }
                sym = FindSymbol(NULL, "class_getImageName");
                if (sym) {
                    MSHookFunction(sym, (void *)hook_class_getImageName, (void **)&orig_class_getImageName);
                }
            }

            dlclose(libSystem);
        }

        %init;

        // Proactive env cleanup (safe) for scoped apps.
        PXJBUnsetSuspiciousEnvIfNeeded();
        dispatch_async(dispatch_get_main_queue(), ^{
            PXJBUnsetSuspiciousEnvIfNeeded();
        });
        PXLog(@"[JailbreakBypass] Phase 1 hooks initialized");
    }
}

// --- Optional strong hooks (installed only when toggle is enabled at launch) ---
static void (*orig__dyld_register_func_for_add_image)(void (*func)(const struct mach_header *, intptr_t));
static void hook__dyld_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t)) {
    if (!orig__dyld_register_func_for_add_image) return;
    if (!PXJBBlockDyldAddImageCallbacksEnabled() || !func) {
        orig__dyld_register_func_for_add_image(func);
        return;
    }
    Dl_info info;
    if (dladdr((const void *)func, &info) && info.dli_fname) {
        if (PXJBShouldHideImageName(info.dli_fname)) {
            return;
        }
    }
    orig__dyld_register_func_for_add_image(func);
}

void PXJBInstallDyldAddImageBlocker(void *sym) {
    if (!sym) return;
    MSHookFunction(sym, (void *)hook__dyld_register_func_for_add_image, (void **)&orig__dyld_register_func_for_add_image);
}

static kern_return_t (*orig_task_info)(task_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
static kern_return_t hook_task_info(task_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    if (!orig_task_info) return KERN_INVALID_ARGUMENT;
    if (!PXJBHideTaskDyldInfoEnabled()) {
        return orig_task_info(target_task, flavor, task_info_out, task_info_outCnt);
    }
    if (target_task != mach_task_self()) {
        return orig_task_info(target_task, flavor, task_info_out, task_info_outCnt);
    }
#ifdef TASK_DYLD_INFO
    if (flavor == TASK_DYLD_INFO) {
        if (task_info_outCnt) *task_info_outCnt = 0;
        return KERN_INVALID_ARGUMENT;
    }
#endif
    return orig_task_info(target_task, flavor, task_info_out, task_info_outCnt);
}

void PXJBInstallTaskInfoHook(void *sym) {
    if (!sym) return;
    MSHookFunction(sym, (void *)hook_task_info, (void **)&orig_task_info);
}
