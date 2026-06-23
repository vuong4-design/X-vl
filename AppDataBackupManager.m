#import "AppDataBackupManager.h"

#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <CoreFoundation/CoreFoundation.h>

#import "AppDataCleaner.h"
#import "FreezeManager.h"

#import "AppEntitlementsReader.h"
#import "AppGroupContainerResolver.h"
#import "CommandRunner.h"
#import "common/PXProcessKiller.h"

#import <CommonCrypto/CommonDigest.h>
#import <notify.h>

static NSString * const PXBackupErrorDomain = @"com.hydra.projectx.backup";

@implementation PXBackupResult
@end

@implementation PXRestoreResult
@end

@implementation AppDataBackupManager

static NSString *PXDataContainerPathFromLaunchServices(NSString *bundleID);

static void PXDebugAppendLine(NSString *path, NSString *line) {
    if (!path.length || !line.length) return;
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *dir = [path stringByDeletingLastPathComponent];
        if (dir.length) {
            [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        }
        NSString *out = [line stringByAppendingString:@"\n"];
        NSData *data = [out dataUsingEncoding:NSUTF8StringEncoding];
        if (!data) return;

        if (![fm fileExistsAtPath:path]) {
            [data writeToFile:path atomically:YES];
            return;
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [data writeToFile:path atomically:YES];
            return;
        }
        @try {
            [fh seekToEndOfFile];
            [fh writeData:data];
        } @catch (__unused NSException *e) {
        }
        [fh closeFile];
    }
}

static void PXDebugHeader(NSString *path, NSString *title) {
    PXDebugAppendLine(path, @"----------------------------------------");
    PXDebugAppendLine(path, [NSString stringWithFormat:@"[%@] %@", [NSDate date], title ?: @""]);
}

static void PXDebugRun(CommandRunner *runner, NSString *path, NSString *label, NSString *cmd) {
    if (!runner || !path.length || !cmd.length) return;
    PXDebugAppendLine(path, [NSString stringWithFormat:@"> %@", label ?: @"cmd"]);
    PXDebugAppendLine(path, [NSString stringWithFormat:@"$ %@", cmd]);
    CommandResult *res = [runner runAndCapture:cmd];
    PXDebugAppendLine(path, [NSString stringWithFormat:@"exit=%d", (int)res.exitCode]);
    if (res.stdoutString.length) {
        PXDebugAppendLine(path, @"[stdout]");
        PXDebugAppendLine(path, res.stdoutString);
    }
    if (res.stderrString.length) {
        PXDebugAppendLine(path, @"[stderr]");
        PXDebugAppendLine(path, res.stderrString);
    }
}

static NSDictionary *PXResolvePathsForBundleID(NSString *bundleID) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"bundleID"] = bundleID ?: @"";

    NSString *dataPath = PXDataContainerPathFromLaunchServices(bundleID);
    if (dataPath) out[@"lsDataContainerPath"] = dataPath;

    // Also capture containerURL for debugging (may be bundle container).
    NSString *containerURLPath = nil;
    @autoreleasepool {
        Class LSApplicationProxyClass = NSClassFromString(@"LSApplicationProxy");
        SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
        if (LSApplicationProxyClass && [LSApplicationProxyClass respondsToSelector:sel]) {
            id proxy = ((id (*)(id, SEL, id))objc_msgSend)(LSApplicationProxyClass, sel, bundleID);
            if (proxy) {
                id url = nil;
                @try { url = [proxy valueForKey:@"containerURL"]; } @catch (__unused NSException *e) {}
                if ([url isKindOfClass:[NSURL class]]) {
                    containerURLPath = [(NSURL *)url path];
                } else if ([url isKindOfClass:[NSString class]]) {
                    containerURLPath = (NSString *)url;
                }
            }
        }
    }
    if (containerURLPath) out[@"lsContainerURLPath"] = containerURLPath;

    return out;
}

+ (instancetype)shared {
    static AppDataBackupManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

static NSString *PXShellQuote(NSString *s) {
    NSString *escaped = [s stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"]; 
    return [NSString stringWithFormat:@"'%@'", escaped];
}

static NSString *PXSanitizeFilenameComponent(NSString *s) {
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"].invertedSet;
    NSString *out = [[s componentsSeparatedByCharactersInSet:allowed] componentsJoinedByString:@"_"];
    return out.length ? out : @"unknown";
}

static NSString *PXDataContainerPathFromLaunchServices(NSString *bundleID) {
    if (!bundleID.length) return nil;
    Class LSApplicationProxyClass = NSClassFromString(@"LSApplicationProxy");
    if (!LSApplicationProxyClass) return nil;

    SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    if (![LSApplicationProxyClass respondsToSelector:sel]) return nil;

    id proxy = ((id (*)(id, SEL, id))objc_msgSend)(LSApplicationProxyClass, sel, bundleID);
    if (!proxy) return nil;

    id url = nil;
    @try {
        url = [proxy valueForKey:@"dataContainerURL"]; 
        if (!url) {
            url = [proxy valueForKey:@"containerURL"]; 
        }
    } @catch (__unused NSException *e) {
        url = nil;
    }
    if ([url isKindOfClass:[NSURL class]]) {
        return [(NSURL *)url path];
    }
    if ([url isKindOfClass:[NSString class]]) {
        return (NSString *)url;
    }
    return nil;
}

static NSString *PXBackupKeychainGroupsKey(NSString *bundleID) {
    return [NSString stringWithFormat:@"dataBackupKeychainGroups_%@", bundleID ?: @""];
}

static NSData *PXFileSHA256(NSString *path) {
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return nil;
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    for (;;) {
        @autoreleasepool {
            NSData *data = [fh readDataOfLength:(1024 * 1024)];
            if (!data.length) {
                break;
            }
            CC_SHA256_Update(&ctx, data.bytes, (CC_LONG)data.length);
        }
    }
    [fh closeFile];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);
    return [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
}

static NSString *PXHexString(NSData *data) {
    if (!data.length) return @"";
    const unsigned char *bytes = data.bytes;
    NSMutableString *out = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [out appendFormat:@"%02x", bytes[i]];
    }
    return out;
}

static NSDictionary *PXArtifactInfo(NSString *path, NSString *name) {
    if (!path.length) return nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
    NSNumber *size = attrs[NSFileSize];
    NSData *sha = PXFileSHA256(path);
    return @{
        @"name": name ?: path.lastPathComponent ?: @"",
        @"path": path,
        @"size": size ?: @0,
        @"sha256": sha ? PXHexString(sha) : @""
    };
}

static BOOL PXContainerUUIDMatchesBundleID(NSFileManager *fm, NSString *baseDir, NSString *uuid, NSString *bundleID) {
    if (!baseDir.length || !uuid.length || !bundleID.length) return NO;
    NSString *containerPath = [baseDir stringByAppendingPathComponent:uuid];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:containerPath isDirectory:&isDir] || !isDir) return NO;
    NSString *metadataPath = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
    NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
    id ident = [meta isKindOfClass:[NSDictionary class]] ? meta[@"MCMMetadataIdentifier"] : nil;
    if ([ident isKindOfClass:[NSString class]]) {
        return [(NSString *)ident isEqualToString:bundleID];
    }
    if ([ident isKindOfClass:[NSArray class]]) {
        return [(NSArray *)ident containsObject:bundleID];
    }
    return NO;
}

static NSString *PXFindDataContainerUUIDByMetadata(NSFileManager *fm, NSString *baseDir, NSString *bundleID) {
    if (!baseDir.length || !bundleID.length) return nil;
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:baseDir isDirectory:&isDir] || !isDir) return nil;
    NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:baseDir error:nil];
    for (NSString *uuid in items) {
        if (![uuid isKindOfClass:[NSString class]] || uuid.length < 8) continue;
        if ([uuid hasPrefix:@"."]) continue;
        if (PXContainerUUIDMatchesBundleID(fm, baseDir, uuid, bundleID)) {
            return uuid;
        }
    }
    return nil;
}

- (void)_killRelatedProcessesForBundleID:(NSString *)bundleID {
    // Always kill the main app process via existing manager.
    [[FreezeManager sharedManager] killApplication:bundleID];

    // Best-effort hard kill by executable name (helps when the app is SIGSTOP'd).
    @try {
        if (bundleID.length) {
            Class proxyCls = NSClassFromString(@"LSApplicationProxy");
            SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
            id proxy = (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
            NSString *exe = nil;
            if (proxy && [proxy respondsToSelector:@selector(bundleExecutable)]) {
                exe = [proxy performSelector:@selector(bundleExecutable)];
            }
            if ([exe isKindOfClass:[NSString class]] && exe.length) {
                PXKillallByName(exe, SIGKILL);
            }
        }
    } @catch (__unused NSException *e) {
    }

    // Safari has multiple helper processes that can keep databases open.
    if ([bundleID isEqualToString:@"com.apple.mobilesafari"]) {
        NSArray<NSString *> *names = @[
            @"MobileSafari",
            @"SafariViewService",
            @"com.apple.WebKit.WebContent",
            @"com.apple.WebKit.Networking"
        ];
        PXKillallTermThenKillMany(names, 0.1);
    }

    // Generic extra stopping for system apps: many have an associated daemon named <exe> + "d".
    @try {
        Class proxyCls = NSClassFromString(@"LSApplicationProxy");
        SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
        id proxy = (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
        NSString *appType = nil;
        NSString *exe = nil;
        if (proxy) {
            @try { appType = [proxy valueForKey:@"applicationType"]; } @catch (__unused NSException *e) {}
            @try { exe = [proxy valueForKey:@"bundleExecutable"]; } @catch (__unused NSException *e) {}
        }

        BOOL isSystem = ([appType isKindOfClass:[NSString class]] && [(NSString *)appType isEqualToString:@"System"]);
        if (isSystem && [exe isKindOfClass:[NSString class]] && exe.length) {
            NSString *daemon = [[(NSString *)exe lowercaseString] stringByAppendingString:@"d"]; 
            NSArray<NSString *> *names = @[ (NSString *)exe, daemon ];
            PXKillallTermThenKillMany(names, 0.15);
        }
    } @catch (__unused NSException *e) {
    }
}

- (NSString *)_globalSafariLibraryPath {
    CommandRunner *runner = [CommandRunner shared];
    return [runner firstExistingPath:@[
        @"/var/mobile/Library/Safari",
        @"/private/var/mobile/Library/Safari",
        @"/var/jb/var/mobile/Library/Safari",
        @"/private/var/jb/var/mobile/Library/Safari"
    ]];
}

- (CommandResult *)_tarCreate:(NSString *)tarPath fromDir:(NSString *)sourceDir toArchive:(NSString *)archivePath {
    CommandRunner *runner = [CommandRunner shared];

    // Prefer preserving extended attributes (file protection class), ACLs and numeric owners.
    NSString *cmd = [NSString stringWithFormat:@"%@ --xattrs --acls --numeric-owner -czf %@ --exclude '.com.apple.mobile_container_manager.metadata.plist' --exclude '.com.apple.containermanagerd.metadata.plist' -C %@ .",
                     PXShellQuote(tarPath),
                     PXShellQuote(archivePath),
                     PXShellQuote(sourceDir)];
    CommandResult *res = [runner runAndCapture:cmd];
    if (res.exitCode == 0) {
        return res;
    }

    // Fallback for tar variants without these flags.
    NSString *fallback = [NSString stringWithFormat:@"%@ -czf %@ --exclude '.com.apple.mobile_container_manager.metadata.plist' --exclude '.com.apple.containermanagerd.metadata.plist' -C %@ .",
                          PXShellQuote(tarPath),
                          PXShellQuote(archivePath),
                          PXShellQuote(sourceDir)];
    return [runner runAndCapture:fallback];
}

static NSString *PXTimestampSuffix(void) {
    return [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
}

- (NSString *)_mobileLibraryBasePath {
    // Support rootful + common jailbreak layouts.
    CommandRunner *runner = [CommandRunner shared];
    NSString *dir = [runner firstExistingPath:@[
        @"/var/mobile/Library",
        @"/private/var/mobile/Library",
        @"/var/jb/var/mobile/Library",
        @"/private/var/jb/var/mobile/Library"
    ]];
    return dir ?: @"/var/mobile/Library";
}

- (BOOL)_isSystemAppBundleID:(NSString *)bundleID {
    if (!bundleID.length) return NO;
    @try {
        Class proxyCls = NSClassFromString(@"LSApplicationProxy");
        SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
        id proxy = (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
        NSString *appType = nil;
        if (proxy) {
            @try { appType = [proxy valueForKey:@"applicationType"]; } @catch (__unused NSException *e) {}
        }
        return ([appType isKindOfClass:[NSString class]] && [(NSString *)appType isEqualToString:@"System"]);
    } @catch (__unused NSException *e) {
        return NO;
    }
}

static NSArray<NSDictionary *> *PXSharedSystemDBSpecs(void) {
    // Shared, system-scoped databases that are commonly used by multiple system apps.
    // Paths are relative to /var/mobile/Library.
    return @[
        @{ @"libraryRel": @"Accounts/Accounts3.sqlite", @"backupName": @"Accounts3.sqlite" },
        @{ @"libraryRel": @"SMS/sms.db", @"backupName": @"sms.db" },
        @{ @"libraryRel": @"Calendar/Calendar.sqlitedb", @"backupName": @"Calendar.sqlitedb" },
        @{ @"libraryRel": @"AddressBook/AddressBook.sqlitedb", @"backupName": @"AddressBook.sqlitedb" },

        // Notes database name varies by iOS.
        @{ @"libraryRel": @"Notes/NoteStore.sqlite", @"backupName": @"NoteStore.sqlite" },
        @{ @"libraryRel": @"Notes/notes.sqlite", @"backupName": @"notes.sqlite" },
    ];
}

static NSArray<NSDictionary *> *PXExpandSQLiteSidecars(NSDictionary *spec) {
    // For sqlite DBs, also include -wal and -shm if they exist.
    NSString *rel = [spec[@"libraryRel"] isKindOfClass:[NSString class]] ? spec[@"libraryRel"] : nil;
    NSString *bn = [spec[@"backupName"] isKindOfClass:[NSString class]] ? spec[@"backupName"] : nil;
    if (!rel.length || !bn.length) return @[];

    return @[
        @{ @"libraryRel": rel, @"backupName": bn },
        @{ @"libraryRel": [rel stringByAppendingString:@"-wal"], @"backupName": [bn stringByAppendingString:@"-wal"] },
        @{ @"libraryRel": [rel stringByAppendingString:@"-shm"], @"backupName": [bn stringByAppendingString:@"-shm"] },
    ];
}

static NSString *PXCleanSubdirName(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || !s.length) return nil;
    NSString *name = [s lastPathComponent];
    if (!name.length) return nil;
    if ([name containsString:@"/"] || [name containsString:@"\\"]) return nil;
    if ([name isEqualToString:@"."] || [name isEqualToString:@".."]) return nil;
    return name;
}

- (NSArray<NSDictionary *> *)_systemGlobalLibraryItemsForBundleID:(NSString *)bundleID {
    if (!bundleID.length) return @[];

    NSString *appType = nil;
    NSString *exe = nil;
    NSString *localized = nil;
    @autoreleasepool {
        Class proxyCls = NSClassFromString(@"LSApplicationProxy");
        SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
        id proxy = (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
        if (proxy) {
            @try { appType = [proxy valueForKey:@"applicationType"]; } @catch (__unused NSException *e) {}
            @try { exe = [proxy valueForKey:@"bundleExecutable"]; } @catch (__unused NSException *e) {}
            @try { localized = [proxy valueForKey:@"localizedName"]; } @catch (__unused NSException *e) {}
        }
    }

    BOOL isSystem = ([appType isKindOfClass:[NSString class]] && [(NSString *)appType isEqualToString:@"System"]);
    if (!isSystem) return @[];

    NSMutableOrderedSet<NSString *> *candidates = [NSMutableOrderedSet orderedSet];
    NSString *a = PXCleanSubdirName(localized);
    NSString *b = PXCleanSubdirName(exe);
    if (a.length) [candidates addObject:a];
    if (b.length) [candidates addObject:b];

    NSString *base = [self _mobileLibraryBasePath];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSDictionary *> *items = [NSMutableArray array];
    for (NSString *subdir in candidates.array) {
        NSString *p = [base stringByAppendingPathComponent:subdir];
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:p isDirectory:&isDir] && isDir) {
            [items addObject:@{ @"subdir": subdir, @"path": p }];
        }
    }
    return items;
}

- (CommandResult *)_tarExtract:(NSString *)tarPath archive:(NSString *)archivePath toDir:(NSString *)destDir {
    CommandRunner *runner = [CommandRunner shared];

    NSString *cmd = [NSString stringWithFormat:@"%@ --xattrs --acls -xzf %@ -C %@",
                     PXShellQuote(tarPath),
                     PXShellQuote(archivePath),
                     PXShellQuote(destDir)];
    CommandResult *res = [runner runAndCapture:cmd];
    if (res.exitCode == 0) {
        return res;
    }

    NSString *fallback = [NSString stringWithFormat:@"%@ -xzf %@ -C %@",
                          PXShellQuote(tarPath),
                          PXShellQuote(archivePath),
                          PXShellQuote(destDir)];
    return [runner runAndCapture:fallback];
}

- (NSString *)_preferencesDirectory {
    // Support rootful + common jailbreak layouts.
    CommandRunner *runner = [CommandRunner shared];
    NSString *dir = [runner firstExistingPath:@[
        @"/var/mobile/Library/Preferences",
        @"/private/var/mobile/Library/Preferences",
        @"/var/jb/var/mobile/Library/Preferences",
        @"/private/var/jb/var/mobile/Library/Preferences"
    ]];
    return dir ?: @"/var/mobile/Library/Preferences";
}

- (NSString *)_profileAppDataPathForBundleID:(NSString *)bundleID {
    NSString *profileId = [self _activeProfileId];
    if (!profileId.length || !bundleID.length) {
        return nil;
    }

    CommandRunner *runner = [CommandRunner shared];
    NSString *path = [runner firstExistingPath:@[
        [NSString stringWithFormat:@"/var/mobile/Library/WeaponX/Profiles/%@/appdata/%@", profileId, bundleID],
        [NSString stringWithFormat:@"/private/var/mobile/Library/WeaponX/Profiles/%@/appdata/%@", profileId, bundleID]
    ]];
    return path;
}

- (NSArray<NSString *> *)_wipeDirectoryContents:(NSString *)dirPath {
    if (!dirPath.length) {
        return @[];
    }
    // Wipe everything inside the directory, but preserve container metadata files.
    // Deleting these can break MCM/LaunchServices container mapping (especially for App Groups).
    // A1: returns the list of paths that failed to delete so callers can react
    // (data container restore treats a non-empty result as a hard failure to
    // avoid mixing stale and restored data).
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *listErr = nil;
    NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:dirPath error:&listErr];
    if (!items.count) {
        return @[];
    }
    NSSet<NSString *> *preserve = [NSSet setWithArray:@[
        @".com.apple.mobile_container_manager.metadata.plist",
        @".com.apple.containermanagerd.metadata.plist"
    ]];
    NSMutableArray<NSString *> *failed = [NSMutableArray array];
    for (NSString *name in items) {
        if (![name isKindOfClass:[NSString class]] || !name.length) continue;
        if ([preserve containsObject:name]) {
            continue;
        }
        NSString *p = [dirPath stringByAppendingPathComponent:name];
        NSError *rmErr = nil;
        if (![fm removeItemAtPath:p error:&rmErr]) {
            // Re-check existence: removeItemAtPath can report failure even when
            // the entry is already gone in some edge cases.
            if ([fm fileExistsAtPath:p]) {
                [failed addObject:p];
            }
        }
    }
    return failed;
}

- (NSString *)_preferencesPlistPathForBundleID:(NSString *)bundleID {
    NSString *prefsDir = [self _preferencesDirectory];
    return [prefsDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.plist", bundleID]];
}

#pragma mark - Keychain Backup/Restore Helpers

- (NSString *)_keychainBackupScriptPath {
    CommandRunner *runner = [CommandRunner shared];
    return [runner firstExistingPath:@[
        @"/Library/WeaponX/keychain_backup.sh",
        @"/var/jb/Library/WeaponX/keychain_backup.sh",
        @"/private/var/jb/Library/WeaponX/keychain_backup.sh"
    ]];
}

static BOOL PXGroupsContainPlatformFamily(NSArray<NSString *> *groups) {
    for (NSString *g in groups) {
        if (![g isKindOfClass:[NSString class]]) continue;
        if ([g hasSuffix:@".platformFamily"] || [g containsString:@"platformFamily"]) {
            return YES;
        }
    }
    return NO;
}

static NSUInteger PXKeychainPlistItemCount(NSString *plistPath) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    if (![d isKindOfClass:[NSDictionary class]]) return 0;
    id items = d[@"items"];
    if ([items isKindOfClass:[NSArray class]]) {
        return [(NSArray *)items count];
    }
    return 0;
}

static BOOL PXOpenApplication(NSString *bundleID) {
    if (!bundleID.length) return NO;
    Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
    if (!wsCls) return NO;
    id ws = [wsCls performSelector:@selector(defaultWorkspace)];
    if (!ws) return NO;
    if ([ws respondsToSelector:@selector(openApplicationWithBundleID:)]) {
        BOOL (*msgSend)(id, SEL, id) = (BOOL (*)(id, SEL, id))objc_msgSend;
        return msgSend(ws, @selector(openApplicationWithBundleID:), bundleID);
    }
    return NO;
}

static NSString *PXSafeBundleString(NSString *bundleID) {
    if (!bundleID.length) return @"unknown";
    NSCharacterSet *allowed = [NSCharacterSet alphanumericCharacterSet];
    NSMutableString *out = [NSMutableString stringWithCapacity:bundleID.length];
    for (NSUInteger i = 0; i < bundleID.length; i++) {
        unichar c = [bundleID characterAtIndex:i];
        if ([allowed characterIsMember:c]) {
            [out appendFormat:@"%C", c];
        } else {
            [out appendString:@"_"];
        }
    }
    return out;
}

static void PXDarwinNotifyPost(NSString *name) {
    if (!name.length) return;
    CFNotificationCenterRef c = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationCenterPostNotification(c, (__bridge CFStringRef)name, NULL, NULL, true);
}

static NSDictionary *PXReadKeychainBridgeResponseIfValid(NSFileManager *fm, NSString *respPath, NSString *nonce) {
    if (!fm || !respPath.length || !nonce.length) return nil;
    if (![fm fileExistsAtPath:respPath]) return nil;
    NSDictionary *candidate = [NSDictionary dictionaryWithContentsOfFile:respPath];
    if (![candidate isKindOfClass:[NSDictionary class]]) return nil;
    NSString *n = [candidate[@"nonce"] isKindOfClass:[NSString class]] ? candidate[@"nonce"] : nil;
    if (!n.length || ![n isEqualToString:nonce]) return nil;
    return candidate;
}

static NSDictionary *PXWaitForKeychainBridgeResponse(NSString *safeBundle, NSString *respPath, NSString *nonce, NSTimeInterval timeoutSec) {
    if (!safeBundle.length || !respPath.length || !nonce.length) return nil;
    if (timeoutSec <= 0) timeoutSec = 20.0;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *immediate = PXReadKeychainBridgeResponseIfValid(fm, respPath, nonce);
    if (immediate) return immediate;

    NSString *notifyName = [NSString stringWithFormat:@"com.hydra.weaponx.keychain.resp.%@", safeBundle];
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    dispatch_queue_t q = dispatch_queue_create("com.weaponx.keychainbridge.wait.backup", DISPATCH_QUEUE_SERIAL);
    __block NSDictionary *resp = nil;

    int token = 0;
    uint32_t st = notify_register_dispatch([notifyName UTF8String], &token, q, ^(int t) {
        (void)t;
        if (resp) return;
        NSDictionary *r = PXReadKeychainBridgeResponseIfValid(fm, respPath, nonce);
        if (r) {
            resp = r;
            dispatch_semaphore_signal(sema);
        }
    });

    if (st != NOTIFY_STATUS_OK) {
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
        while ((CFAbsoluteTimeGetCurrent() - start) < timeoutSec) {
            NSDictionary *r = PXReadKeychainBridgeResponseIfValid(fm, respPath, nonce);
            if (r) return r;
            [NSThread sleepForTimeInterval:0.2];
        }
        return nil;
    }

    NSDictionary *afterReg = PXReadKeychainBridgeResponseIfValid(fm, respPath, nonce);
    if (afterReg) {
        notify_cancel(token);
        return afterReg;
    }

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutSec * NSEC_PER_SEC));
    (void)dispatch_semaphore_wait(sema, deadline);
    notify_cancel(token);

    if (resp) return resp;
    return PXReadKeychainBridgeResponseIfValid(fm, respPath, nonce);
}

- (BOOL)_inAppKeychainBackupForBundleID:(NSString *)bundleID
                          containerPath:(NSString *)dataContainerPath
                                 groups:(NSArray<NSString *> *)groups
                                 toFile:(NSString *)destFile
                              debugPath:(NSString *)debugKeychain
                               warnings:(NSMutableArray<NSString *> *)warnings {
    if (!bundleID.length || !dataContainerPath.length || !destFile.length) return NO;
    if (!groups.count) return NO;

    NSString *safeBundle = PXSafeBundleString(bundleID);
    NSString *reqPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_request_%@.plist", safeBundle];
    NSString *respPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_response_%@.plist", safeBundle];
    NSString *outPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_export_%@.plist", safeBundle];
    NSString *logPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_bridge_%@.log", safeBundle];

    NSString *nonce = [[NSUUID UUID] UUIDString];

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:reqPath error:nil];
    [fm removeItemAtPath:respPath error:nil];
    [fm removeItemAtPath:outPath error:nil];

    NSDictionary *req = @{
        @"action": @"backup",
        @"bundleID": bundleID,
        @"groups": groups,
        @"nonce": nonce,
        @"outPath": outPath,
        @"respPath": respPath,
        @"logPath": logPath,
        @"bridgeOnly": @YES,
    };
    if (![req writeToFile:reqPath atomically:YES]) {
        [warnings addObject:@"In-app keychain backup: failed to write request" ];
        return NO;
    }

    PXDebugHeader(debugKeychain, @"In-App Keychain Backup");
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"request=%@", reqPath]);
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"tmpOut=%@", outPath]);
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"nonce=%@", nonce]);

    // Notify bridge (best-effort)
    PXDarwinNotifyPost([NSString stringWithFormat:@"com.hydra.weaponx.keychain.req.%@", safeBundle]);

    __block BOOL opened = NO;
    if ([NSThread isMainThread]) {
        opened = PXOpenApplication(bundleID);
    } else {
        dispatch_sync(dispatch_get_main_queue(), ^{
            opened = PXOpenApplication(bundleID);
        });
    }
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"openApplication=%@", opened ? @"YES" : @"NO"]);

    // Wait via Darwin notify (avoid polling). Use shorter timeout if open failed.
    NSTimeInterval waitSec = opened ? 30.0 : 6.0;
    NSDictionary *resp = PXWaitForKeychainBridgeResponse(safeBundle, respPath, nonce, waitSec);

    // Always capture bridge log + tmp dir state (best-effort)
    {
        NSString *bridgeLog = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
        if (bridgeLog.length) {
            PXDebugHeader(debugKeychain, @"In-App Bridge Log");
            PXDebugAppendLine(debugKeychain, bridgeLog);
        }
        PXDebugRun([CommandRunner shared], debugKeychain, @"ls /tmp (keychain bridge)",
                   @"ls -la /tmp 2>/dev/null || true");
    }

    if (![resp isKindOfClass:[NSDictionary class]]) {
        [warnings addObject:@"In-app keychain backup: no response (timeout?)" ];
        [self _killRelatedProcessesForBundleID:bundleID];
        return NO;
    }

    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"resp=%@", resp]);

    BOOL ok = [resp[@"ok"] respondsToSelector:@selector(boolValue)] ? [resp[@"ok"] boolValue] : NO;
    if (!ok) {
        NSString *err = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"";
        if (err.length) [warnings addObject:[NSString stringWithFormat:@"In-app keychain backup failed: %@", err]];
        [self _killRelatedProcessesForBundleID:bundleID];
        return NO;
    }

    if (![fm fileExistsAtPath:outPath]) {
        [warnings addObject:@"In-app keychain backup: export file missing" ];
        [self _killRelatedProcessesForBundleID:bundleID];
        return NO;
    }

    [fm removeItemAtPath:destFile error:nil];
    if (![fm copyItemAtPath:outPath toPath:destFile error:nil]) {
        [warnings addObject:@"In-app keychain backup: failed to copy export to destination" ];
        [self _killRelatedProcessesForBundleID:bundleID];
        return NO;
    }

    [self _killRelatedProcessesForBundleID:bundleID];
    [fm removeItemAtPath:reqPath error:nil];
    [fm removeItemAtPath:respPath error:nil];
    [fm removeItemAtPath:outPath error:nil];

    // Keep bridge log for debugging.

    return YES;
}

- (BOOL)_inAppKeychainRestoreForBundleID:(NSString *)bundleID
                           containerPath:(NSString *)dataContainerPath
                                  groups:(NSArray<NSString *> *)groups
                                fromFile:(NSString *)srcFile
                               overwrite:(BOOL)overwrite
                               debugPath:(NSString *)debugKeychain
                                warnings:(NSMutableArray<NSString *> *)warnings {
    if (!bundleID.length || !dataContainerPath.length || !srcFile.length) return NO;
    if (!groups.count) return NO;

    NSString *safeBundle = PXSafeBundleString(bundleID);
    NSString *reqPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_request_%@.plist", safeBundle];
    NSString *respPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_response_%@.plist", safeBundle];
    NSString *inPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_import_%@.plist", safeBundle];
    NSString *logPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_bridge_%@.log", safeBundle];

    NSString *nonce = [[NSUUID UUID] UUIDString];

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:reqPath error:nil];
    [fm removeItemAtPath:respPath error:nil];
    [fm removeItemAtPath:inPath error:nil];

    if (![fm copyItemAtPath:srcFile toPath:inPath error:nil]) {
        [warnings addObject:@"In-app keychain restore: failed to stage import file" ];
        return NO;
    }

    NSDictionary *req = @{
        @"action": @"restore",
        @"bundleID": bundleID,
        @"groups": groups,
        @"inPath": inPath,
        @"overwrite": @(overwrite),
        @"respPath": respPath,
        @"logPath": logPath,
        @"nonce": nonce,
        @"bridgeOnly": @YES,
    };
    if (![req writeToFile:reqPath atomically:YES]) {
        [warnings addObject:@"In-app keychain restore: failed to write request" ];
        return NO;
    }

    PXDebugHeader(debugKeychain, @"In-App Keychain Restore");
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"request=%@", reqPath]);
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"tmpIn=%@", inPath]);
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"nonce=%@", nonce]);

    PXDarwinNotifyPost([NSString stringWithFormat:@"com.hydra.weaponx.keychain.req.%@", safeBundle]);

    __block BOOL opened = NO;
    if ([NSThread isMainThread]) {
        opened = PXOpenApplication(bundleID);
    } else {
        dispatch_sync(dispatch_get_main_queue(), ^{
            opened = PXOpenApplication(bundleID);
        });
    }
    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"openApplication=%@", opened ? @"YES" : @"NO"]);

    NSTimeInterval waitSec = opened ? 30.0 : 6.0;
    NSDictionary *resp = PXWaitForKeychainBridgeResponse(safeBundle, respPath, nonce, waitSec);

    // Always capture bridge log + tmp dir state (best-effort)
    {
        NSString *bridgeLog = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
        if (bridgeLog.length) {
            PXDebugHeader(debugKeychain, @"In-App Bridge Log");
            PXDebugAppendLine(debugKeychain, bridgeLog);
        }
        PXDebugRun([CommandRunner shared], debugKeychain, @"ls /tmp (keychain bridge)",
                   @"ls -la /tmp 2>/dev/null || true");
    }

    if (![resp isKindOfClass:[NSDictionary class]]) {
        [warnings addObject:@"In-app keychain restore: no response (timeout?)" ];
        [self _killRelatedProcessesForBundleID:bundleID];
        return NO;
    }

    PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"resp=%@", resp]);
    BOOL ok = [resp[@"ok"] respondsToSelector:@selector(boolValue)] ? [resp[@"ok"] boolValue] : NO;
    if (!ok) {
        NSString *err = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"";
        if (err.length) [warnings addObject:[NSString stringWithFormat:@"In-app keychain restore failed: %@", err]];
        [self _killRelatedProcessesForBundleID:bundleID];
        return NO;
    }

    [self _killRelatedProcessesForBundleID:bundleID];
    [fm removeItemAtPath:reqPath error:nil];
    [fm removeItemAtPath:respPath error:nil];
    [fm removeItemAtPath:inPath error:nil];
    return YES;
}

- (BOOL)_backupKeychainForBundleID:(NSString *)bundleID
                            groups:(NSArray<NSString *> *)groups
                            toFile:(NSString *)backupFile
                          warnings:(NSMutableArray<NSString *> *)warnings {
    NSString *scriptPath = [self _keychainBackupScriptPath];
    if (!scriptPath) {
        [warnings addObject:@"Keychain backup script not found; skipping keychain backup"];
        return NO;
    }
    
    CommandRunner *runner = [CommandRunner shared];
    NSString *groupsArg = groups.count ? [NSString stringWithFormat:@" --groups %@", PXShellQuote([groups componentsJoinedByString:@","])] : @"";
    NSString *cmd = [NSString stringWithFormat:@"%@ backup %@ %@%@",
                     PXShellQuote(scriptPath),
                     PXShellQuote(bundleID),
                     PXShellQuote(backupFile),
                     groupsArg];
    
    CommandResult *res = [runner runAndCapture:cmd];
    if (res.exitCode != 0) {
        NSString *stderrMsg = res.stderrString.length ? res.stderrString : @"";
        NSString *stdoutMsg = res.stdoutString.length ? res.stdoutString : @"";
        NSMutableString *msg = [NSMutableString stringWithString:@"Keychain backup failed"]; 
        if (stderrMsg.length) {
            [msg appendFormat:@"\nstderr: %@", stderrMsg];
        }
        if (stdoutMsg.length) {
            [msg appendFormat:@"\nstdout: %@", stdoutMsg];
        }
        [warnings addObject:[NSString stringWithFormat:@"Keychain backup: %@", msg]];
        return NO;
    }
    
    return [[NSFileManager defaultManager] fileExistsAtPath:backupFile];
}

- (BOOL)_restoreKeychainForBundleID:(NSString *)bundleID
                             groups:(NSArray<NSString *> *)groups
                           fromFile:(NSString *)backupFile
                          overwrite:(BOOL)overwrite
                           warnings:(NSMutableArray<NSString *> *)warnings {
    NSString *scriptPath = [self _keychainBackupScriptPath];
    if (!scriptPath) {
        [warnings addObject:@"Keychain backup script not found; skipping keychain restore"];
        return NO;
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:backupFile]) {
        [warnings addObject:@"Keychain backup file not found; skipping keychain restore"];
        return NO;
    }
    
    CommandRunner *runner = [CommandRunner shared];
    NSString *overwriteArg = overwrite ? @"--overwrite" : @"";
    NSString *groupsArg = groups.count ? [NSString stringWithFormat:@" --groups %@", PXShellQuote([groups componentsJoinedByString:@","])] : @"";
    NSString *cmd = [NSString stringWithFormat:@"%@ restore %@ %@ %@%@",
                     PXShellQuote(scriptPath),
                     PXShellQuote(bundleID),
                     PXShellQuote(backupFile),
                     overwriteArg,
                     groupsArg];
    
    CommandResult *res = [runner runAndCapture:cmd];
    // Store last keychain restore output for debugging
    NSDictionary *report = @{
        @"bundleID": bundleID ?: @"",
        @"groups": groups ?: @[],
        @"cmd": cmd ?: @"",
        @"exitCode": @(res.exitCode),
        @"stdout": res.stdoutString ?: @"",
        @"stderr": res.stderrString ?: @"",
    };
    [[NSUserDefaults standardUserDefaults] setObject:report forKey:[NSString stringWithFormat:@"PXKeychainRestoreResult_%@", bundleID]];
    [[NSUserDefaults standardUserDefaults] synchronize];
    if (res.exitCode != 0) {
        NSString *stderrMsg = res.stderrString.length ? res.stderrString : @"";
        NSString *stdoutMsg = res.stdoutString.length ? res.stdoutString : @"";
        NSMutableString *msg = [NSMutableString stringWithString:@"Keychain restore failed"]; 
        if (stderrMsg.length) {
            [msg appendFormat:@"\nstderr: %@", stderrMsg];
        }
        if (stdoutMsg.length) {
            [msg appendFormat:@"\nstdout: %@", stdoutMsg];
        }
        [warnings addObject:[NSString stringWithFormat:@"Keychain restore: %@", msg]];
        return NO;
    }
    
    return YES;
}

- (NSString *)_backupRoot {
    NSString *profileId = [self _activeProfileId];
    if (profileId.length) {
        return [NSString stringWithFormat:@"/var/mobile/Library/WeaponX/Profiles/%@/backups", profileId];
    }
    // Fallback to legacy global backups directory
    return @"/var/mobile/Library/WeaponX/Backups";
}

// Central profile ID helper (profile switch integration)
- (NSString *)_activeProfileId {
    // Read from the same central store used across the project.
    NSString *centralInfoPath = @"/var/mobile/Library/WeaponX/Profiles/current_profile_info.plist";
    NSDictionary *centralInfo = [NSDictionary dictionaryWithContentsOfFile:centralInfoPath];
    NSString *profileId = [centralInfo isKindOfClass:[NSDictionary class]] ? centralInfo[@"ProfileId"] : nil;
    if ([profileId isKindOfClass:[NSString class]] && profileId.length) {
        return profileId;
    }

    NSString *fallbackPath = @"/var/mobile/Library/WeaponX/active_profile_info.plist";
    NSDictionary *fallbackInfo = [NSDictionary dictionaryWithContentsOfFile:fallbackPath];
    profileId = [fallbackInfo isKindOfClass:[NSDictionary class]] ? fallbackInfo[@"ProfileId"] : nil;
    if ([profileId isKindOfClass:[NSString class]] && profileId.length) {
        return profileId;
    }

    return nil;
}

- (NSString *)_timestampString {
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    fmt.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"]; 
    fmt.dateFormat = @"yyyyMMdd-HHmmss";
    return [fmt stringFromDate:[NSDate date]];
}

- (NSArray<NSString *> *)listBackupDirectoriesForBundleID:(NSString *)bundleID {
    if (!bundleID.length) {
        return @[];
    }
    NSString *dir = [[self _backupRoot] stringByAppendingPathComponent:bundleID];
    NSFileManager *fm = [NSFileManager defaultManager];

    NSMutableArray<NSString *> *dirs = [NSMutableArray array];

    BOOL isDir = NO;
    if ([fm fileExistsAtPath:dir isDirectory:&isDir] && isDir) {
        NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *item in items) {
            NSString *path = [dir stringByAppendingPathComponent:item];
            BOOL itemIsDir = NO;
            if ([fm fileExistsAtPath:path isDirectory:&itemIsDir] && itemIsDir) {
                NSString *manifest = [path stringByAppendingPathComponent:@"manifest.plist"];
                if ([fm fileExistsAtPath:manifest]) {
                    [dirs addObject:path];
                }
            }
        }
    }

    // Also include legacy global backups if present (so users can migrate smoothly)
    NSString *legacyDir = [@"/var/mobile/Library/WeaponX/Backups" stringByAppendingPathComponent:bundleID];
    BOOL legacyIsDir = NO;
    if (![legacyDir isEqualToString:dir] && [fm fileExistsAtPath:legacyDir isDirectory:&legacyIsDir] && legacyIsDir) {
        NSArray<NSString *> *legacyItems = [fm contentsOfDirectoryAtPath:legacyDir error:nil];
        for (NSString *item in legacyItems) {
            NSString *path = [legacyDir stringByAppendingPathComponent:item];
            BOOL itemIsDir = NO;
            if ([fm fileExistsAtPath:path isDirectory:&itemIsDir] && itemIsDir) {
                NSString *manifest = [path stringByAppendingPathComponent:@"manifest.plist"];
                if ([fm fileExistsAtPath:manifest]) {
                    [dirs addObject:path];
                }
            }
        }
    }

    [dirs sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        // Sort newest-first based on the last path component (timestamp folder convention).
        return [b.lastPathComponent compare:a.lastPathComponent];
    }];
    return dirs;
}

- (NSDictionary *)readManifestAtBackupDirectory:(NSString *)backupDir
                                          error:(NSError **)error {
    NSString *manifest = [backupDir stringByAppendingPathComponent:@"manifest.plist"];
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:manifest];
    if (![dict isKindOfClass:[NSDictionary class]]) {
        if (error) {
            *error = [NSError errorWithDomain:PXBackupErrorDomain
                                         code:200
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to read manifest"}];
        }
        return nil;
    }
    return dict;
}

- (void)createBackupForBundleID:(NSString *)bundleID
                        appName:(NSString *)appName
                        options:(PXBackupOptions)options
                     completion:(void (^)(PXBackupResult *, NSError *))completion {
    if (!bundleID.length) {
        if (completion) {
            completion(nil, [NSError errorWithDomain:PXBackupErrorDomain
                                                code:100
                                            userInfo:@{NSLocalizedDescriptionKey: @"Missing bundleID"}]);
        }
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableArray<NSString *> *warnings = [NSMutableArray array];
        NSFileManager *fm = [NSFileManager defaultManager];
        CommandRunner *runner = [CommandRunner shared];

        NSString *profileId = [self _activeProfileId];

        // Prefer jailbreak/Procursus tar first (often has xattrs/acl support); /usr/bin/tar on iOS may not.
        NSString *tarPath = [runner firstExistingPath:@[
            @"/var/jb/usr/bin/gtar",
            @"/private/preboot/jb/usr/bin/gtar",
            @"/usr/local/bin/gtar",
            @"/usr/bin/gtar",
            @"/var/jb/usr/bin/bsdtar",
            @"/private/preboot/jb/usr/bin/bsdtar",
            @"/usr/local/bin/bsdtar",
            @"/usr/bin/bsdtar",
            @"/var/jb/usr/bin/tar",
            @"/private/preboot/jb/usr/bin/tar",
            @"/usr/bin/tar",
            @"/bin/tar"
        ]];
        if (!tarPath) {
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:101
                                           userInfo:@{NSLocalizedDescriptionKey: @"tar not found"}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }

        // Prefer LaunchServices-reported container path (active container).
        NSString *dataContainerPath = nil;
        NSString *dataUUID = nil;
        {
            NSString *lsPath = PXDataContainerPathFromLaunchServices(bundleID);
            BOOL isDir = NO;
            if (lsPath.length && [fm fileExistsAtPath:lsPath isDirectory:&isDir] && isDir) {
                dataContainerPath = lsPath;
                dataUUID = lsPath.lastPathComponent;
            }
        }

        if (!dataContainerPath) {
            NSArray<NSString *> *bases = @[@"/var/mobile/Containers/Data/Application", @"/private/var/mobile/Containers/Data/Application", @"/containers/Data/Application", @"/private/var/containers/Data/Application"]; 
            for (NSString *base in bases) {
                NSString *found = PXFindDataContainerUUIDByMetadata(fm, base, bundleID);
                if (found.length) {
                    NSString *p = [base stringByAppendingPathComponent:found];
                    BOOL isDir = NO;
                    if ([fm fileExistsAtPath:p isDirectory:&isDir] && isDir) {
                        dataUUID = found;
                        dataContainerPath = p;
                        break;
                    }
                }
            }
            if (!dataContainerPath.length) {
                NSString *lsPath = PXDataContainerPathFromLaunchServices(bundleID) ?: @"";
                NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                   code:102
                                               userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Data container not found (bundleID=%@ lsPath=%@)", bundleID, lsPath]}];
                dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                return;
            }
        }

        if (!dataContainerPath.length) {
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:103
                                           userInfo:@{NSLocalizedDescriptionKey: @"Data container path missing"}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }

        NSString *timestamp = [self _timestampString];
        NSString *backupDir = [[[self _backupRoot] stringByAppendingPathComponent:bundleID] stringByAppendingPathComponent:timestamp];
        NSString *debugBefore = [backupDir stringByAppendingPathComponent:@"debug_before_backup.txt"];
        NSString *debugAfter = [backupDir stringByAppendingPathComponent:@"debug_after_backup.txt"];
        NSString *debugKeychain = [backupDir stringByAppendingPathComponent:@"debug_keychain.txt"];
        NSString *groupsDir = [backupDir stringByAppendingPathComponent:@"groups"]; 
        NSString *prefsDir = [backupDir stringByAppendingPathComponent:@"preferences"]; 

        NSError *mkErr = nil;
        if (![fm createDirectoryAtPath:groupsDir withIntermediateDirectories:YES attributes:nil error:&mkErr]) {
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:104
                                           userInfo:@{NSLocalizedDescriptionKey: mkErr.localizedDescription ?: @"Failed to create backup directory"}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }
        [fm createDirectoryAtPath:prefsDir withIntermediateDirectories:YES attributes:nil error:nil];

        // Restrict permissions best-effort
        [runner run:[NSString stringWithFormat:@"chmod 700 %@ 2>/dev/null || true", PXShellQuote(backupDir)]];
        [runner run:[NSString stringWithFormat:@"chmod 700 %@ 2>/dev/null || true", PXShellQuote(groupsDir)]];
        [runner run:[NSString stringWithFormat:@"chmod 700 %@ 2>/dev/null || true", PXShellQuote(prefsDir)]];

        // Debug snapshot: before backup
        {
            PXDebugHeader(debugBefore, @"Backup Start");
            NSDictionary *rp = PXResolvePathsForBundleID(bundleID);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"bundleID=%@", bundleID]);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"profileId=%@", profileId ?: @""]);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"timestamp=%@", timestamp]);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"tarPath=%@", tarPath ?: @""]);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"lsDataContainerPath=%@", rp[@"lsDataContainerPath"] ?: @""]);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"lsContainerURLPath=%@", rp[@"lsContainerURLPath"] ?: @""]);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"chosenDataContainerPath=%@", dataContainerPath ?: @""]);
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"chosenDataUUID=%@", dataUUID ?: @""]);
            PXDebugRun(runner, debugBefore, @"du data", [NSString stringWithFormat:@"du -sk %@ 2>/dev/null || true", PXShellQuote(dataContainerPath)]);
            PXDebugRun(runner, debugBefore, @"du library", [NSString stringWithFormat:@"du -sk %@ 2>/dev/null || true", PXShellQuote([dataContainerPath stringByAppendingPathComponent:@"Library"]) ]);
            PXDebugRun(runner, debugBefore, @"ls root", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(dataContainerPath)]);
            PXDebugRun(runner, debugBefore, @"ls library", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote([dataContainerPath stringByAppendingPathComponent:@"Library"]) ]);
            PXDebugRun(runner, debugBefore, @"ls prefs", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote([dataContainerPath stringByAppendingPathComponent:@"Library/Preferences"]) ]);
            PXDebugRun(runner, debugBefore, @"ls cookies", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote([dataContainerPath stringByAppendingPathComponent:@"Library/Cookies"]) ]);
            PXDebugRun(runner, debugBefore, @"ls webkit", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote([dataContainerPath stringByAppendingPathComponent:@"Library/WebKit"]) ]);

            // Snapshot-only (system-wide) paths for debugging (restore does NOT touch these by default)
            PXDebugHeader(debugBefore, @"System Snapshot (Debug Only)");
            PXDebugRun(runner, debugBefore, @"ls Accounts3", @"ls -lh /var/mobile/Library/Accounts/Accounts3.sqlite 2>/dev/null || true");
            PXDebugRun(runner, debugBefore, @"ls Cookies", @"ls -la /var/mobile/Library/Cookies 2>/dev/null || true");
            PXDebugRun(runner, debugBefore, @"ls WebKit WebsiteData", @"ls -la /var/mobile/Library/WebKit/WebsiteData 2>/dev/null || true");
        }

        // Initialize keychain debug file (even if keychain option is off)
        {
            PXDebugHeader(debugKeychain, @"Keychain Debug");
            PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"bundleID=%@", bundleID]);
            PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"profileId=%@", profileId ?: @""]);
            PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"backupDir=%@", backupDir]);
        }

        // Ensure target app is not running while archiving.
        [self _killRelatedProcessesForBundleID:bundleID];

        NSString *dataArchivePath = [backupDir stringByAppendingPathComponent:@"data.tar.gz"];
        CommandResult *tarRes = [self _tarCreate:tarPath fromDir:dataContainerPath toArchive:dataArchivePath];
        if (tarRes.exitCode != 0 || ![fm fileExistsAtPath:dataArchivePath]) {
            NSString *msg = tarRes.stderrString.length ? tarRes.stderrString : @"tar failed for data container";
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:105
                                           userInfo:@{NSLocalizedDescriptionKey: msg}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }

        NSMutableArray<NSDictionary *> *groupManifests = [NSMutableArray array];
        NSArray<AppGroupContainerInfo *> *groupContainers = @[];
        NSArray<NSString *> *groupIDs = @[];

        if (options & PXBackupOptionIncludeAppGroups) {
            NSError *entErr = nil;
            AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
            groupIDs = [reader applicationGroupsForBundleID:bundleID error:&entErr];
            if (entErr) {
                [warnings addObject:[NSString stringWithFormat:@"Entitlements read failed: %@", entErr.localizedDescription]];
            }

            if (groupIDs.count) {
                AppGroupContainerResolver *resolver = [[AppGroupContainerResolver alloc] init];
                groupContainers = [resolver resolveGroupContainersForGroupIDs:groupIDs];
                if (!groupContainers.count) {
                    [warnings addObject:@"No App Group containers matched entitlements"];
                }
            }
        }

        // Debug snapshot: groups resolution
        {
            PXDebugHeader(debugBefore, @"App Groups Resolve");
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"groupIDs=%@", groupIDs ?: @[]]);
            NSMutableArray *paths = [NSMutableArray array];
            for (AppGroupContainerInfo *info in groupContainers) {
                [paths addObject:[NSString stringWithFormat:@"%@ => %@ (%@)", info.groupID ?: @"", info.path ?: @"", info.uuid ?: @""]];
                PXDebugRun(runner, debugBefore, [NSString stringWithFormat:@"du group %@", info.groupID ?: @""], [NSString stringWithFormat:@"du -sk %@ 2>/dev/null || true", PXShellQuote(info.path)]);
                PXDebugRun(runner, debugBefore, [NSString stringWithFormat:@"ls group %@", info.groupID ?: @""], [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(info.path)]);
            }
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"groupPaths=%@", paths]);
        }

        for (AppGroupContainerInfo *info in groupContainers) {
            NSString *archiveName = [NSString stringWithFormat:@"%@.tar.gz", PXSanitizeFilenameComponent(info.groupID)];
            NSString *archivePath = [groupsDir stringByAppendingPathComponent:archiveName];

            CommandResult *r = [self _tarCreate:tarPath fromDir:info.path toArchive:archivePath];
            if (r.exitCode != 0 || ![fm fileExistsAtPath:archivePath]) {
                [warnings addObject:[NSString stringWithFormat:@"Failed to archive group %@ (%@)", info.groupID, info.uuid]];
                continue;
            }

            [groupManifests addObject:@{
                @"groupID": info.groupID,
                @"uuid": info.uuid,
                @"archive": [@"groups" stringByAppendingPathComponent:archiveName]
            }];
        }

        // Profile redirected appdata (system apps like Safari may store most data here)
        NSString *profileAppDataPath = [self _profileAppDataPathForBundleID:bundleID];
        NSString *profileAppDataArchivePath = nil;
        if (profileAppDataPath.length) {
            BOOL isDir = NO;
            if ([fm fileExistsAtPath:profileAppDataPath isDirectory:&isDir] && isDir) {
                profileAppDataArchivePath = [backupDir stringByAppendingPathComponent:@"profile_appdata.tar.gz"];
                CommandResult *r = [self _tarCreate:tarPath fromDir:profileAppDataPath toArchive:profileAppDataArchivePath];
                if (r.exitCode != 0 || ![fm fileExistsAtPath:profileAppDataArchivePath]) {
                    [warnings addObject:@"Failed to archive profile appdata; continuing" ];
                    profileAppDataArchivePath = nil;
                }
            }
        }

        // Global Library storage for Safari (history/bookmarks live under /var/mobile/Library/Safari)
        NSString *globalSafariPath = nil;
        NSString *globalSafariArchivePath = nil;
        if ([bundleID isEqualToString:@"com.apple.mobilesafari"]) {
            globalSafariPath = [self _globalSafariLibraryPath];
            if (globalSafariPath.length) {
                BOOL isDir = NO;
                if ([fm fileExistsAtPath:globalSafariPath isDirectory:&isDir] && isDir) {
                    globalSafariArchivePath = [backupDir stringByAppendingPathComponent:@"global_safari.tar.gz"];
                    CommandResult *r = [self _tarCreate:tarPath fromDir:globalSafariPath toArchive:globalSafariArchivePath];
                    if (r.exitCode != 0 || ![fm fileExistsAtPath:globalSafariArchivePath]) {
                        [warnings addObject:@"Failed to archive global Safari library; continuing"];
                        globalSafariArchivePath = nil;
                    }
                }
            }
        }

        BOOL prefsIncluded = (options & PXBackupOptionIncludePreferences) != 0;
        NSString *prefSourcePath = [self _preferencesPlistPathForBundleID:bundleID];
        NSString *prefDestPath = [prefsDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.plist", bundleID]];
        if (prefsIncluded) {
            if ([fm fileExistsAtPath:prefSourcePath]) {
                NSString *cpCmd = [NSString stringWithFormat:@"cp -f %@ %@ 2>/dev/null || true", PXShellQuote(prefSourcePath), PXShellQuote(prefDestPath)];
                [runner run:cpCmd];
                [runner run:[NSString stringWithFormat:@"chmod 600 %@ 2>/dev/null || true", PXShellQuote(prefDestPath)]];
            } else {
                [warnings addObject:@"Global preferences plist not found (OK for most apps); skipping"];
            }
        }

        // Keychain backup
        BOOL keychainIncluded = (options & PXBackupOptionIncludeKeychain) != 0;
        NSString *keychainBackupPath = nil;
        NSString *keychainMethod = nil;
        NSArray<NSString *> *selectedKeychainGroups = @[];
        if (keychainIncluded) {
            keychainBackupPath = [backupDir stringByAppendingPathComponent:@"keychain.plist"];
            // Default selection: ALL groups from entitlements if no saved preference.
            id saved = [[NSUserDefaults standardUserDefaults] objectForKey:PXBackupKeychainGroupsKey(bundleID)];
            if ([saved isKindOfClass:[NSArray class]] && [(NSArray *)saved count] > 0) {
                NSMutableArray<NSString *> *tmp = [NSMutableArray array];
                for (id v in (NSArray *)saved) {
                    if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
                        [tmp addObject:(NSString *)v];
                    }
                }
                selectedKeychainGroups = tmp;
            } else {
                NSError *entErr = nil;
                AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
                NSArray<NSString *> *entGroups = [reader keychainAccessGroupsForBundleID:bundleID error:&entErr];
                if (entGroups.count) {
                    selectedKeychainGroups = entGroups;
                    [[NSUserDefaults standardUserDefaults] setObject:entGroups forKey:PXBackupKeychainGroupsKey(bundleID)];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                } else if (entErr) {
                    [warnings addObject:[NSString stringWithFormat:@"Keychain groups read failed: %@", entErr.localizedDescription]];
                }
            }

            // Ensure default keychain group (application-identifier) is included even when the user has a saved subset.
            // Many apps store keychain items under this group even when it is not listed in keychain-access-groups.
            {
                NSError *entErr = nil;
                AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
                NSDictionary *ent = [reader fullEntitlementsForBundleID:bundleID error:&entErr];
                id appIdent = [ent isKindOfClass:[NSDictionary class]] ? ent[@"application-identifier"] : nil;
                if ([appIdent isKindOfClass:[NSString class]] && [(NSString *)appIdent length] > 0) {
                    NSMutableOrderedSet<NSString *> *set = [NSMutableOrderedSet orderedSetWithArray:selectedKeychainGroups ?: @[]];
                    [set addObject:(NSString *)appIdent];
                    selectedKeychainGroups = set.array;
                }
            }

            // Debug: list keychain items before backup
            {
                PXDebugHeader(debugKeychain, @"Keychain Before Backup");
                PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"selectedGroups=%@", selectedKeychainGroups ?: @[]]);
                NSString *scriptPath = [runner firstExistingPath:@[@"/Library/WeaponX/keychain_backup.sh",
                                                                  @"/var/jb/Library/WeaponX/keychain_backup.sh",
                                                                  @"/private/var/jb/Library/WeaponX/keychain_backup.sh"]];
                if (scriptPath.length && selectedKeychainGroups.count) {
                    NSString *csv = [selectedKeychainGroups componentsJoinedByString:@","];
                    PXDebugRun(runner, debugKeychain, @"list", [NSString stringWithFormat:@"%@ list %@ --groups %@", PXShellQuote(scriptPath), PXShellQuote(bundleID), PXShellQuote(csv)]);
                }
            }

            BOOL keychainSuccess = [self _backupKeychainForBundleID:bundleID
                                                            groups:selectedKeychainGroups
                                                            toFile:keychainBackupPath
                                                          warnings:warnings];
            if (!keychainSuccess) {
                keychainBackupPath = nil; // Mark as not included if failed
            } else {
                keychainMethod = @"helper";
                [runner run:[NSString stringWithFormat:@"chmod 600 %@ 2>/dev/null || true", PXShellQuote(keychainBackupPath)]];
                PXDebugHeader(debugKeychain, @"Keychain Backup Result");
                PXDebugAppendLine(debugKeychain, @"status=ok");
                PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"archive=%@", keychainBackupPath]);
                PXDebugRun(runner, debugKeychain, @"ls keychain.plist", [NSString stringWithFormat:@"ls -lh %@ 2>/dev/null || true", PXShellQuote(keychainBackupPath)]);

                // If helper cannot access restricted groups (e.g. *.platformFamily), fallback to in-app export.
                NSUInteger count = PXKeychainPlistItemCount(keychainBackupPath);
                PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"plistItems=%lu", (unsigned long)count]);
                if (count == 0 && PXGroupsContainPlatformFamily(selectedKeychainGroups)) {
                    PXDebugAppendLine(debugKeychain, @"helper returned 0 items; trying in-app export");
                    BOOL inAppOK = [self _inAppKeychainBackupForBundleID:bundleID
                                                           containerPath:dataContainerPath
                                                                  groups:selectedKeychainGroups
                                                                  toFile:keychainBackupPath
                                                               debugPath:debugKeychain
                                                                warnings:warnings];
                    if (inAppOK) {
                        keychainMethod = @"in_app";
                        [runner run:[NSString stringWithFormat:@"chmod 600 %@ 2>/dev/null || true", PXShellQuote(keychainBackupPath)]];
                        PXDebugRun(runner, debugKeychain, @"ls keychain.plist (after in-app)", [NSString stringWithFormat:@"ls -lh %@ 2>/dev/null || true", PXShellQuote(keychainBackupPath)]);
                        PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"plistItemsAfterInApp=%lu", (unsigned long)PXKeychainPlistItemCount(keychainBackupPath)]);
                    } else {
                        PXDebugAppendLine(debugKeychain, @"in-app export failed");
                    }
                }
            }
        }

        // Generic system app global data: many system apps store most data under /var/mobile/Library/<AppName>.
        NSArray<NSDictionary *> *systemGlobalItems = [self _systemGlobalLibraryItemsForBundleID:bundleID];
        NSMutableArray<NSDictionary *> *systemGlobalManifests = [NSMutableArray array];
        if (systemGlobalItems.count) {
            PXDebugHeader(debugBefore, @"System App Global Library");
        }
        for (NSDictionary *it in systemGlobalItems) {
            NSString *subdir = [it[@"subdir"] isKindOfClass:[NSString class]] ? it[@"subdir"] : nil;
            NSString *srcPath = [it[@"path"] isKindOfClass:[NSString class]] ? it[@"path"] : nil;
            if (!subdir.length || !srcPath.length) continue;

            // Avoid double-archiving Safari which is handled explicitly.
            if ([bundleID isEqualToString:@"com.apple.mobilesafari"] && [subdir isEqualToString:@"Safari"]) {
                continue;
            }

            NSString *archiveName = [NSString stringWithFormat:@"global_library_%@.tar.gz", PXSanitizeFilenameComponent(subdir)];
            NSString *archivePath = [backupDir stringByAppendingPathComponent:archiveName];

            [self _killRelatedProcessesForBundleID:bundleID];
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"item=%@ path=%@", subdir, srcPath]);
            CommandResult *r = [self _tarCreate:tarPath fromDir:srcPath toArchive:archivePath];
            if (r.exitCode != 0 || ![fm fileExistsAtPath:archivePath]) {
                [warnings addObject:[NSString stringWithFormat:@"Failed to archive system global library %@; continuing", subdir]];
                continue;
            }

            [systemGlobalManifests addObject:@{ @"subdir": subdir, @"archive": archiveName }];
        }

        // Shared system DBs: back up for system apps (can impact multiple apps).
        NSMutableArray<NSDictionary *> *sharedSystemDBFiles = [NSMutableArray array];
        if ([self _isSystemAppBundleID:bundleID]) {
            NSString *libBase = [self _mobileLibraryBasePath];
            NSString *sharedDir = [backupDir stringByAppendingPathComponent:@"shared_db"];
            [fm createDirectoryAtPath:sharedDir withIntermediateDirectories:YES attributes:nil error:nil];
            [runner run:[NSString stringWithFormat:@"chmod 700 %@ 2>/dev/null || true", PXShellQuote(sharedDir)]];

            PXDebugHeader(debugBefore, @"Shared System DBs");
            PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"libraryBase=%@", libBase ?: @""]);

            for (NSDictionary *spec in PXSharedSystemDBSpecs()) {
                for (NSDictionary *entry in PXExpandSQLiteSidecars(spec)) {
                    NSString *rel = [entry[@"libraryRel"] isKindOfClass:[NSString class]] ? entry[@"libraryRel"] : nil;
                    NSString *bn = [entry[@"backupName"] isKindOfClass:[NSString class]] ? entry[@"backupName"] : nil;
                    if (!rel.length || !bn.length) continue;

                    NSString *src = [libBase stringByAppendingPathComponent:rel];
                    if (![fm fileExistsAtPath:src]) {
                        continue;
                    }
                    NSString *dstRel = [@"shared_db" stringByAppendingPathComponent:bn];
                    NSString *dst = [backupDir stringByAppendingPathComponent:dstRel];

                    // Best-effort stop associated daemons first.
                    // A3: poll for actual exit instead of a fixed sleep so the
                    // copy does not race a daemon that still holds the DB open.
                    [self _killRelatedProcessesForBundleID:bundleID];
                    NSArray<NSString *> *dbDaemonsBackup = @[@"accountsd", @"calaccessd", @"imagent", @"MobileSMS"];
                    for (NSString *d in dbDaemonsBackup) {
                        PXKillallByName(d, SIGTERM);
                    }
                    if (!PXWaitForProcessesToExit(dbDaemonsBackup, 2.0)) {
                        for (NSString *d in dbDaemonsBackup) {
                            if (PXProcessIsRunning(d)) {
                                PXKillallByName(d, SIGKILL);
                            }
                        }
                        PXWaitForProcessesToExit(dbDaemonsBackup, 0.5);
                    }

                    PXDebugAppendLine(debugBefore, [NSString stringWithFormat:@"copy %@ -> %@", src, dstRel]);
                    [runner run:[NSString stringWithFormat:@"cp -a %@ %@ 2>/dev/null || true", PXShellQuote(src), PXShellQuote(dst)]];
                    [runner run:[NSString stringWithFormat:@"chmod 600 %@ 2>/dev/null || true", PXShellQuote(dst)]];
                    if ([fm fileExistsAtPath:dst]) {
                        [sharedSystemDBFiles addObject:@{ @"libraryRel": rel, @"archive": dstRel }];
                    }
                }
            }

            if (!sharedSystemDBFiles.count) {
                [warnings addObject:@"System app: no shared system DBs were found to back up"];
            } else {
                [warnings addObject:@"System app: included shared system DBs (this may affect multiple apps)"];
            }
        }

        UIDevice *device = [UIDevice currentDevice];
        NSString *iosVersion = device.systemVersion ?: @"";
        // profileId already computed above

        NSMutableArray *artifacts = [NSMutableArray array];
        NSDictionary *dataArtifact = PXArtifactInfo(dataArchivePath, @"data.tar.gz");
        if (dataArtifact) [artifacts addObject:dataArtifact];
        for (NSDictionary *g in groupManifests) {
            NSString *rel = g[@"archive"]; // groups/<name>.tar.gz
            if ([rel isKindOfClass:[NSString class]]) {
                NSString *abs = [backupDir stringByAppendingPathComponent:(NSString *)rel];
                NSDictionary *gi = PXArtifactInfo(abs, rel);
                if (gi) [artifacts addObject:gi];
            }
        }
        if (profileAppDataArchivePath) {
            NSDictionary *a = PXArtifactInfo(profileAppDataArchivePath, @"profile_appdata.tar.gz");
            if (a) [artifacts addObject:a];
        }
        if (globalSafariArchivePath) {
            NSDictionary *a = PXArtifactInfo(globalSafariArchivePath, @"global_safari.tar.gz");
            if (a) [artifacts addObject:a];
        }
        for (NSDictionary *g in systemGlobalManifests) {
            NSString *rel = g[@"archive"]; // global_library_*.tar.gz
            if ([rel isKindOfClass:[NSString class]] && rel.length) {
                NSString *abs = [backupDir stringByAppendingPathComponent:(NSString *)rel];
                NSDictionary *gi = PXArtifactInfo(abs, rel);
                if (gi) [artifacts addObject:gi];
            }
        }
        for (NSDictionary *d in sharedSystemDBFiles) {
            NSString *rel = [d[@"archive"] isKindOfClass:[NSString class]] ? d[@"archive"] : nil;
            if (!rel.length) continue;
            NSString *abs = [backupDir stringByAppendingPathComponent:rel];
            NSDictionary *di = PXArtifactInfo(abs, rel);
            if (di) [artifacts addObject:di];
        }
        if (prefDestPath && [[NSFileManager defaultManager] fileExistsAtPath:prefDestPath]) {
            NSDictionary *a = PXArtifactInfo(prefDestPath, [NSString stringWithFormat:@"preferences/%@.plist", bundleID]);
            if (a) [artifacts addObject:a];
        }
        if (keychainBackupPath && [[NSFileManager defaultManager] fileExistsAtPath:keychainBackupPath]) {
            NSDictionary *a = PXArtifactInfo(keychainBackupPath, @"keychain.plist");
            if (a) [artifacts addObject:a];
        }

        NSDictionary *manifest = @{
            @"manifestVersion": @2,
            @"bundleID": bundleID,
            @"appName": appName ?: @"",
            @"timestamp": timestamp,
            @"iosVersion": iosVersion,
            @"profileId": profileId,
            @"data": @{
                @"uuid": dataUUID,
                @"archive": @"data.tar.gz",
                @"containerPath": dataContainerPath
            },
            @"applicationGroups": groupIDs ?: @[],
            @"appGroups": groupManifests,
            @"preferences": @{
                @"included": @(prefsIncluded),
                @"archive": [NSString stringWithFormat:@"preferences/%@.plist", bundleID]
            },
            @"keychain": @{
                @"included": @(keychainBackupPath != nil),
                @"archive": keychainBackupPath ? @"keychain.plist" : @"",
                @"groupsSelected": selectedKeychainGroups ?: @[],
                @"method": keychainMethod ?: @""
            },
            @"profileAppData": @{
                @"included": @(profileAppDataArchivePath != nil),
                @"archive": profileAppDataArchivePath ? @"profile_appdata.tar.gz" : @"",
                @"path": profileAppDataPath ?: @""
            },
            @"globalSafari": @{
                @"included": @(globalSafariArchivePath != nil),
                @"archive": globalSafariArchivePath ? @"global_safari.tar.gz" : @"",
                @"path": globalSafariPath ?: @""
            },
            @"systemGlobalLibrary": @{
                @"included": @(systemGlobalManifests.count > 0),
                @"items": systemGlobalManifests
            },
            @"sharedSystemDB": @{
                @"included": @(sharedSystemDBFiles.count > 0),
                @"files": sharedSystemDBFiles
            },
            @"artifacts": artifacts,
            @"options": @{
                @"includeAppGroups": @((options & PXBackupOptionIncludeAppGroups) != 0),
                @"includePreferences": @(prefsIncluded),
                @"includeKeychain": @(keychainIncluded)
            }
        };

        // Debug snapshot: after backup artifacts
        {
            PXDebugHeader(debugAfter, @"Backup Artifacts");
            PXDebugAppendLine(debugAfter, [NSString stringWithFormat:@"backupDir=%@", backupDir]);
            PXDebugRun(runner, debugAfter, @"ls backupDir", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(backupDir)]);
            PXDebugRun(runner, debugAfter, @"ls groupsDir", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(groupsDir)]);
            PXDebugRun(runner, debugAfter, @"ls prefsDir", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(prefsDir)]);
            PXDebugRun(runner, debugAfter, @"ls data.tar.gz", [NSString stringWithFormat:@"ls -lh %@ 2>/dev/null || true", PXShellQuote(dataArchivePath)]);
            if (keychainBackupPath) {
                PXDebugRun(runner, debugAfter, @"ls keychain.plist", [NSString stringWithFormat:@"ls -lh %@ 2>/dev/null || true", PXShellQuote(keychainBackupPath)]);
            }
            PXDebugRun(runner, debugAfter, @"cat manifest.plist", [NSString stringWithFormat:@"ls -lh %@ 2>/dev/null || true", PXShellQuote([backupDir stringByAppendingPathComponent:@"manifest.plist"]) ]);
        }

        NSString *manifestPath = [backupDir stringByAppendingPathComponent:@"manifest.plist"];
        if (![manifest writeToFile:manifestPath atomically:YES]) {
            [warnings addObject:@"Failed to write manifest"];
        } else {
            [runner run:[NSString stringWithFormat:@"chmod 600 %@ 2>/dev/null || true", PXShellQuote(manifestPath)]];
        }

        PXBackupResult *out = [[PXBackupResult alloc] init];
        out.backupDirectory = backupDir;
        out.manifestPath = manifestPath;
        out.warnings = warnings;

        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) {
                completion(out, nil);
            }
        });
    });
}

// A4 helper: remove stale quarantine trash entries ("*.WeaponXTrash.<epoch>")
// in the given directories that are older than the supplied age. The epoch
// suffix must be pure digits; entries without a valid numeric epoch are skipped.
// Scope is deliberately narrow: only the named directories are scanned (no
// recursion), and only files matching the WeaponXTrash naming pattern are
// considered. A quarantine created during the current restore run will have a
// recent epoch and therefore will not be eligible for removal.
- (void)_cleanStaleQuarantineTrashInDirectories:(NSArray<NSString *> *)dirs
                                      olderThan:(NSTimeInterval)maxAge {
    if (dirs.count == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSTimeInterval nowEpoch = [[NSDate date] timeIntervalSince1970];
    NSSet<NSString *> *seen = [NSSet setWithArray:dirs];
    for (NSString *dir in seen) {
        if (![dir isKindOfClass:[NSString class]] || !dir.length) continue;
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) continue;
        NSError *listErr = nil;
        NSArray<NSString *> *entries = [fm contentsOfDirectoryAtPath:dir error:&listErr];
        if (!entries) continue;
        for (NSString *name in entries) {
            NSRange marker = [name rangeOfString:@".WeaponXTrash." options:NSBackwardsSearch];
            if (marker.location == NSNotFound) continue;
            NSString *epochStr = [name substringFromIndex:NSMaxRange(marker)];
            if (!epochStr.length) continue;
            BOOL allDigits = YES;
            for (NSUInteger i = 0; i < epochStr.length; i++) {
                unichar c = [epochStr characterAtIndex:i];
                if (c < '0' || c > '9') { allDigits = NO; break; }
            }
            if (!allDigits) continue;
            NSTimeInterval entryEpoch = (NSTimeInterval)[epochStr doubleValue];
            if (nowEpoch - entryEpoch < maxAge) continue;
            NSString *fullPath = [dir stringByAppendingPathComponent:name];
            CommandRunner *runner = [CommandRunner shared];
            [runner run:[NSString stringWithFormat:@"rm -rf %@ 2>/dev/null || true", PXShellQuote(fullPath)]];
        }
    }
}

- (void)restoreBackupAtDirectory:(NSString *)backupDir
                        bundleID:(NSString *)bundleID
                         appName:(NSString *)appName
                     completion:(void (^)(PXRestoreResult *, NSError *))completion {
    if (!backupDir.length || !bundleID.length) {
        if (completion) {
            completion(nil, [NSError errorWithDomain:PXBackupErrorDomain
                                                code:300
                                            userInfo:@{NSLocalizedDescriptionKey: @"Missing parameters"}]);
        }
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableArray<NSString *> *warnings = [NSMutableArray array];
        NSFileManager *fm = [NSFileManager defaultManager];
        CommandRunner *runner = [CommandRunner shared];

        NSString *debugPre = [backupDir stringByAppendingPathComponent:@"debug_before_restore.txt"];
        NSString *debugPost = [backupDir stringByAppendingPathComponent:@"debug_after_restore.txt"];
        NSString *debugKeychain = [backupDir stringByAppendingPathComponent:@"debug_keychain.txt"];

        // Debug snapshot: restore start
        {
            PXDebugHeader(debugPre, @"Restore Start");
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"bundleID=%@", bundleID]);
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"appName=%@", appName ?: @""]);
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"backupDir=%@", backupDir]);
            NSDictionary *rp = PXResolvePathsForBundleID(bundleID);
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"lsDataContainerPath=%@", rp[@"lsDataContainerPath"] ?: @""]);
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"lsContainerURLPath=%@", rp[@"lsContainerURLPath"] ?: @""]);
            PXDebugRun(runner, debugPre, @"ls backupDir", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(backupDir)]);

            PXDebugHeader(debugPre, @"System Snapshot (Debug Only)");
            PXDebugRun(runner, debugPre, @"ls Accounts3", @"ls -lh /var/mobile/Library/Accounts/Accounts3.sqlite 2>/dev/null || true");
            PXDebugRun(runner, debugPre, @"ls Cookies", @"ls -la /var/mobile/Library/Cookies 2>/dev/null || true");
            PXDebugRun(runner, debugPre, @"ls WebKit WebsiteData", @"ls -la /var/mobile/Library/WebKit/WebsiteData 2>/dev/null || true");

            PXDebugHeader(debugKeychain, @"Keychain Debug");
            PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"bundleID=%@", bundleID]);
            PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"backupDir=%@", backupDir]);
        }

        // Prefer jailbreak/Procursus tar first (often has xattrs/acl support); /usr/bin/tar on iOS may not.
        NSString *tarPath = [runner firstExistingPath:@[
            @"/var/jb/usr/bin/gtar",
            @"/private/preboot/jb/usr/bin/gtar",
            @"/usr/local/bin/gtar",
            @"/usr/bin/gtar",
            @"/var/jb/usr/bin/bsdtar",
            @"/private/preboot/jb/usr/bin/bsdtar",
            @"/usr/local/bin/bsdtar",
            @"/usr/bin/bsdtar",
            @"/var/jb/usr/bin/tar",
            @"/private/preboot/jb/usr/bin/tar",
            @"/usr/bin/tar",
            @"/bin/tar"
        ]];
        if (!tarPath) {
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:301
                                           userInfo:@{NSLocalizedDescriptionKey: @"tar not found"}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }

        PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"tarPath=%@", tarPath]);

        NSString *manifestPath = [backupDir stringByAppendingPathComponent:@"manifest.plist"];
        NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:manifestPath];
        if (![manifest isKindOfClass:[NSDictionary class]]) {
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:302
                                           userInfo:@{NSLocalizedDescriptionKey: @"Manifest missing or invalid"}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }

        // Kill app before restore
        [self _killRelatedProcessesForBundleID:bundleID];

        NSString *manifestProfileId = nil;
        if ([manifest[@"profileId"] isKindOfClass:[NSString class]]) {
            manifestProfileId = manifest[@"profileId"];
        }
        NSString *activeProfileId = [self _activeProfileId];
        if (manifestProfileId.length && activeProfileId.length && ![manifestProfileId isEqualToString:activeProfileId]) {
            [warnings addObject:[NSString stringWithFormat:@"Backup was created under profile %@ but current profile is %@", manifestProfileId, activeProfileId]];
        }

        // A4 (Part 2): clean stale quarantine trash (>24h) in the narrow set of
        // parent directories this restore may touch. Done before extraction so a
        // fresh quarantine from this run is never eligible for cleanup.
        {
            NSMutableSet<NSString *> *trashScanDirs = [NSMutableSet set];
            NSString *restoreLibBase = [self _mobileLibraryBasePath];
            if (restoreLibBase.length) {
                [trashScanDirs addObject:restoreLibBase];
            }
            NSDictionary *sharedDBManifest = manifest[@"sharedSystemDB"];
            if ([sharedDBManifest isKindOfClass:[NSDictionary class]]) {
                NSArray *files = sharedDBManifest[@"files"];
                if ([files isKindOfClass:[NSArray class]]) {
                    for (NSDictionary *d in files) {
                        if (![d isKindOfClass:[NSDictionary class]]) continue;
                        NSString *libraryRel = d[@"libraryRel"];
                        if (![libraryRel isKindOfClass:[NSString class]] || !libraryRel.length) continue;
                        if (!restoreLibBase.length) continue;
                        NSString *dest = [restoreLibBase stringByAppendingPathComponent:libraryRel];
                        NSString *parent = [dest stringByDeletingLastPathComponent];
                        if (parent.length) {
                            [trashScanDirs addObject:parent];
                        }
                    }
                }
            }
            [self _cleanStaleQuarantineTrashInDirectories:[trashScanDirs allObjects]
                                                olderThan:86400.0];
        }

        // Data container lookup:
        // Prefer active container path (LaunchServices). Fall back to metadata scan.
        NSString *manifestDataUUID = nil;
        if ([manifest[@"data"] isKindOfClass:[NSDictionary class]] && [manifest[@"data"][@"uuid"] isKindOfClass:[NSString class]]) {
            manifestDataUUID = manifest[@"data"][@"uuid"];
        }
 
        NSString *dataUUID = nil;
        NSString *dataContainerPath = nil;

        // Prefer LaunchServices-reported container path (most reliable for the *active* container).
        {
            NSString *lsPath = PXDataContainerPathFromLaunchServices(bundleID);
            BOOL isDir = NO;
            if (lsPath.length && [fm fileExistsAtPath:lsPath isDirectory:&isDir] && isDir) {
                dataContainerPath = lsPath;
                dataUUID = lsPath.lastPathComponent;
            }
        }

        NSArray<NSString *> *bases = @[
            @"/var/mobile/Containers/Data/Application",
            @"/private/var/mobile/Containers/Data/Application",
            @"/containers/Data/Application",
            @"/private/var/containers/Data/Application"
        ];

        // Scan bases for a container with matching metadata.
        if (!dataContainerPath) {
            for (NSString *base in bases) {
                NSString *found = PXFindDataContainerUUIDByMetadata(fm, base, bundleID);
                if (found.length) {
                    dataUUID = found;
                    dataContainerPath = [base stringByAppendingPathComponent:found];
                    break;
                }
            }
        }

        // Fallback: use manifest containerPath/UUID if directory exists (useful after aggressive clears).
        if (!dataContainerPath) {
            NSString *p = nil;
            if ([manifest[@"data"] isKindOfClass:[NSDictionary class]] && [manifest[@"data"][@"containerPath"] isKindOfClass:[NSString class]]) {
                p = manifest[@"data"][@"containerPath"];
            }
            BOOL isDir = NO;
            if (p.length && [fm fileExistsAtPath:p isDirectory:&isDir] && isDir) {
                dataContainerPath = p;
                dataUUID = p.lastPathComponent;
                [warnings addObject:@"Using manifest containerPath for restore (fallback)" ];
            }
        }
        if (!dataContainerPath && manifestDataUUID.length) {
            for (NSString *base in bases) {
                NSString *p = [base stringByAppendingPathComponent:manifestDataUUID];
                BOOL isDir = NO;
                if ([fm fileExistsAtPath:p isDirectory:&isDir] && isDir) {
                    dataContainerPath = p;
                    dataUUID = manifestDataUUID;
                    [warnings addObject:@"Using manifest UUID for restore (fallback)" ];
                    break;
                }
            }
        }

        if (!dataUUID.length || !dataContainerPath.length) {
            NSString *hint = @"Data container not found. Ensure the app is installed and launched at least once (to create its data container).";
            NSString *lsPath = PXDataContainerPathFromLaunchServices(bundleID) ?: @"";
            NSString *detail = [NSString stringWithFormat:@"%@ (bundleID=%@ lsPath=%@ manifestUUID=%@)", hint, bundleID, lsPath, manifestDataUUID ?: @""];
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:303
                                           userInfo:@{NSLocalizedDescriptionKey: detail}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }

        PXDebugHeader(debugPre, @"Chosen Container");
        PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"chosenDataContainerPath=%@", dataContainerPath ?: @""]);
        PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"chosenDataUUID=%@", dataUUID ?: @""]);
        PXDebugRun(runner, debugPre, @"du data", [NSString stringWithFormat:@"du -sk %@ 2>/dev/null || true", PXShellQuote(dataContainerPath)]);
        PXDebugRun(runner, debugPre, @"ls prefs", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote([dataContainerPath stringByAppendingPathComponent:@"Library/Preferences"]) ]);

        // App Groups via entitlements (Option B)
        NSArray<AppGroupContainerInfo *> *groupContainers = @[];
        NSDictionary *options = manifest[@"options"];
        BOOL includeGroups = YES;
        if ([options isKindOfClass:[NSDictionary class]] && [options[@"includeAppGroups"] respondsToSelector:@selector(boolValue)]) {
            includeGroups = [options[@"includeAppGroups"] boolValue];
        }
        if (includeGroups) {
            NSError *entErr = nil;
            AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
            NSArray<NSString *> *groupIDs = [reader applicationGroupsForBundleID:bundleID error:&entErr];
            if (entErr) {
                [warnings addObject:[NSString stringWithFormat:@"Entitlements read failed: %@", entErr.localizedDescription]];
            }
            if (groupIDs.count) {
                AppGroupContainerResolver *resolver = [[AppGroupContainerResolver alloc] init];
                groupContainers = [resolver resolveGroupContainersForGroupIDs:groupIDs];
            }
        }

        // Integrity verify artifacts (best-effort)
        NSDictionary *artByName = nil;
        if ([manifest[@"artifacts"] isKindOfClass:[NSArray class]]) {
            NSMutableDictionary *m = [NSMutableDictionary dictionary];
            for (NSDictionary *a in (NSArray *)manifest[@"artifacts"]) {
                if (![a isKindOfClass:[NSDictionary class]]) continue;
                NSString *name = a[@"name"];
                if ([name isKindOfClass:[NSString class]] && name.length) {
                    m[name] = a;
                }
            }
            artByName = m;
        }

        // Validate data archive before wiping
        NSString *dataArchive = [backupDir stringByAppendingPathComponent:@"data.tar.gz"];
        if (![fm fileExistsAtPath:dataArchive]) {
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:305
                                           userInfo:@{NSLocalizedDescriptionKey: @"data.tar.gz missing"}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }
        NSDictionary *dataArt = artByName ? artByName[@"data.tar.gz"] : nil;
        if ([dataArt isKindOfClass:[NSDictionary class]]) {
            NSNumber *expectedSize = dataArt[@"size"];
            NSString *expectedHash = dataArt[@"sha256"];
            NSDictionary *attrs = [fm attributesOfItemAtPath:dataArchive error:nil];
            NSNumber *size = attrs[NSFileSize];
            if (expectedSize && size && [expectedSize longLongValue] > 0 && [size longLongValue] != [expectedSize longLongValue]) {
                NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                   code:314
                                               userInfo:@{NSLocalizedDescriptionKey: @"data.tar.gz size mismatch"}];
                dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                return;
            }
            if ([expectedHash isKindOfClass:[NSString class]] && expectedHash.length > 0) {
                NSString *actual = PXHexString(PXFileSHA256(dataArchive));
                if (actual.length && ![actual isEqualToString:expectedHash]) {
                    NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                       code:315
                                                   userInfo:@{NSLocalizedDescriptionKey: @"data.tar.gz sha256 mismatch"}];
                    dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                    return;
                }
            }
        }

        // Two-phase restore for data container: extract to staging first.
        NSString *stagingRoot = [NSString stringWithFormat:@"/tmp/weaponx_restore_%d", getpid()];
        NSString *stagingData = [stagingRoot stringByAppendingPathComponent:@"data"]; 
        [fm removeItemAtPath:stagingRoot error:nil];
        [fm createDirectoryAtPath:stagingData withIntermediateDirectories:YES attributes:nil error:nil];

        CommandResult *stx = [self _tarExtract:tarPath archive:dataArchive toDir:stagingData];
        if (stx.exitCode != 0) {
            NSString *msg = stx.stderrString.length ? stx.stderrString : @"Failed to extract data archive to staging";
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:316
                                           userInfo:@{NSLocalizedDescriptionKey: msg}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }

        // Wipe data container contents and clone from staging via tar pipe.
        PXDebugHeader(debugPre, @"Data Restore (Staging -> Container)");
        PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"stagingData=%@", stagingData ?: @""]);
        PXDebugRun(runner, debugPre, @"du stagingData", [NSString stringWithFormat:@"du -sk %@ 2>/dev/null || true", PXShellQuote(stagingData)]);
        PXDebugRun(runner, debugPre, @"ls container (before wipe)", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(dataContainerPath)]);
        // A1: hard-fail if the data container could not be fully wiped. Continuing
        // would clone restored data on top of stale files, mixing old and new
        // state in the app's primary container.
        NSArray<NSString *> *wipeFailed = [self _wipeDirectoryContents:dataContainerPath];
        if (wipeFailed.count) {
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"wipeFailedCount=%lu", (unsigned long)wipeFailed.count]);
            for (NSString *fp in wipeFailed) {
                PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"wipeFailed=%@", fp]);
            }
            [fm removeItemAtPath:stagingRoot error:nil];
            NSString *msg = [NSString stringWithFormat:@"Failed to wipe data container before restore (%lu item(s) remained); aborting to avoid mixing stale and restored data", (unsigned long)wipeFailed.count];
            NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                               code:319
                                           userInfo:@{NSLocalizedDescriptionKey: msg}];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
            return;
        }
        PXDebugRun(runner, debugPre, @"ls container (after wipe)", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(dataContainerPath)]);
        BOOL shouldPreferCpClone = NO;
        if ([tarPath isEqualToString:@"/usr/bin/tar"] || [tarPath isEqualToString:@"/bin/tar"]) {
            // iOS system tar commonly lacks xattrs/acl support.
            shouldPreferCpClone = YES;
        }

        CommandResult *cloneRes = nil;
        if (!shouldPreferCpClone) {
            NSString *cloneCmd = [NSString stringWithFormat:@"%@ --xattrs --acls -cf - -C %@ . | %@ --xattrs --acls -xf - -C %@",
                                  PXShellQuote(tarPath),
                                  PXShellQuote(stagingData),
                                  PXShellQuote(tarPath),
                                  PXShellQuote(dataContainerPath)];
            cloneRes = [runner runAndCapture:cloneCmd];
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"tarPipeCloneExit=%d", (int)cloneRes.exitCode]);
            if (cloneRes.stderrString.length) {
                PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"tarPipeCloneStderr=%@", cloneRes.stderrString]);
            }
            if (cloneRes.exitCode != 0) {
                shouldPreferCpClone = YES;
            }
            if (cloneRes.stderrString.length && [cloneRes.stderrString containsString:@"XATTR support is not available"]) {
                // Even if tar returns exit=0, we will not get correct metadata.
                shouldPreferCpClone = YES;
            }
        } else {
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"tarPipeCloneSkipped=1 tarPath=%@", tarPath]);
        }

        if (shouldPreferCpClone) {
            NSString *fallbackCmd = [NSString stringWithFormat:@"cp -a %@/. %@/ 2>/dev/null",
                                     PXShellQuote(stagingData),
                                     PXShellQuote(dataContainerPath)];
            CommandResult *cpRes = [runner runAndCapture:fallbackCmd];
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"cpCloneExit=%d", (int)cpRes.exitCode]);
            if (cpRes.stderrString.length) {
                PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"cpCloneStderr=%@", cpRes.stderrString]);
            }
            if (cpRes.exitCode != 0) {
                NSString *msg = (cloneRes && cloneRes.stderrString.length) ? cloneRes.stderrString : @"tar pipe clone failed";
                if (cpRes.stderrString.length) {
                    msg = [msg stringByAppendingFormat:@"; cp: %@", cpRes.stderrString];
                }
                NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                   code:317
                                               userInfo:@{NSLocalizedDescriptionKey: msg}];
                dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                return;
            }
        }

        // Ensure ownership is correct (some extraction/copy paths may produce root-owned files).
        [runner run:[NSString stringWithFormat:@"chown -R mobile:mobile %@ 2>/dev/null || true", PXShellQuote(dataContainerPath)]];

        // Post-restore hygiene: refresh preferences daemon caches.
        // Some apps read state via cfprefsd and may not notice external file writes immediately.
        PXKillallByName(@"cfprefsd", SIGTERM);

        // Cleanup staging best-effort
        [fm removeItemAtPath:stagingRoot error:nil];

        // Data container restored.

        // Restore profile redirected appdata (if present)
        NSDictionary *profileAppData = manifest[@"profileAppData"];
        BOOL includeProfileAppData = NO;
        if ([profileAppData isKindOfClass:[NSDictionary class]] && [profileAppData[@"included"] respondsToSelector:@selector(boolValue)]) {
            includeProfileAppData = [profileAppData[@"included"] boolValue];
        }
        if (includeProfileAppData) {
            NSString *profileAppDataPath = [self _profileAppDataPathForBundleID:bundleID];
            NSString *archivePath = [backupDir stringByAppendingPathComponent:@"profile_appdata.tar.gz"];
            if (profileAppDataPath.length && [fm fileExistsAtPath:archivePath]) {
                BOOL isDir = NO;
                if ([fm fileExistsAtPath:profileAppDataPath isDirectory:&isDir] && isDir) {
                    // A1: warning-only for non-primary containers; restore continues.
                    NSArray<NSString *> *pwFailed = [self _wipeDirectoryContents:profileAppDataPath];
                    if (pwFailed.count) {
                        [warnings addObject:[NSString stringWithFormat:@"Profile appdata wipe incomplete (%lu item(s) remained); restored data may mix with stale files", (unsigned long)pwFailed.count]];
                    }
                    CommandResult *r = [self _tarExtract:tarPath archive:archivePath toDir:profileAppDataPath];
                    if (r.exitCode != 0) {
                        NSString *msg = r.stderrString.length ? r.stderrString : @"Failed to restore profile appdata";
                        NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                           code:307
                                                       userInfo:@{NSLocalizedDescriptionKey: msg}];
                        dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                        return;
                    }
                    [runner run:[NSString stringWithFormat:@"chown -R mobile:mobile %@ 2>/dev/null || true", PXShellQuote(profileAppDataPath)]];
                } else {
                    NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                       code:308
                                                   userInfo:@{NSLocalizedDescriptionKey: @"Profile appdata directory missing"}];
                    dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                    return;
                }
            } else {
                NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                   code:309
                                               userInfo:@{NSLocalizedDescriptionKey: @"Profile appdata archive missing"}];
                dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                return;
            }
        }

        // Restore global Safari library (if present)
        NSDictionary *globalSafari = manifest[@"globalSafari"];
        BOOL includeGlobalSafari = NO;
        if ([globalSafari isKindOfClass:[NSDictionary class]] && [globalSafari[@"included"] respondsToSelector:@selector(boolValue)]) {
            includeGlobalSafari = [globalSafari[@"included"] boolValue];
        }
        if (includeGlobalSafari) {
            NSString *globalSafariPath = [self _globalSafariLibraryPath];
            NSString *archivePath = [backupDir stringByAppendingPathComponent:@"global_safari.tar.gz"];
            if (globalSafariPath.length && [fm fileExistsAtPath:archivePath]) {
                BOOL isDir = NO;
                if ([fm fileExistsAtPath:globalSafariPath isDirectory:&isDir] && isDir) {
                    // A1: warning-only for non-primary containers; restore continues.
                    NSArray<NSString *> *gsFailed = [self _wipeDirectoryContents:globalSafariPath];
                    if (gsFailed.count) {
                        [warnings addObject:[NSString stringWithFormat:@"Global Safari wipe incomplete (%lu item(s) remained); restored data may mix with stale files", (unsigned long)gsFailed.count]];
                    }
                    CommandResult *r = [self _tarExtract:tarPath archive:archivePath toDir:globalSafariPath];
                    if (r.exitCode != 0) {
                        NSString *msg = r.stderrString.length ? r.stderrString : @"Failed to restore global Safari library";
                        NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                           code:311
                                                       userInfo:@{NSLocalizedDescriptionKey: msg}];
                        dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                        return;
                    }
                    [runner run:[NSString stringWithFormat:@"chown -R mobile:mobile %@ 2>/dev/null || true", PXShellQuote(globalSafariPath)]];
                } else {
                    NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                       code:312
                                                   userInfo:@{NSLocalizedDescriptionKey: @"Global Safari directory missing"}];
                    dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                    return;
                }
            } else {
                NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                   code:313
                                               userInfo:@{NSLocalizedDescriptionKey: @"Global Safari archive missing"}];
                dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                return;
            }
        }

        // Wipe and restore each group
        for (AppGroupContainerInfo *info in groupContainers) {
            // Debug: group state before wipe
            PXDebugHeader(debugPre, [NSString stringWithFormat:@"Group Restore: %@", info.groupID ?: @""]);
            PXDebugAppendLine(debugPre, [NSString stringWithFormat:@"groupPath=%@", info.path ?: @""]);
            PXDebugRun(runner, debugPre, @"ls group (before)", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(info.path)]);
            // A1: warning-only for app group containers; restore continues.
            NSArray<NSString *> *grpFailed = [self _wipeDirectoryContents:info.path];
            if (grpFailed.count) {
                [warnings addObject:[NSString stringWithFormat:@"Group %@ wipe incomplete (%lu item(s) remained); restored data may mix with stale files", info.groupID ?: @"", (unsigned long)grpFailed.count]];
            }
            PXDebugRun(runner, debugPre, @"ls group (after wipe)", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(info.path)]);

            NSString *archiveName = [NSString stringWithFormat:@"%@.tar.gz", PXSanitizeFilenameComponent(info.groupID)];
            NSString *archivePath = [[backupDir stringByAppendingPathComponent:@"groups"] stringByAppendingPathComponent:archiveName];
            if (![fm fileExistsAtPath:archivePath]) {
                [warnings addObject:[NSString stringWithFormat:@"Missing group archive for %@", info.groupID]];
                continue;
            }

            CommandResult *r = [self _tarExtract:tarPath archive:archivePath toDir:info.path];
            if (r.exitCode != 0) {
                NSString *msg = r.stderrString.length ? r.stderrString : [NSString stringWithFormat:@"Failed to extract group %@", info.groupID];
                NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                   code:310
                                               userInfo:@{NSLocalizedDescriptionKey: msg}];
                dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                return;
            }

            [runner run:[NSString stringWithFormat:@"chown -R mobile:mobile %@ 2>/dev/null || true", PXShellQuote(info.path)]];
            PXDebugRun(runner, debugPost, @"ls group (after extract)", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote(info.path)]);
        }

        // Restore generic system app global Library folders (if present)
        NSDictionary *systemGlobal = manifest[@"systemGlobalLibrary"];
        BOOL includeSystemGlobal = NO;
        NSArray *items = nil;
        if ([systemGlobal isKindOfClass:[NSDictionary class]]) {
            if ([systemGlobal[@"included"] respondsToSelector:@selector(boolValue)]) {
                includeSystemGlobal = [systemGlobal[@"included"] boolValue];
            }
            if ([systemGlobal[@"items"] isKindOfClass:[NSArray class]]) {
                items = systemGlobal[@"items"];
            }
        }
        if (includeSystemGlobal && items.count) {
            NSString *libBase = [self _mobileLibraryBasePath];
            for (NSDictionary *it in (NSArray *)items) {
                if (![it isKindOfClass:[NSDictionary class]]) continue;
                NSString *subdir = [it[@"subdir"] isKindOfClass:[NSString class]] ? it[@"subdir"] : nil;
                NSString *archive = [it[@"archive"] isKindOfClass:[NSString class]] ? it[@"archive"] : nil;
                if (!subdir.length || !archive.length) continue;

                // Avoid double-restoring Safari which is handled explicitly.
                if ([bundleID isEqualToString:@"com.apple.mobilesafari"] && [subdir isEqualToString:@"Safari"]) {
                    continue;
                }

                NSString *archivePath = [backupDir stringByAppendingPathComponent:archive];
                if (![fm fileExistsAtPath:archivePath]) {
                    [warnings addObject:[NSString stringWithFormat:@"Missing system global archive for %@; skipping", subdir]];
                    continue;
                }

                NSString *dest = [libBase stringByAppendingPathComponent:subdir];
                [self _killRelatedProcessesForBundleID:bundleID];

                // Quarantine existing directory to avoid detached DB crashes.
                NSString *trash = [NSString stringWithFormat:@"%@.WeaponXTrash.%@", dest, PXTimestampSuffix()];
                if ([fm fileExistsAtPath:dest]) {
                    [runner run:[NSString stringWithFormat:@"mv %@ %@ 2>/dev/null || true", PXShellQuote(dest), PXShellQuote(trash)]];
                }
                [runner run:[NSString stringWithFormat:@"mkdir -p %@ 2>/dev/null || true", PXShellQuote(dest)]];

                CommandResult *r = [self _tarExtract:tarPath archive:archivePath toDir:dest];
                if (r.exitCode != 0) {
                    NSString *msg = r.stderrString.length ? r.stderrString : [NSString stringWithFormat:@"Failed to restore system global library %@", subdir];
                    NSError *err = [NSError errorWithDomain:PXBackupErrorDomain
                                                       code:318
                                                   userInfo:@{NSLocalizedDescriptionKey: msg}];
                    dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(nil, err); });
                    return;
                }
                // A4: extract succeeded; remove the quarantined trash for this dest now.
                if (trash.length && [fm fileExistsAtPath:trash]) {
                    [runner run:[NSString stringWithFormat:@"rm -rf %@ 2>/dev/null || true", PXShellQuote(trash)]];
                }
                [runner run:[NSString stringWithFormat:@"chown -R mobile:mobile %@ 2>/dev/null || true", PXShellQuote(dest)]];
            }
        }

        // Restore shared system DBs (if present)
        NSDictionary *sharedDB = manifest[@"sharedSystemDB"];
        BOOL includeSharedDB = NO;
        NSArray *dbFiles = nil;
        if ([sharedDB isKindOfClass:[NSDictionary class]]) {
            if ([sharedDB[@"included"] respondsToSelector:@selector(boolValue)]) {
                includeSharedDB = [sharedDB[@"included"] boolValue];
            }
            if ([sharedDB[@"files"] isKindOfClass:[NSArray class]]) {
                dbFiles = sharedDB[@"files"];
            }
        }
        if (includeSharedDB && dbFiles.count) {
            NSString *libBase = [self _mobileLibraryBasePath];

            // Stop common daemons that may hold these DBs.
            // A3: poll for actual exit instead of a fixed 0.2s sleep. Send
            // SIGTERM, wait (bounded) for the daemons to leave the process
            // table, then SIGKILL any that are still alive as a fallback.
            NSArray<NSString *> *dbDaemons = @[@"accountsd", @"calaccessd", @"imagent", @"MobileSMS"];
            for (NSString *d in dbDaemons) {
                PXKillallByName(d, SIGTERM);
            }
            if (!PXWaitForProcessesToExit(dbDaemons, 2.0)) {
                // Some daemon did not exit within the grace window; force-kill
                // the stragglers and give them a brief moment to disappear.
                for (NSString *d in dbDaemons) {
                    if (PXProcessIsRunning(d)) {
                        PXKillallByName(d, SIGKILL);
                    }
                }
                PXWaitForProcessesToExit(dbDaemons, 0.5);
            }

            for (NSDictionary *it in (NSArray *)dbFiles) {
                if (![it isKindOfClass:[NSDictionary class]]) continue;
                NSString *libraryRel = [it[@"libraryRel"] isKindOfClass:[NSString class]] ? it[@"libraryRel"] : nil;
                NSString *archiveRel = [it[@"archive"] isKindOfClass:[NSString class]] ? it[@"archive"] : nil;
                if (!libraryRel.length || !archiveRel.length) continue;

                NSString *src = [backupDir stringByAppendingPathComponent:archiveRel];
                if (![fm fileExistsAtPath:src]) {
                    [warnings addObject:[NSString stringWithFormat:@"Missing shared DB archive %@; skipping", archiveRel]];
                    continue;
                }

                NSString *dest = [libBase stringByAppendingPathComponent:libraryRel];
                NSString *destDir = [dest stringByDeletingLastPathComponent];
                [runner run:[NSString stringWithFormat:@"mkdir -p %@ 2>/dev/null || true", PXShellQuote(destDir)]];

                NSString *trash = [NSString stringWithFormat:@"%@.WeaponXTrash.%@", dest, PXTimestampSuffix()];
                if ([fm fileExistsAtPath:dest]) {
                    [runner run:[NSString stringWithFormat:@"mv %@ %@ 2>/dev/null || true", PXShellQuote(dest), PXShellQuote(trash)]];
                }

                [runner run:[NSString stringWithFormat:@"cp -a %@ %@ 2>/dev/null || true", PXShellQuote(src), PXShellQuote(dest)]];
                [runner run:[NSString stringWithFormat:@"chown mobile:mobile %@ 2>/dev/null || true", PXShellQuote(dest)]];
                [runner run:[NSString stringWithFormat:@"chmod 600 %@ 2>/dev/null || true", PXShellQuote(dest)]];
                // A4: copy verified by destination existence; remove this dest's trash now.
                if (trash.length && [fm fileExistsAtPath:dest] && [fm fileExistsAtPath:trash]) {
                    [runner run:[NSString stringWithFormat:@"rm -rf %@ 2>/dev/null || true", PXShellQuote(trash)]];
                }
            }

            [warnings addObject:@"Restored shared system DBs (this may affect multiple apps)"];

            // Restart daemons best-effort.
            PXKillallByName(@"accountsd", SIGTERM);
            PXKillallByName(@"calaccessd", SIGTERM);
            PXKillallByName(@"imagent", SIGTERM);
            PXKillallByName(@"MobileSMS", SIGTERM);
        }

        // Preferences restore
        BOOL includePrefs = YES;
        NSDictionary *prefs = manifest[@"preferences"];
        if ([prefs isKindOfClass:[NSDictionary class]] && [prefs[@"included"] respondsToSelector:@selector(boolValue)]) {
            includePrefs = [prefs[@"included"] boolValue];
        }
        if (includePrefs) {
            NSString *prefBackup = [[backupDir stringByAppendingPathComponent:@"preferences"] stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.plist", bundleID]];
            NSString *prefDest = [self _preferencesPlistPathForBundleID:bundleID];
            if ([fm fileExistsAtPath:prefBackup]) {
                // A2: kill cfprefsd BEFORE copying the plist so its in-memory cache
                // cannot flush stale values back over the freshly copied file
                // during the copy. Kill again afterwards to force a reload from
                // the new file on next access.
                PXKillallByName(@"cfprefsd", SIGTERM);
                [runner run:[NSString stringWithFormat:@"cp -f %@ %@ 2>/dev/null || true", PXShellQuote(prefBackup), PXShellQuote(prefDest)]];
                [runner run:[NSString stringWithFormat:@"chown mobile:mobile %@ 2>/dev/null || true", PXShellQuote(prefDest)]];
                [runner run:[NSString stringWithFormat:@"chmod 644 %@ 2>/dev/null || true", PXShellQuote(prefDest)]];
                PXKillallByName(@"cfprefsd", SIGTERM);
            } else {
                [warnings addObject:@"Preferences archive missing; skipping"];
            }
        }

        // Keychain restore (warning-only on failure)
        NSDictionary *keychainInfo = manifest[@"keychain"];
        BOOL includeKeychain = NO;
        if ([keychainInfo isKindOfClass:[NSDictionary class]] && [keychainInfo[@"included"] respondsToSelector:@selector(boolValue)]) {
            includeKeychain = [keychainInfo[@"included"] boolValue];
        }
        if (includeKeychain) {
            NSString *keychainBackupPath = [backupDir stringByAppendingPathComponent:@"keychain.plist"];
            NSArray<NSString *> *groups = @[];
            if ([keychainInfo isKindOfClass:[NSDictionary class]] && [keychainInfo[@"groupsSelected"] isKindOfClass:[NSArray class]]) {
                groups = keychainInfo[@"groupsSelected"];
            }
            NSString *method = ([keychainInfo isKindOfClass:[NSDictionary class]] && [keychainInfo[@"method"] isKindOfClass:[NSString class]]) ? keychainInfo[@"method"] : @"";
            BOOL shouldUseInApp = PXGroupsContainPlatformFamily(groups) || [method isEqualToString:@"in_app"];

            BOOL ok = NO;
            if (shouldUseInApp) {
                // Use app context so keychain access uses the app's original entitlements.
                ok = [self _inAppKeychainRestoreForBundleID:bundleID
                                              containerPath:dataContainerPath
                                                     groups:groups
                                                   fromFile:keychainBackupPath
                                                  overwrite:YES
                                                  debugPath:debugKeychain
                                                   warnings:warnings];
            } else {
                ok = [self _restoreKeychainForBundleID:bundleID
                                              groups:groups
                                            fromFile:keychainBackupPath
                                           overwrite:YES
                                            warnings:warnings];
            }

            if (!ok) {
                [warnings addObject:@"Keychain restore failed (continuing)" ];
            }

            // Debug keychain list after restore
            PXDebugHeader(debugKeychain, @"Keychain After Restore");
            PXDebugAppendLine(debugKeychain, [NSString stringWithFormat:@"groups=%@", groups ?: @[]]);
            if (!shouldUseInApp) {
                NSString *scriptPath = [runner firstExistingPath:@[@"/Library/WeaponX/keychain_backup.sh",
                                                                  @"/var/jb/Library/WeaponX/keychain_backup.sh",
                                                                  @"/private/var/jb/Library/WeaponX/keychain_backup.sh"]];
                if (scriptPath.length && groups.count) {
                    NSString *csv = [groups componentsJoinedByString:@","];
                    PXDebugRun(runner, debugKeychain, @"list", [NSString stringWithFormat:@"%@ list %@ --groups %@", PXShellQuote(scriptPath), PXShellQuote(bundleID), PXShellQuote(csv)]);
                }
            } else {
                PXDebugAppendLine(debugKeychain, @"post-restore list skipped (used in-app keychain method)" );
            }
        }

        // Debug snapshot: after restore
        {
            PXDebugHeader(debugPost, @"Restore Done");
            NSDictionary *rp = PXResolvePathsForBundleID(bundleID);
            NSString *lsDataPath = rp[@"lsDataContainerPath"];
            PXDebugAppendLine(debugPost, [NSString stringWithFormat:@"lsDataContainerPath=%@", lsDataPath ?: @""]);
            PXDebugAppendLine(debugPost, [NSString stringWithFormat:@"chosenDataContainerPath=%@", dataContainerPath ?: @""]);
            PXDebugRun(runner, debugPost, @"du data", [NSString stringWithFormat:@"du -sk %@ 2>/dev/null || true", PXShellQuote(dataContainerPath)]);
            PXDebugRun(runner, debugPost, @"ls prefs", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote([dataContainerPath stringByAppendingPathComponent:@"Library/Preferences"]) ]);
            NSString *prefDest = [self _preferencesPlistPathForBundleID:bundleID];
            PXDebugRun(runner, debugPost, @"ls global prefs", [NSString stringWithFormat:@"ls -lh %@ 2>/dev/null || true", PXShellQuote(prefDest)]);

            if ([lsDataPath isKindOfClass:[NSString class]] && lsDataPath.length && ![lsDataPath isEqualToString:dataContainerPath]) {
                PXDebugHeader(debugPost, @"WARNING: Active Container Differs");
                PXDebugRun(runner, debugPost, @"du lsDataContainerPath", [NSString stringWithFormat:@"du -sk %@ 2>/dev/null || true", PXShellQuote(lsDataPath)]);
                PXDebugRun(runner, debugPost, @"ls lsDataContainerPath/Library/Preferences", [NSString stringWithFormat:@"ls -la %@ 2>/dev/null || true", PXShellQuote([lsDataPath stringByAppendingPathComponent:@"Library/Preferences"]) ]);
            }
        }

        PXRestoreResult *out = [[PXRestoreResult alloc] init];
        out.warnings = warnings;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) {
                completion(out, nil);
            }
        });
    });
}

@end
