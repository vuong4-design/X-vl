#import "AppDataCleaner.h"
#import <spawn.h>
#import <sys/wait.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/message.h>
#import <errno.h>
#import <unistd.h>
#import <sys/stat.h>
#import <signal.h>
#import <sqlite3.h>
#import <notify.h>

#import "AppEntitlementsReader.h"
#import "CommandRunner.h"
#import "AppGroupContainerResolver.h"
#import "FreezeManager.h"
#import "common/PXProcessKiller.h"
#ifdef PROJECTX_TROLLSTORE
#import "PXShellRouter.h"
#endif

// Add SearchableIndex framework if available
#import <CoreSpotlight/CoreSpotlight.h>

// For NSTask compatibility on iOS
@interface NSTask : NSObject
- (void)setLaunchPath:(NSString *)path;
- (void)setArguments:(NSArray *)arguments;
- (void)setStandardOutput:(id)output;
- (void)setStandardError:(id)error;
- (void)launch;
- (void)waitUntilExit;
@end

@implementation AppDataCleaner {
    NSFileManager *_fileManager;
}

- (BOOL)_sqliteExecAtPath:(NSString *)dbPath sql:(NSString *)sql errorOut:(NSString **)errorOut {
    if (!dbPath.length || !sql.length) {
        if (errorOut) *errorOut = @"invalid args";
        return NO;
    }
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(dbPath.UTF8String, &db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK || !db) {
        if (errorOut) {
            const char *msg = db ? sqlite3_errmsg(db) : "open failed";
            *errorOut = [NSString stringWithFormat:@"sqlite open rc=%d %s", rc, msg];
        }
        if (db) sqlite3_close(db);
        return NO;
    }
    sqlite3_busy_timeout(db, 3000);

    char *errMsg = NULL;
    rc = sqlite3_exec(db, sql.UTF8String, NULL, NULL, &errMsg);
    BOOL ok = (rc == SQLITE_OK);
    if (!ok && errorOut) {
        NSString *e = errMsg ? [NSString stringWithUTF8String:errMsg] : @"sqlite exec failed";
        *errorOut = [NSString stringWithFormat:@"sqlite exec rc=%d %@", rc, e ?: @""];
    }
    if (errMsg) sqlite3_free(errMsg);
    sqlite3_close(db);
    return ok;
}

// Execute SQL on an already-open sqlite handle.
static BOOL PXSQLiteExec(sqlite3 *db, NSString *sql, NSString **errorOut) {
    if (!db || !sql.length) {
        if (errorOut) *errorOut = @"invalid args";
        return NO;
    }
    char *errMsg = NULL;
    int rc = sqlite3_exec(db, sql.UTF8String, NULL, NULL, &errMsg);
    BOOL ok = (rc == SQLITE_OK);
    if (!ok && errorOut) {
        NSString *e = errMsg ? [NSString stringWithUTF8String:errMsg] : @"sqlite exec failed";
        *errorOut = [NSString stringWithFormat:@"sqlite exec rc=%d %@", rc, e ?: @""];
    }
    if (errMsg) sqlite3_free(errMsg);
    return ok;
}

static NSString *PXSQLiteScalar(sqlite3 *db, NSString *sql) {
    if (!db || !sql.length) return nil;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL);
    if (rc != SQLITE_OK || !stmt) return nil;
    NSString *out = nil;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        if (txt) out = [NSString stringWithUTF8String:(const char *)txt];
    }
    sqlite3_finalize(stmt);
    return out;
}

static BOOL PXSQLiteTableHasColumn(sqlite3 *db, NSString *table, NSString *column) {
    if (!db || !table.length || !column.length) return NO;
    NSString *t = [table stringByReplacingOccurrencesOfString:@"'" withString:@"''"]; 
    NSString *sql = [NSString stringWithFormat:@"PRAGMA table_info('%@');", t];
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &st, NULL);
    if (rc != SQLITE_OK || !st) {
        if (st) sqlite3_finalize(st);
        return NO;
    }
    BOOL found = NO;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1); // column name
        if (name) {
            NSString *n = [NSString stringWithUTF8String:(const char *)name];
            if ([n isEqualToString:column]) {
                found = YES;
                break;
            }
        }
    }
    sqlite3_finalize(st);
    return found;
}

static BOOL PXSQLiteIsSafeIdentifier(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"];
    return ([[s stringByTrimmingCharactersInSet:allowed] length] == 0);
}

static NSSet<NSString *> *PXSQLiteColumnsForTableCached(sqlite3 *db,
                                                        NSString *table,
                                                        NSMutableDictionary<NSString *, NSSet<NSString *> *> *cache) {
    if (!db || !table.length) return [NSSet set];
    if (!cache) return [NSSet set];
    NSSet *cached = cache[table];
    if ([cached isKindOfClass:[NSSet class]]) return cached;

    if (!PXSQLiteIsSafeIdentifier(table)) {
        cache[table] = [NSSet set];
        return cache[table];
    }

    NSString *sql = [NSString stringWithFormat:@"PRAGMA table_info('%@');", table];
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &st, NULL);
    if (rc != SQLITE_OK || !st) {
        if (st) sqlite3_finalize(st);
        cache[table] = [NSSet set];
        return cache[table];
    }

    NSMutableSet<NSString *> *cols = [NSMutableSet set];
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name) {
            NSString *n = [NSString stringWithUTF8String:(const char *)name];
            if (n.length) [cols addObject:n];
        }
    }
    sqlite3_finalize(st);

    cache[table] = [cols copy];
    return cache[table];
}

static BOOL PXSQLiteTableHasColumnCached(sqlite3 *db,
                                        NSString *table,
                                        NSString *column,
                                        NSMutableDictionary<NSString *, NSSet<NSString *> *> *cache) {
    if (!db || !table.length || !column.length) return NO;
    NSSet<NSString *> *cols = PXSQLiteColumnsForTableCached(db, table, cache);
    return [cols containsObject:column];
}

static void PXSQLiteLogAccountsSample(AppDataCleaner *selfRef, sqlite3 *db, NSString *label) {
    if (!selfRef || !db) return;

    NSMutableDictionary<NSString *, NSSet<NSString *> *> *colCache = [NSMutableDictionary dictionary];
    NSMutableArray<NSString *> *cols = [NSMutableArray array];
    // Always include primary key if present.
    if (PXSQLiteTableHasColumnCached(db, @"ZACCOUNT", @"Z_PK", colCache)) [cols addObject:@"Z_PK"]; 
    if (PXSQLiteTableHasColumnCached(db, @"ZACCOUNT", @"ZACCOUNTTYPE", colCache)) [cols addObject:@"ZACCOUNTTYPE"]; 
    for (NSString *c in @[@"ZIDENTIFIER", @"ZUSERNAME", @"ZEMAILADDRESS", @"ZDISPLAYNAME", @"ZACCOUNTDESCRIPTION", @"ZOWNINGBUNDLEID"]) {
        if (PXSQLiteTableHasColumnCached(db, @"ZACCOUNT", c, colCache)) [cols addObject:c];
    }
    if (!cols.count) return;

    NSString *select = [NSString stringWithFormat:@"SELECT %@ FROM ZACCOUNT ORDER BY Z_PK LIMIT 10;", [cols componentsJoinedByString:@", "]];
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, select.UTF8String, -1, &st, NULL);
    if (rc != SQLITE_OK || !st) {
        if (st) sqlite3_finalize(st);
        return;
    }

    NSMutableArray *rows = [NSMutableArray array];
    while (sqlite3_step(st) == SQLITE_ROW) {
        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        for (int i = 0; i < (int)cols.count; i++) {
            const unsigned char *txt = sqlite3_column_text(st, i);
            if (txt) {
                row[cols[i]] = [NSString stringWithUTF8String:(const char *)txt];
            } else {
                // Integers can come back as NULL in text; try int64.
                sqlite3_int64 v = sqlite3_column_int64(st, i);
                row[cols[i]] = [NSString stringWithFormat:@"%lld", v];
            }
        }
        [rows addObject:row];
    }
    sqlite3_finalize(st);
    if (rows.count) {
        [selfRef logMessage:@"[AppDataCleaner] %@ Accounts3 ZACCOUNT sample=%@", label ?: @"", rows];
    }
}

- (NSString *)_sqliteScalarAtPath:(NSString *)dbPath sql:(NSString *)sql errorOut:(NSString **)errorOut {
    if (!dbPath.length || !sql.length) {
        if (errorOut) *errorOut = @"invalid args";
        return nil;
    }
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(dbPath.UTF8String, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK || !db) {
        if (errorOut) {
            const char *msg = db ? sqlite3_errmsg(db) : "open failed";
            *errorOut = [NSString stringWithFormat:@"sqlite open rc=%d %s", rc, msg];
        }
        if (db) sqlite3_close(db);
        return nil;
    }
    sqlite3_busy_timeout(db, 3000);

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL);
    if (rc != SQLITE_OK || !stmt) {
        if (errorOut) {
            *errorOut = [NSString stringWithFormat:@"sqlite prepare rc=%d %s", rc, sqlite3_errmsg(db)];
        }
        if (stmt) sqlite3_finalize(stmt);
        sqlite3_close(db);
        return nil;
    }

    NSString *out = nil;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        if (txt) out = [NSString stringWithUTF8String:(const char *)txt];
    } else if (rc != SQLITE_DONE) {
        if (errorOut) {
            *errorOut = [NSString stringWithFormat:@"sqlite step rc=%d %s", rc, sqlite3_errmsg(db)];
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

- (NSArray<NSString *> *)_resolvedAppGroupUUIDsFromEntitlements:(NSString *)bundleID rootless:(BOOL)rootless {
    if (!bundleID.length) return @[];

    AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
    NSError *entErr = nil;
    NSDictionary *ent = [reader fullEntitlementsForBundleID:bundleID error:&entErr];

    NSArray *groups = nil;
    if ([ent isKindOfClass:[NSDictionary class]]) {
        id v = ent[@"com.apple.security.application-groups"];
        if ([v isKindOfClass:[NSArray class]]) {
            groups = (NSArray *)v;
        } else {
            v = ent[@"application-groups"];
            if ([v isKindOfClass:[NSArray class]]) {
                groups = (NSArray *)v;
            }
        }
    }
    if (!groups.count) {
        return @[];
    }

    NSMutableArray<NSString *> *groupIDs = [NSMutableArray array];
    for (id g in groups) {
        if ([g isKindOfClass:[NSString class]] && [(NSString *)g length] > 0) {
            [groupIDs addObject:(NSString *)g];
        }
    }
    if (!groupIDs.count) {
        return @[];
    }

    AppGroupContainerResolver *resolver = [[AppGroupContainerResolver alloc] init];
    NSArray<AppGroupContainerInfo *> *infos = [resolver resolveGroupContainersForGroupIDs:groupIDs];
    NSMutableOrderedSet<NSString *> *uuids = [NSMutableOrderedSet orderedSet];
    for (AppGroupContainerInfo *info in infos) {
        if (![info.path isKindOfClass:[NSString class]] || !info.path.length) continue;
        BOOL isRootless = [info.path hasPrefix:@"/containers/Shared/AppGroup/"];
        if (rootless != isRootless) continue;
        NSString *uuid = [info.path lastPathComponent];
        if (uuid.length) {
            [uuids addObject:uuid];
        }
    }
    return uuids.array;
}

static void PXKillAppProcessBestEffort(AppDataCleaner *selfRef, NSString *bundleID) {
    if (!bundleID.length || !selfRef) return;

    // 0) Best-effort kill by LaunchServices executable name (works for system apps too)
    @try {
        Class proxyCls = NSClassFromString(@"LSApplicationProxy");
        SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
        id proxy = (proxyCls && [proxyCls respondsToSelector:sel]) ? ((id (*)(id, SEL, id))objc_msgSend)(proxyCls, sel, bundleID) : nil;
        NSString *exe = nil;
        if (proxy && [proxy respondsToSelector:@selector(bundleExecutable)]) {
            exe = [proxy performSelector:@selector(bundleExecutable)];
        }
        if ([exe isKindOfClass:[NSString class]] && exe.length) {
            PXKillallTermThenKill(exe, 0.15);
        }
    } @catch (__unused NSException *e) {
    }

    // 1) Try kill by executable name from bundle container
    NSString *bundleUUID = [selfRef findBundleContainerUUID:bundleID];
    if (bundleUUID.length) {
        NSString *bundleRoot = [NSString stringWithFormat:@"/var/mobile/Containers/Bundle/Application/%@", bundleUUID];
        NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundleRoot error:nil];
        for (NSString *item in items) {
            if ([item hasSuffix:@".app"]) {
                NSString *plistPath = [[bundleRoot stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"]; 
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plistPath];
                NSString *exeName = [info[@"CFBundleExecutable"] isKindOfClass:[NSString class]] ? info[@"CFBundleExecutable"] : nil;
                if (exeName.length) {
                    PXKillallTermThenKill(exeName, 0.15);
                }
                break;
            }
        }
    }
}

static void PXStopMailDaemonsBestEffort(AppDataCleaner *selfRef) {
    if (!selfRef) return;
    // Try to stop launchd jobs first to prevent immediate respawn.
    NSArray<NSString *> *labels = @[
        @"gui/501/com.apple.maild",
        @"gui/501/com.apple.mobilemail.maild",
        @"system/com.apple.maild",
        @"system/com.apple.mobilemail.maild"
    ];
    for (NSString *label in labels) {
        [selfRef runCommandWithPrivileges:[NSString stringWithFormat:@"launchctl kill SIGTERM %@ 2>/dev/null || true", label]];
        [selfRef runCommandWithPrivileges:[NSString stringWithFormat:@"launchctl stop %@ 2>/dev/null || true", label]];
    }

    // Fallback to process kills.
    PXKillallByName(@"maild", SIGTERM);
    PXKillallByName(@"Mail", SIGTERM);
}

static void PXStopSafariDaemonsBestEffort(AppDataCleaner *selfRef) {
    if (!selfRef) return;
    // Safari uses multiple helper processes that can keep databases open.
    NSArray<NSString *> *names = @[
        @"MobileSafari",
        @"SafariViewService",
        @"com.apple.WebKit.WebContent",
        @"com.apple.WebKit.Networking",
        @"com.apple.WebKit.GPU",
        @"nsurlsessiond",
        @"accountsd",
        @"webbookmarksd"
    ];
    (void)selfRef;
    PXKillallTermThenKillMany(names, 0.2);
}

static NSString *PXFirstExistingPath(NSFileManager *fm, NSArray<NSString *> *paths) {
    if (!fm || ![paths isKindOfClass:[NSArray class]]) return nil;
    for (NSString *p in paths) {
        if ([p isKindOfClass:[NSString class]] && p.length && [fm fileExistsAtPath:p]) {
            return p;
        }
    }
    return nil;
}

static BOOL PXWaitForProcessExit(AppDataCleaner *selfRef, NSString *procName, NSTimeInterval timeout) {
    if (!selfRef || !procName.length) return YES;
    CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
    while ((CFAbsoluteTimeGetCurrent() - start) < timeout) {
        NSString *cmd = [NSString stringWithFormat:@"pgrep -x '%@' 2>/dev/null | head -n 1", procName];
        NSString *out = [selfRef runCommandAndGetOutput:cmd];
        if (![out isKindOfClass:[NSString class]] || out.length == 0) {
            return YES;
        }
        [NSThread sleepForTimeInterval:0.1];
    }
    return NO;
}

- (BOOL)_deepCleanEnabled {
    NSUserDefaults *sec = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
    if (!sec) {
        return NO;
    }
    // Default OFF
    if (![sec objectForKey:@"deepCleanEnabled"]) {
        return NO;
    }
    return [sec boolForKey:@"deepCleanEnabled"];
}

static NSString *PXShellQuote(NSString *s) {
    if (!s.length) return @"''";
    NSString *escaped = [s stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"]; 
    return [NSString stringWithFormat:@"'%@'", escaped];
}

static NSString *PXTimestampSuffix(void) {
    return [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
}

static NSString *PXKeychainWipeEnabledKey(NSString *bundleID) {
    return [NSString stringWithFormat:@"dataCleanerKeychainWipeEnabled_%@", bundleID ?: @""];
}

static NSString *PXKeychainWipeGroupsKey(NSString *bundleID) {
    return [NSString stringWithFormat:@"dataCleanerKeychainWipeGroups_%@", bundleID ?: @""];
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
    dispatch_queue_t q = dispatch_queue_create("com.weaponx.keychainbridge.wait.cleaner", DISPATCH_QUEUE_SERIAL);
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

+ (instancetype)sharedManager {
    static AppDataCleaner *sharedManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedManager = [[self alloc] init];
    });
    return sharedManager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _fileManager = [NSFileManager defaultManager];
        // Clear old log file on init
        NSString *logPath = @"/var/mobile/Documents/AppDataCleaner.log";
        [@"=== AppDataCleaner Log Started ===\n" writeToFile:logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    return self;
}

// Helper to log to both console and file
- (void)logMessage:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    // Log to console
    NSLog(@"%@", message);
    
    // Also append to file for easy reading on device
    NSString *logPath = @"/var/mobile/Documents/AppDataCleaner.log";
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"HH:mm:ss"];
    NSString *timestamp = [formatter stringFromDate:[NSDate date]];
    NSString *logLine = [NSString stringWithFormat:@"[%@] %@\n", timestamp, message];
    
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:logPath];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:[logLine dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    } else {
        // File doesn't exist, create it
        [logLine writeToFile:logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

#pragma mark - Keychain Wipe Settings

- (BOOL)_isKeychainWipeEnabledForBundleID:(NSString *)bundleID {
    if (!bundleID.length) return NO;
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = PXKeychainWipeEnabledKey(bundleID);
    if ([defaults objectForKey:key] == nil) {
        // Default OFF (safer): keychain wipe can log you out and may not be restorable for some apps.
        return NO;
    }
    return [defaults boolForKey:key];
}

- (NSArray<NSString *> *)_selectedKeychainGroupsForBundleID:(NSString *)bundleID
                                                     error:(NSError **)error {
    if (!bundleID.length) return @[];
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    id saved = [defaults objectForKey:PXKeychainWipeGroupsKey(bundleID)];
    if ([saved isKindOfClass:[NSArray class]] && [(NSArray *)saved count] > 0) {
        NSMutableArray<NSString *> *out = [NSMutableArray array];
        for (id v in (NSArray *)saved) {
            if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
                [out addObject:(NSString *)v];
            }
        }
        return out;
    }

    // Default selection: ALL groups from entitlements.
    AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
    NSError *entErr = nil;
    NSArray<NSString *> *groups = [reader keychainAccessGroupsForBundleID:bundleID error:&entErr];
    if (groups.count > 0) {
        [defaults setObject:groups forKey:PXKeychainWipeGroupsKey(bundleID)];
        // Keep wipe disabled by default; user can enable explicitly in UI.
        [defaults setBool:NO forKey:PXKeychainWipeEnabledKey(bundleID)];
        [defaults synchronize];
        return groups;
    }

    if (error) {
        *error = entErr ?: [NSError errorWithDomain:@"AppDataCleaner"
                                               code:100
                                           userInfo:@{NSLocalizedDescriptionKey: @"Failed to read keychain-access-groups for this app"}];
    }
    return @[];
}

- (BOOL)_wipeSelectedKeychainForBundleID:(NSString *)bundleID
                                   error:(NSError **)error {
    if (!bundleID.length) return YES;
    if (![self _isKeychainWipeEnabledForBundleID:bundleID]) {
        [self logMessage:@"[AppDataCleaner] Keychain wipe disabled for %@", bundleID];
        return YES;
    }

    NSError *groupsErr = nil;
    NSArray<NSString *> *groups = [self _selectedKeychainGroupsForBundleID:bundleID error:&groupsErr];
    if (groups.count == 0) {
        // User may have selected none, or we couldn't resolve entitlements.
        if (groupsErr) {
            if (error) *error = groupsErr;
            return NO;
        }
        [self logMessage:@"[AppDataCleaner] Keychain wipe enabled but 0 groups selected for %@ (skipping)", bundleID];
        return YES;
    }

    BOOL isSystemApp = [bundleID hasPrefix:@"com.apple."];
    if (isSystemApp) {
        NSUserDefaults *sec = [[NSUserDefaults alloc] initWithSuiteName:@"com.weaponx.securitySettings"];
        BOOL allow = [sec boolForKey:@"allowSystemKeychainWipeEnabled"];
        if (!allow) {
            if (error) {
                *error = [NSError errorWithDomain:@"AppDataCleaner"
                                             code:101
                                         userInfo:@{NSLocalizedDescriptionKey: @"System keychain wipe is disabled (enable in Security tab)"}];
            }
            return NO;
        }
        [self logMessage:@"[AppDataCleaner] System keychain wipe enabled for %@", bundleID];

        // Use in-app bridge to wipe keychain groups (helper resign is unreliable for system apps).
        NSString *safeBundle = [[bundleID componentsSeparatedByCharactersInSet:[[NSCharacterSet alphanumericCharacterSet] invertedSet]] componentsJoinedByString:@"_"];
        NSString *reqPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_request_%@.plist", safeBundle];
        NSString *respPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_response_%@.plist", safeBundle];
        NSString *logPath = [NSString stringWithFormat:@"/tmp/weaponx_keychain_bridge_%@.log", safeBundle];
        NSString *nonce = [[NSUUID UUID] UUIDString];

        [[NSFileManager defaultManager] removeItemAtPath:reqPath error:nil];
        [[NSFileManager defaultManager] removeItemAtPath:respPath error:nil];

        NSDictionary *req = @{
            @"action": @"wipe",
            @"bundleID": bundleID,
            @"groups": groups,
            @"nonce": nonce,
            @"respPath": respPath,
            @"logPath": logPath,
            @"bridgeOnly": @YES,
        };

        [self logMessage:@"[AppDataCleaner] System keychain wipe via bridge: nonce=%@", nonce];
        [self logMessage:@"[AppDataCleaner] System keychain wipe via bridge: request=%@", reqPath];
        [self logMessage:@"[AppDataCleaner] System keychain wipe via bridge: response=%@", respPath];
        [self logMessage:@"[AppDataCleaner] System keychain wipe via bridge: log=%@", logPath];
        if (![req writeToFile:reqPath atomically:YES]) {
            if (error) {
                *error = [NSError errorWithDomain:@"AppDataCleaner" code:105 userInfo:@{NSLocalizedDescriptionKey: @"Failed to write keychain bridge request"}];
            }
            return NO;
        }

        // Notify bridge and launch app
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                            (__bridge CFStringRef)[NSString stringWithFormat:@"com.hydra.weaponx.keychain.req.%@", safeBundle],
                                            NULL, NULL, true);
        Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
        BOOL opened = NO;
        if (wsCls) {
            id ws = [wsCls performSelector:@selector(defaultWorkspace)];
            if (ws && [ws respondsToSelector:@selector(openApplicationWithBundleID:)]) {
                opened = ((BOOL (*)(id, SEL, id))objc_msgSend)(ws, @selector(openApplicationWithBundleID:), bundleID);

                // Immediately bring ProjectX back to foreground (best-effort).
                NSString *selfBundle = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
                if (selfBundle.length) {
                    ((BOOL (*)(id, SEL, id))objc_msgSend)(ws, @selector(openApplicationWithBundleID:), selfBundle);
                }
            }
        }

        NSTimeInterval waitSec = opened ? 30.0 : 6.0;
        NSDictionary *resp = PXWaitForKeychainBridgeResponse(safeBundle, respPath, nonce, waitSec);

        // Kill app after bridge (may be SIGSTOP'd)
        PXKillAppProcessBestEffort(self, bundleID);

        // If it failed, include bridge log snippet for debugging.
        if (![resp isKindOfClass:[NSDictionary class]] || ![resp[@"ok"] respondsToSelector:@selector(boolValue)] || ![resp[@"ok"] boolValue]) {
            NSString *bridgeLog = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
            if (bridgeLog.length) {
                NSString *snippet = bridgeLog;
                if (snippet.length > 600) {
                    snippet = [snippet substringFromIndex:(snippet.length - 600)];
                }
                [self logMessage:@"[AppDataCleaner] System keychain bridge log (tail): %@", snippet];
            }
        }

        if (![resp isKindOfClass:[NSDictionary class]] || ![resp[@"ok"] respondsToSelector:@selector(boolValue)] || ![resp[@"ok"] boolValue]) {
            NSString *msg = [resp[@"error"] isKindOfClass:[NSString class]] ? resp[@"error"] : @"System keychain wipe timed out";
            if (error) {
                *error = [NSError errorWithDomain:@"AppDataCleaner" code:106 userInfo:@{NSLocalizedDescriptionKey: msg}];
            }
            return NO;
        }

        [self logMessage:@"[AppDataCleaner] System keychain wipe succeeded for %@", bundleID];

        [[NSFileManager defaultManager] removeItemAtPath:reqPath error:nil];
        [[NSFileManager defaultManager] removeItemAtPath:respPath error:nil];
        return YES;
    }

    AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
    NSError *entErr = nil;
    NSDictionary *fullEnt = [reader fullEntitlementsForBundleID:bundleID error:&entErr];
    NSString *appIdentifier = nil;
    if ([fullEnt isKindOfClass:[NSDictionary class]]) {
        id v = fullEnt[@"application-identifier"];
        if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
            appIdentifier = (NSString *)v;
        }
    }
    if (!appIdentifier.length) {
        appIdentifier = bundleID;
    }

    CommandRunner *runner = [CommandRunner shared];
    NSString *ldidPath = [runner firstExistingPath:@[
        @"/usr/bin/ldid",
        @"/var/jb/usr/bin/ldid",
        @"/private/preboot/jb/usr/bin/ldid",
        @"/bin/ldid"
    ]];
    if (!ldidPath.length) {
        if (error) {
            *error = [NSError errorWithDomain:@"AppDataCleaner"
                                         code:102
                                     userInfo:@{NSLocalizedDescriptionKey: @"ldid not found (required for keychain wipe)"}];
        }
        return NO;
    }

    NSString *helperPath = [runner firstExistingPath:@[
        @"/Library/WeaponX/backup_helper",
        @"/var/jb/Library/WeaponX/backup_helper",
        @"/private/var/jb/Library/WeaponX/backup_helper"
    ]];
    if (!helperPath.length) {
        if (error) {
            *error = [NSError errorWithDomain:@"AppDataCleaner"
                                         code:103
                                     userInfo:@{NSLocalizedDescriptionKey: @"backup_helper not found (WeaponX not installed?)"}];
        }
        return NO;
    }

    // Create temp dir
    NSString *tmpDir = [NSString stringWithFormat:@"/tmp/keychain_wipe_%d", getpid()];
    [_fileManager createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *workingHelper = [tmpDir stringByAppendingPathComponent:@"backup_helper"];
    NSString *entPath = [tmpDir stringByAppendingPathComponent:@"helper_ent.plist"];

    // Copy helper
    [_fileManager removeItemAtPath:workingHelper error:nil];
    NSError *copyErr = nil;
    if (![_fileManager copyItemAtPath:helperPath toPath:workingHelper error:&copyErr]) {
        if (error) {
            *error = [NSError errorWithDomain:@"AppDataCleaner"
                                         code:104
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to copy backup_helper: %@", copyErr.localizedDescription ?: @"unknown"]}];
        }
        return NO;
    }
    chmod([workingHelper fileSystemRepresentation], 0755);

    // Write entitlements for the helper (scoped to selected groups)
    NSDictionary *helperEnt = @{
        @"platform-application": @YES,
        @"application-identifier": appIdentifier,
        @"com.apple.private.security.no-sandbox": @YES,
        @"com.apple.private.security.no-container": @YES,
        @"com.apple.private.security.container-required": @NO,
        @"com.apple.keystore.access-keychain-keys": @YES,
        @"com.apple.keystore.device": @YES,
        @"keychain-access-groups": groups,
    };
    NSError *plistErr = nil;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:helperEnt
                                                                   format:NSPropertyListXMLFormat_v1_0
                                                                  options:0
                                                                    error:&plistErr];
    if (!plistData.length || plistErr) {
        if (error) {
            *error = plistErr ?: [NSError errorWithDomain:@"AppDataCleaner"
                                                    code:105
                                                userInfo:@{NSLocalizedDescriptionKey: @"Failed to build helper entitlements"}];
        }
        return NO;
    }
    if (![plistData writeToFile:entPath atomically:YES]) {
        if (error) {
            *error = [NSError errorWithDomain:@"AppDataCleaner"
                                         code:106
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to write helper entitlements file"}];
        }
        return NO;
    }

    // Resign
    NSString *signCmd = [NSString stringWithFormat:@"%@ -S%@ %@",
                         PXShellQuote(ldidPath),
                         PXShellQuote(entPath),
                         PXShellQuote(workingHelper)];
    CommandResult *signRes = [runner runAndCapture:signCmd];
    if (signRes.exitCode != 0) {
        if (error) {
            NSString *msg = signRes.stderrString.length ? signRes.stderrString : @"ldid failed";
            *error = [NSError errorWithDomain:@"AppDataCleaner"
                                         code:107
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to resign helper: %@", msg]}];
        }
        return NO;
    }

    NSString *groupsCSV = [groups componentsJoinedByString:@","];
    NSString *wipeCmd = [NSString stringWithFormat:@"%@ --action wipe --groups %@",
                         PXShellQuote(workingHelper),
                         PXShellQuote(groupsCSV)];
    [self logMessage:@"[AppDataCleaner] Keychain wipe via helper for %@ (groups=%lu)", bundleID, (unsigned long)groups.count];
    CommandResult *wipeRes = [runner runAndCapture:wipeCmd];

    NSDictionary *report = @{
        @"bundleID": bundleID,
        @"groups": groups,
        @"exitCode": @(wipeRes.exitCode),
        @"stdout": wipeRes.stdoutString ?: @"",
        @"stderr": wipeRes.stderrString ?: @"",
    };
    [[NSUserDefaults standardUserDefaults] setObject:report forKey:[NSString stringWithFormat:@"DataCleaningKeychainResult_%@", bundleID]];
    [[NSUserDefaults standardUserDefaults] synchronize];

    if (wipeRes.exitCode != 0) {
        if (error) {
            NSString *msg = wipeRes.stderrString.length ? wipeRes.stderrString : @"Keychain wipe failed";
            *error = [NSError errorWithDomain:@"AppDataCleaner"
                                         code:108
                                     userInfo:@{NSLocalizedDescriptionKey: msg}];
        }
        return NO;
    }

    return YES;
}

#pragma mark - Main Public Methods

- (void)clearDataForBundleID:(NSString *)bundleID completion:(void (^)(BOOL, NSError *))completion {
    [self logMessage:@"[AppDataCleaner] === STARTING data clearing for %@ ===", bundleID];
    
    // Use __block to track if completion was called
    __block BOOL completionCalled = NO;
    __block dispatch_semaphore_t completionLock = dispatch_semaphore_create(1);

    // Freeze/unfreeze around destructive wipes to prevent relaunch mid-clean.
    FreezeManager *freezer = [FreezeManager sharedManager];
    __block BOOL wasFrozen = [freezer isApplicationFrozen:bundleID];
    __block BOOL frozeForThisClear = NO;
    
    // Capture self for logging in blocks
    __weak typeof(self) weakSelf = self;

    // Keep ProjectX running even if another app is launched (e.g., system keychain wipe via bridge).
    __block UIBackgroundTaskIdentifier bgTask = UIBackgroundTaskInvalid;
    dispatch_async(dispatch_get_main_queue(), ^{
        bgTask = [[UIApplication sharedApplication] beginBackgroundTaskWithName:@"AppDataCleaner" expirationHandler:^{
            // Best-effort: allow watchdog to handle timeout.
        }];
    });

    // Cancelable watchdog (avoid false timeout after success)
    __block dispatch_source_t watchdogTimer = nil;
    
    // Helper block to safely call completion only once
    void (^safeCompletion)(BOOL, NSError *) = ^(BOOL success, NSError *error) {
        dispatch_semaphore_wait(completionLock, DISPATCH_TIME_FOREVER);
        if (!completionCalled) {
            completionCalled = YES;
            dispatch_semaphore_signal(completionLock);

            // Unfreeze only if we froze it in this operation.
            if (frozeForThisClear) {
                @try {
                    [freezer unfreezeApplication:bundleID];
                } @catch (__unused NSException *e) {
                }
            }

            if (watchdogTimer) {
                dispatch_source_cancel(watchdogTimer);
                watchdogTimer = nil;
            }

            if (bgTask != UIBackgroundTaskInvalid) {
                UIBackgroundTaskIdentifier taskToEnd = bgTask;
                bgTask = UIBackgroundTaskInvalid;
                dispatch_async(dispatch_get_main_queue(), ^{
                    [[UIApplication sharedApplication] endBackgroundTask:taskToEnd];
                });
            }

            [weakSelf logMessage:@"[AppDataCleaner] Calling completion handler (success=%d)", success];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) {
                    completion(success, error);
                }
            });
        } else {
            dispatch_semaphore_signal(completionLock);
        }
    };

    BOOL deepClean = [self _deepCleanEnabled];
    BOOL isSystemApp = [bundleID hasPrefix:@"com.apple."];
    // Deep Clean and system apps can legitimately take a long time.
    // Avoid failing early while still making progress.
    int timeoutSec = (deepClean || isSystemApp) ? (30 * 60) : 120;

    // Run watchdog on a global queue so it isn't delayed by UI activity.
    watchdogTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    dispatch_source_set_timer(watchdogTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeoutSec * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(watchdogTimer, ^{
        dispatch_semaphore_wait(completionLock, DISPATCH_TIME_FOREVER);
        BOOL alreadyCompleted = completionCalled;
        dispatch_semaphore_signal(completionLock);
        if (alreadyCompleted) {
            return;
        }
        [weakSelf logMessage:@"[AppDataCleaner] WATCHDOG: %d second timeout reached", timeoutSec];
        NSError *timeoutError = [NSError errorWithDomain:@"AppDataCleaner"
                                                   code:-100
                                               userInfo:@{NSLocalizedDescriptionKey: @"Clear Data timed out"}];
        safeCompletion(NO, timeoutError);
    });
    dispatch_resume(watchdogTimer);
    
    // Dispatch the cleaning process to background queue
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        @autoreleasepool {
            __strong typeof(weakSelf) strongSelf = weakSelf;
            [strongSelf logMessage:@"[AppDataCleaner] Background cleaning started for %@", bundleID];
            
            @try {
                 // Step 0: Force Kill Application to release file locks
                 [strongSelf logMessage:@"[AppDataCleaner] Step 0: Kill application..."];

                [strongSelf logMessage:@"[AppDataCleaner] Deep Clean (verify scan) = %@", [strongSelf _deepCleanEnabled] ? @"ON" : @"OFF"];
                
                // Kill by executable name (no shell) to release file locks.
                PXKillAppProcessBestEffort(strongSelf, bundleID);

                [NSThread sleepForTimeInterval:0.5]; // Wait for process to die

                 // Safari: also stop WebKit helper processes to fully release cookie/session DBs.
                 if ([bundleID isEqualToString:@"com.apple.mobilesafari"]) {
                     [strongSelf logMessage:@"[AppDataCleaner] MobileSafari: stopping WebKit/Safari helper processes..."];
                     PXStopSafariDaemonsBestEffort(strongSelf);
                 }
                 
                 // Step 1: Clear keychain FIRST (most important for login data)
                 [strongSelf logMessage:@"[AppDataCleaner] Step 1: Clearing keychain (selected groups)..."];
                NSError *keychainError1 = nil;
                BOOL keychainOK1 = [strongSelf _wipeSelectedKeychainForBundleID:bundleID error:&keychainError1];
                
                // Step 2: Clear URL credentials (session tokens)
                [strongSelf logMessage:@"[AppDataCleaner] Step 2: Clearing URL credentials..."];
                [strongSelf clearURLCredentialsForBundleID:bundleID];
                
                // Step 3: Clear app state data (login sessions)
                [strongSelf logMessage:@"[AppDataCleaner] Step 3: Clearing app state data..."];
                [strongSelf _internalClearAppStateData:bundleID];

                 // Freeze now (after any in-app keychain bridge launch) to prevent relaunch mid-wipe.
                 if (!wasFrozen) {
                     [strongSelf logMessage:@"[AppDataCleaner] Freezing app launch to prevent relaunch during wipe..."];
                     @try {
                         [freezer freezeApplication:bundleID];
                     } @catch (__unused NSException *e) {
                     }
                     frozeForThisClear = [freezer isApplicationFrozen:bundleID];
                 }
                 
                 // Step 4: Use completeAppDataWipe for comprehensive data wiping
                 [strongSelf logMessage:@"[AppDataCleaner] Step 4: Running completeAppDataWipe..."];
                 [strongSelf completeAppDataWipe:bundleID];
                
                // Step 5: Clear HTTP cookie storage in memory  
                [strongSelf logMessage:@"[AppDataCleaner] Step 5: Clearing HTTP cookies from memory..."];
                NSHTTPCookieStorage *cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                NSArray *allCookies = [[cookieStorage cookies] copy];
                for (NSHTTPCookie *cookie in allCookies) {
                    [cookieStorage deleteCookie:cookie];
                }
                [strongSelf logMessage:@"[AppDataCleaner] Cleared %lu cookies from memory", (unsigned long)allCookies.count];
                
                // Step 6: Clear keychain AGAIN to catch any recreated items
                [strongSelf logMessage:@"[AppDataCleaner] Step 6: Final keychain cleanup (selected groups)..."];
                NSError *keychainError2 = nil;
                BOOL keychainOK2 = YES;
                // System keychain wipe requires launching the app; do it once per run to avoid long UX.
                if ([bundleID hasPrefix:@"com.apple."]) {
                    [strongSelf logMessage:@"[AppDataCleaner] Skipping second keychain wipe for system app %@", bundleID];
                } else {
                    keychainOK2 = [strongSelf _wipeSelectedKeychainForBundleID:bundleID error:&keychainError2];
                }
                
                // Step 7: Sync filesystem
                [strongSelf logMessage:@"[AppDataCleaner] Step 7: Syncing filesystem..."];
                sync();
                
                [strongSelf logMessage:@"[AppDataCleaner] === COMPLETED data clearing for %@ ===", bundleID];
                if (!keychainOK1 || !keychainOK2) {
                    NSError *err = keychainError2 ?: keychainError1;
                    safeCompletion(NO, err ?: [NSError errorWithDomain:@"AppDataCleaner"
                                                                 code:-2
                                                             userInfo:@{NSLocalizedDescriptionKey: @"Keychain wipe failed"}]);
                } else {
                    safeCompletion(YES, nil);
                }
                
            } @catch (NSException *exception) {
                [strongSelf logMessage:@"[AppDataCleaner] EXCEPTION: %@", exception];
                safeCompletion(NO, [NSError errorWithDomain:@"AppDataCleaner" 
                                                      code:-1 
                                                  userInfo:@{NSLocalizedDescriptionKey: exception.reason ?: @"Unknown error"}]);
            }
        }
    });
    
    [self logMessage:@"[AppDataCleaner] clearDataForBundleID returned immediately"];
}

#pragma mark - Improved Rootless-Compatible App Data Wiping

- (void)completeAppDataWipe:(NSString *)bundleID {
    [self logMessage:@"[AppDataCleaner] Starting complete wipe for %@", bundleID];
    
    // --- Optimized: Cache directory listings for this cleaning pass ---
    NSArray *cachedDataDirs = [self listDirectoriesInPath:@"/var/mobile/Containers/Data/Application"];
    NSArray *cachedRootlessDataDirs = [self listDirectoriesInPath:@"/containers/Data/Application"];
    NSArray *cachedBundleDirs = [self listDirectoriesInPath:@"/var/containers/Bundle/Application"];
    NSArray *cachedRootlessBundleDirs = [self listDirectoriesInPath:@"/containers/Bundle/Application"];
    // App groups are resolved from entitlements + resolver; no need to list all group dirs here.

    [self logMessage:@"[AppDataCleaner] Found %lu data containers, %lu rootless containers", 
          (unsigned long)cachedDataDirs.count, (unsigned long)cachedRootlessDataDirs.count];

    // Optimized lookups using cached listings
    NSString *dataUUID = [self optimized_findDataContainerUUID:bundleID inDirectories:cachedDataDirs];
    NSString *rootlessDataUUID = [self optimized_findRootlessDataContainerUUID:bundleID inDirectories:cachedRootlessDataDirs];
    // Resolve app groups from entitlements (avoid overly broad heuristics, especially for com.apple.*).
    NSArray *groupUUIDs = [self _resolvedAppGroupUUIDsFromEntitlements:bundleID rootless:NO];
    NSArray *rootlessGroupUUIDs = [self _resolvedAppGroupUUIDsFromEntitlements:bundleID rootless:YES];
    NSString *bundleUUID = [self optimized_findBundleContainerUUID:bundleID inDirectories:cachedBundleDirs rootlessDirs:cachedRootlessBundleDirs];

    // Find extension containers (pass cached dirs for speed)
    NSArray *extensionContainers = [self optimized_findExtensionContainers:bundleID dataDirs:cachedDataDirs rootlessDataDirs:cachedRootlessDataDirs bundleDirs:cachedBundleDirs rootlessBundleDirs:cachedRootlessBundleDirs];
    
    [self logMessage:@"[AppDataCleaner] Found UUIDs - Bundle: %@, Data: %@, RootlessData: %@, Groups=%lu RootlessGroups=%lu", 
          bundleUUID ?: @"nil", dataUUID ?: @"nil", rootlessDataUUID ?: @"nil", (unsigned long)groupUUIDs.count, (unsigned long)rootlessGroupUUIDs.count];

     BOOL deep = [self _deepCleanEnabled];
     BOOL isSystemApp = [bundleID hasPrefix:@"com.apple."];
     int rmTimeout = (deep || isSystemApp) ? (15 * 60) : (5 * 60);
     int findTimeout = (deep || isSystemApp) ? (20 * 60) : (8 * 60);
    
    // Clear data container
    if (dataUUID) {
        NSString *dataContainerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", dataUUID];
        [self logMessage:@"[AppDataCleaner] Wiping data container: %@", dataContainerPath];
        
        // DEBUG: Count files before
        NSError *err = nil;
        NSArray *beforeContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[dataContainerPath stringByAppendingPathComponent:@"Library"] error:&err];
        [self logMessage:@"[AppDataCleaner] DEBUG: Library has %lu items before wipe", (unsigned long)beforeContents.count];
        
        // FAST wipe: remove top-level directories entirely (much faster than chmod -R + rm contents).
        // Container metadata plists at root are preserved.
        NSArray *subDirs = @[@"Documents", @"Library", @"tmp", @"StoreKit", @"SystemData"]; 
        for (NSString *dir in subDirs) {
            NSString *fullPath = [dataContainerPath stringByAppendingPathComponent:dir];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@' 2>/dev/null || true", fullPath] timeoutSec:rmTimeout];
        }
        // Recreate minimal structure to avoid app/iOS assumptions.
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"mkdir -p '%@/Documents' '%@/Library/Caches' '%@/Library/Preferences' '%@/tmp' 2>/dev/null || true",
                                      dataContainerPath, dataContainerPath, dataContainerPath, dataContainerPath] timeoutSec:60];
        
        // Also wipe any hidden directories and files at root level
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -mindepth 1 -maxdepth 1 -name '.*' ! -name '.com.apple*' -exec rm -rf {} \\; 2>/dev/null || true", dataContainerPath] timeoutSec:findTimeout];
        
        // DEBUG: Count files after
        NSArray *afterContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[dataContainerPath stringByAppendingPathComponent:@"Library"] error:nil];
        [self logMessage:@"[AppDataCleaner] DEBUG: Library has %lu items AFTER wipe", (unsigned long)afterContents.count];
        
        // DEBUG: List remaining items
        if (afterContents.count > 0) {
            [self logMessage:@"[AppDataCleaner] DEBUG: Remaining items: %@", [afterContents componentsJoinedByString:@", "]];
        }
        
        [self logMessage:@"[AppDataCleaner] Data container wiped successfully"];
    }
    
    // Clear rootless data container using the same approach
    if (rootlessDataUUID) {
        NSString *rootlessDataPath = [NSString stringWithFormat:@"/containers/Data/Application/%@", rootlessDataUUID];
        NSLog(@"[AppDataCleaner] Wiping rootless data container: %@", rootlessDataPath);
        [self completelyWipeContainer:rootlessDataPath];
    } else {
        NSLog(@"[AppDataCleaner] Directory does not exist: /containers/Data/Application");
    }
    
    // Clear App Store receipt
    [self clearAppReceiptData:bundleID withBundleUUID:bundleUUID];
    
    // Process rootless bundle container
    NSString *rootlessBundlePath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@", bundleUUID];
    if ([[NSFileManager defaultManager] fileExistsAtPath:rootlessBundlePath]) {
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'/*", rootlessBundlePath] timeoutSec:rmTimeout];
    }
    
    // Process group containers - DIRECT wipe using fast rm -rf
    [self logMessage:@"[AppDataCleaner] Wiping %lu app group containers directly", (unsigned long)groupUUIDs.count];
    for (NSString *groupUUID in groupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", groupUUID];
        [self logMessage:@"[AppDataCleaner] Fast wiping group: %@", groupUUID];
        // Wipe everything except container metadata (critical for stable mapping).
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -mindepth 1 -maxdepth 1 -not -name '.com.apple.mobile_container_manager.metadata.plist' -not -name '.com.apple.containermanagerd.metadata.plist' -exec rm -rf {} + 2>/dev/null || true",
                                      groupPath] timeoutSec:findTimeout];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"mkdir -p '%@/Documents' '%@/Library/Caches' '%@/Library/Preferences' '%@/tmp' 2>/dev/null || true",
                                      groupPath, groupPath, groupPath, groupPath] timeoutSec:60];
    }
    
    // Process rootless group containers
    for (NSString *groupUUID in rootlessGroupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/containers/Shared/AppGroup/%@", groupUUID];
        [self logMessage:@"[AppDataCleaner] Fast wiping rootless group: %@", groupUUID];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -mindepth 1 -maxdepth 1 -not -name '.com.apple.mobile_container_manager.metadata.plist' -not -name '.com.apple.containermanagerd.metadata.plist' -exec rm -rf {} + 2>/dev/null || true",
                                      groupPath] timeoutSec:findTimeout];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"mkdir -p '%@/Documents' '%@/Library/Caches' '%@/Library/Preferences' '%@/tmp' 2>/dev/null || true",
                                      groupPath, groupPath, groupPath, groupPath] timeoutSec:60];
    }
    
    [self logMessage:@"[AppDataCleaner] Group containers wiped successfully"];

    // Extra cleanup for MobileMail: email/account display is primarily system-scoped (Accounts3 + /var/mobile/Library/Mail).
    if ([bundleID isEqualToString:@"com.apple.mobilemail"]) {
        [self logMessage:@"[AppDataCleaner] MobileMail: wiping /var/mobile/Library/Mail and mail prefs"]; 

        // Stop mail-related daemons and wait for exit to avoid maild SIGABRT on detached DB.
        PXStopMailDaemonsBestEffort(self);
        if (!PXWaitForProcessExit(self, @"maild", 5.0)) {
            [self logMessage:@"[AppDataCleaner] MobileMail: maild still running; forcing kill"]; 
            PXKillallByName(@"maild", SIGKILL);
            (void)PXWaitForProcessExit(self, @"maild", 2.0);
        }
        (void)PXWaitForProcessExit(self, @"Mail", 2.0);

        // Avoid detaching an open sqlite DB: quarantine the Mail directory via rename.
        // If any lingering maild instance still holds files open, rename is safe; rm -rf can trigger SIGABRT later.
        NSString *mailPath = @"/var/mobile/Library/Mail";
        NSString *trashPath = [NSString stringWithFormat:@"/var/mobile/Library/Mail.WeaponXTrash.%@", PXTimestampSuffix()];
        if ([_fileManager fileExistsAtPath:mailPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"mv '%@' '%@' 2>/dev/null || true", mailPath, trashPath]];
        }
        [self runCommandWithPrivileges:@"mkdir -p '/var/mobile/Library/Mail' 2>/dev/null || true"]; 
        [self runCommandWithPrivileges:@"chown -R mobile:mobile '/var/mobile/Library/Mail' 2>/dev/null || true"]; 

        [self runCommandWithPrivileges:@"rm -f '/var/mobile/Library/Preferences/com.apple.mail.plist' 2>/dev/null || true"]; 
        [self runCommandWithPrivileges:@"rm -f '/var/mobile/Library/Preferences/com.apple.mobilemail.plist' 2>/dev/null || true"]; 
        [self runCommandWithPrivileges:@"rm -f '/private/var/mobile/Library/Preferences/com.apple.mail.plist' 2>/dev/null || true"]; 
        [self runCommandWithPrivileges:@"rm -f '/private/var/mobile/Library/Preferences/com.apple.mobilemail.plist' 2>/dev/null || true"]; 

        // Keep maild stopped while accounts cleanup runs.
        PXStopMailDaemonsBestEffort(self);

        // Best-effort remove Mail account rows from Accounts3 (schema varies by iOS; keep scoped to mail-type identifiers).
        NSString *accountsDB = @"/var/mobile/Library/Accounts/Accounts3.sqlite";
        if ([_fileManager fileExistsAtPath:accountsDB]) {
            // Stop accountsd before touching DB (avoid "database is locked").
            // Use TERM first to reduce crash reports.
            PXKillallTermThenKill(@"accountsd", 0.15);
            [NSThread sleepForTimeInterval:0.2];

            // Use one RW connection for before/delete/after to avoid transient CANTOPEN.
            sqlite3 *db = NULL;
            int rc = sqlite3_open_v2(accountsDB.UTF8String, &db, SQLITE_OPEN_READWRITE, NULL);
            if (rc != SQLITE_OK || !db) {
                NSString *msg = db ? [NSString stringWithUTF8String:sqlite3_errmsg(db)] : @"open failed";
                [self logMessage:@"[AppDataCleaner] MobileMail: Accounts3 open failed rc=%d %@", rc, msg ?: @""];
                if (db) sqlite3_close(db);
            } else {
                sqlite3_busy_timeout(db, 3000);

                NSString *beforeCount = PXSQLiteScalar(db, @"SELECT count(*) FROM ZACCOUNT;");
                [self logMessage:@"[AppDataCleaner] MobileMail: Accounts3 ZACCOUNT count before=%@", beforeCount ?: @"(nil)"];

                // Identify mail-related account types.
                NSString *typeCount = PXSQLiteScalar(db,
                    @"SELECT count(*) FROM ZACCOUNTTYPE WHERE "
                    "ZIDENTIFIER LIKE '%mail%' OR ZIDENTIFIER LIKE '%imap%' OR ZIDENTIFIER LIKE '%smtp%' OR ZIDENTIFIER LIKE '%exchange%' OR "
                    "ZIDENTIFIER LIKE '%google%' OR ZIDENTIFIER LIKE '%gmail%';");
                [self logMessage:@"[AppDataCleaner] MobileMail: mail-ish/google-ish account types=%@", typeCount ?: @"(nil)"];

                NSString *errMsg = nil;
                PXSQLiteExec(db, @"PRAGMA busy_timeout=3000;", NULL);
                PXSQLiteExec(db, @"BEGIN IMMEDIATE;", &errMsg);
                if (errMsg.length) {
                    [self logMessage:@"[AppDataCleaner] MobileMail: BEGIN IMMEDIATE failed %@", errMsg];
                    errMsg = nil;
                }

                // Delete matching accounts and best-effort related rows.
                // We intentionally ignore errors for tables that may not exist on some iOS versions.
                // For Gmail accounts configured in Mail, the underlying account type is often Google-based
                // (e.g. com.apple.account.Google) and may not match mail/imap/smtp identifiers.
                NSString *deleteAccounts =
                    @"DELETE FROM ZACCOUNT WHERE ZACCOUNTTYPE IN (SELECT Z_PK FROM ZACCOUNTTYPE WHERE "
                    "ZIDENTIFIER LIKE '%mail%' OR ZIDENTIFIER LIKE '%imap%' OR ZIDENTIFIER LIKE '%smtp%' OR ZIDENTIFIER LIKE '%exchange%' OR "
                    "ZIDENTIFIER LIKE '%google%' OR ZIDENTIFIER LIKE '%gmail%');";
                BOOL delOK = PXSQLiteExec(db, deleteAccounts, &errMsg);
                int changes = sqlite3_changes(db);
                [self logMessage:@"[AppDataCleaner] MobileMail: ZACCOUNT delete ok=%d changes=%d %@", delOK, changes, errMsg.length ? errMsg : @""];
                errMsg = nil;

                // Companion tables are schema-dependent. Try deletes if they exist; ignore failures.
                // (We do not assume these tables exist on all iOS versions.)
                PXSQLiteExec(db, @"DELETE FROM ZACCOUNTPROPERTY WHERE ZOWNER IN (SELECT Z_PK FROM ZACCOUNT);", NULL);
                PXSQLiteExec(db, @"DELETE FROM ZCREDENTIALITEM WHERE ZOWNER IN (SELECT Z_PK FROM ZACCOUNT);", NULL);

                PXSQLiteExec(db, @"COMMIT;", &errMsg);
                if (errMsg.length) {
                    [self logMessage:@"[AppDataCleaner] MobileMail: COMMIT failed %@", errMsg];
                    errMsg = nil;
                }
                PXSQLiteExec(db, @"PRAGMA wal_checkpoint(TRUNCATE);", NULL);

                NSString *afterCount = PXSQLiteScalar(db, @"SELECT count(*) FROM ZACCOUNT;");
                [self logMessage:@"[AppDataCleaner] MobileMail: Accounts3 ZACCOUNT count after=%@", afterCount ?: @"(nil)"];

                // If accounts remain, log a few account type identifiers for debugging.
                NSString *sample = nil;
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(db, "SELECT ZIDENTIFIER FROM ZACCOUNTTYPE LIMIT 12;", -1, &st, NULL) == SQLITE_OK && st) {
                    NSMutableArray *ids = [NSMutableArray array];
                    while (sqlite3_step(st) == SQLITE_ROW) {
                        const unsigned char *txt = sqlite3_column_text(st, 0);
                        if (txt) [ids addObject:[NSString stringWithUTF8String:(const char *)txt]];
                    }
                    sqlite3_finalize(st);
                    sample = [ids componentsJoinedByString:@", "];
                } else if (st) {
                    sqlite3_finalize(st);
                }
                if (sample.length) {
                    [self logMessage:@"[AppDataCleaner] MobileMail: ZACCOUNTTYPE sample=%@", sample];
                }

                sqlite3_close(db);
            }
        }

        // Restart accounts daemons (best-effort) so UI reflects removal.
        PXKillallByName(@"accountsd", SIGTERM);
        PXKillallByName(@"Mail", SIGTERM);
        [NSThread sleepForTimeInterval:0.15];
        PXKillallByName(@"accountsd", SIGKILL);
        PXKillallByName(@"Mail", SIGKILL);

        // Do not auto-restart maild; let launchd bring it back when needed.

        // IMPORTANT: Do not delete the quarantined old store in the same run.
        // maild can still have open sqlite connections or scheduled vacuum activities; deleting can cause SIGABRT
        // (detached database IO error). Leaving it avoids crashes; user can delete later (e.g. after reboot).
        if ([trashPath hasPrefix:@"/var/mobile/Library/Mail.WeaponXTrash."]) {
            [self logMessage:@"[AppDataCleaner] MobileMail: kept old store at %@ (safe).", trashPath];
        }
    }
    
    // Process extension containers - simplified
    if (extensionContainers.count > 0) {
        [self logMessage:@"[AppDataCleaner] Wiping %lu extension containers", (unsigned long)extensionContainers.count];
        for (NSDictionary *extInfo in extensionContainers) {
            NSString *extDataUUID = extInfo[@"dataUUID"];
            if (extDataUUID) {
                NSString *containerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", extDataUUID];
                [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'/* 2>/dev/null || true", containerPath]];
            }
        }
        [self logMessage:@"[AppDataCleaner] Extension containers wiped"];
    }
    
    // Clear preferences and cookies only (SAFE paths, no SpringBoard state!)
    [self logMessage:@"[AppDataCleaner] Clearing preferences and cookies"];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '/var/mobile/Library/Preferences/%@.plist' 2>/dev/null || true", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '/var/mobile/Library/Caches/%@' 2>/dev/null || true", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '/var/mobile/Library/Cookies/%@.binarycookies' 2>/dev/null || true", bundleID]];
    
    // NOTE: Removed SpringBoard/ApplicationState deletion - it causes RESPRING!
    // NOTE: Removed PluginKit clearing - it uses slow findPathsMatchingPattern
    
    // Keychain wipe is handled by clearDataForBundleID using selected groups.
    // Avoid running legacy heuristic wipes here.
    
    // Skip RootHide var data clearing - uses slow findPathsMatchingPattern
    [self logMessage:@"[AppDataCleaner] Skipping RootHide cleaning (optimization)"];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Caches/%@", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Preferences/%@.plist", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/root/Library/Preferences/%@.plist", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /private/var/mobile/Library/Preferences/%@.plist", bundleID]];

    // Clear iCloud-related data
    [self logMessage:@"[AppDataCleaner] Clearing iCloud-related data"]; 
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    [self clearICloudData:bundleID];
    [self logMessage:@"[AppDataCleaner] iCloud cleanup took %.2fs", CFAbsoluteTimeGetCurrent() - t0];
    
    // Clear app state data - SKIP second call to avoid respring
    // [self _internalClearAppStateData:bundleID];
    
    // URL credentials are cleared by clearDataForBundleID.
    
    // Clear encrypted data 
    [self logMessage:@"[AppDataCleaner] DEBUG: Clearing encrypted data..."];
    [self _internalClearEncryptedData:bundleID];
    
    // If we have a data container, verify HTTPStorages are wiped
    if (dataUUID) {
        NSString *authPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/Library/HTTPStorages", dataUUID];
        [self logMessage:@"[AppDataCleaner] DEBUG: Wiping HTTPStorages at %@", authPath];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'/* 2>/dev/null || true", authPath]];
    }
    
    // Clear Spotlight data
    [self logMessage:@"[AppDataCleaner] DEBUG: Clearing Spotlight indexes..."];
    [self clearSpotlightIndexes:bundleID];
    
    // Skip slow media/health/safari clearing for now
    [self logMessage:@"[AppDataCleaner] DEBUG: Skipping media/health/safari (optimization)"];
    // [self clearMediaData:bundleID];
    // [self clearHealthData:bundleID];

    // Safari is special: it uses system-scoped stores under /var/mobile/Library.
    // Without clearing those, sessions/cookies can persist even after wiping the app container.
    if ([bundleID isEqualToString:@"com.apple.mobilesafari"]) {
        [self _wipeMobileSafariSystemStores];
    }
    
    // Clean SiriAnalytics
    [self logMessage:@"[AppDataCleaner] DEBUG: Cleaning Siri analytics..."];
    [self cleanSiriAnalyticsDatabase:bundleID];
    
    // Skip these - they modify system state and can cause respring:
    // [self cleanIconStatePlist:bundleID];
    // [self cleanLaunchServicesDatabase:bundleID];
    
    // SAFE to run now (modified to avoid respring)
    [self refreshSystemServices];
    
    [self logMessage:@"[AppDataCleaner] Skipped unsafe system state modifications"];
    
    // NOTE: Universal keychain wipe removed (too broad / can delete unrelated items).

    // === FINAL SWEEP FOR 100% COVERAGE ===
    NSLog(@"[AppDataCleaner] Starting final sweep for any remaining traces of %@", bundleID);
    NSMutableArray *finalSweepPaths = [NSMutableArray array];
    if (dataUUID) {
        [finalSweepPaths addObject:[NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", dataUUID]];
    }
    if (rootlessDataUUID) {
        [finalSweepPaths addObject:[NSString stringWithFormat:@"/containers/Data/Application/%@", rootlessDataUUID]];
    }
    for (NSString *groupUUID in groupUUIDs) {
        NSString *path = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", groupUUID];
        NSLog(@"[AppDataCleaner][Detect] App Group Container: %@", path);
        [finalSweepPaths addObject:path];
    }
    for (NSString *groupUUID in rootlessGroupUUIDs) {
        NSString *path = [NSString stringWithFormat:@"/containers/Shared/AppGroup/%@", groupUUID];
        NSLog(@"[AppDataCleaner][Detect] Rootless App Group Container: %@", path);
        [finalSweepPaths addObject:path];
    }
    for (NSDictionary *extInfo in extensionContainers) {
        NSString *extDataUUID = extInfo[@"dataUUID"];
        NSString *path = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", extDataUUID];
        NSLog(@"[AppDataCleaner][Detect] Extension Data Container: %@", path);
        [finalSweepPaths addObject:path];
    }
    // Recursively remove all non-Apple files from each container (parallelized)
    dispatch_apply(finalSweepPaths.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        NSString *containerPath = finalSweepPaths[i];
        NSLog(@"[AppDataCleaner][Sweep] Starting sweep for container: %@", containerPath);
        [self finalSweepForContainer:containerPath];
        NSLog(@"[AppDataCleaner][Sweep] Finished sweep for container: %@", containerPath);
    });
    // Sweep for crash logs and system logs
    [self removeCrashLogsForBundleID:bundleID];
    NSLog(@"[AppDataCleaner] Completed wipe for %@", bundleID);
}

// FINAL SWEEP: Recursively remove all files/folders except .com.apple* or system files
- (void)finalSweepForContainer:(NSString *)containerPath {
    if (![containerPath isKindOfClass:[NSString class]] || containerPath.length == 0) return;
    if (![[NSFileManager defaultManager] fileExistsAtPath:containerPath]) return;

    // Fast final sweep: avoid per-file chmod/chflags/rm.
    // Preserve all .com.apple* entries to keep container metadata stable.
    BOOL deep = [self _deepCleanEnabled];
    int timeout = deep ? (20 * 60) : (8 * 60);

    NSString *quoted = PXShellQuote(containerPath);
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"chflags -R nouchg,noschg,nohidden %@ 2>/dev/null || true", quoted] timeoutSec:timeout];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"chmod -R 0777 %@ 2>/dev/null || true", quoted] timeoutSec:timeout];

    // One traversal. -prune skips any .com.apple* anywhere in tree.
    NSString *wipe = [NSString stringWithFormat:@"find %@ -mindepth 1 -path '*/.com.apple*' -prune -o -exec rm -rf {} + 2>/dev/null || true", quoted];
    [self runCommandWithPrivileges:wipe timeoutSec:timeout];
}

// Remove crash logs and system logs for this bundleID
- (void)removeCrashLogsForBundleID:(NSString *)bundleID {
    NSArray *crashLogDirs = @[
        @"/var/mobile/Library/Logs/CrashReporter",
        @"/private/var/logs/CrashReporter"
    ];
    for (NSString *dir in crashLogDirs) {
        NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *file in contents) {
            if ([file containsString:bundleID]) {
                NSString *fullPath = [dir stringByAppendingPathComponent:file];
                [self fixPermissionsAndRemovePath:fullPath];
                if ([[NSFileManager defaultManager] fileExistsAtPath:fullPath]) {
                    NSLog(@"[AppDataCleaner][CrashLogSweep] Could not delete crash log: %@", fullPath);
                }
            }
        }
    }
}


// NEW: Method to clear app store receipt data
- (void)clearAppReceiptData:(NSString *)bundleID withBundleUUID:(NSString *)bundleUUID {
    if (!bundleUUID) {
        NSLog(@"[AppDataCleaner] No bundle UUID found for cleaning app receipt");
        return;
    }
    
    NSLog(@"[AppDataCleaner] Clearing App Store receipt for %@", bundleID);
    
    // First find the app name from the bundle directory
    NSString *bundlePath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@", bundleUUID];
    NSArray *bundleContents = [self listDirectoriesInPath:bundlePath];
    
    for (NSString *item in bundleContents) {
        if ([item hasSuffix:@".app"]) {
            // Found the app bundle, now target the _MASReceipt directory
            NSString *receiptPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@/%@/_MASReceipt", 
                                   bundleUUID, item];
            
            NSLog(@"[AppDataCleaner] Wiping app receipt at: %@", receiptPath);
            
            // Use a more aggressive approach due to potential permission issues
            [self fixPermissionsAndRemovePath:receiptPath];
            
            // Create an empty directory to avoid errors 
            [_fileManager createDirectoryAtPath:receiptPath
                   withIntermediateDirectories:YES
                                    attributes:nil
                                         error:nil];
            break;
        }
    }
    
    // Also check rootless path
    NSString *rootlessBundlePath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@", bundleUUID];
    NSArray *rootlessBundleContents = [self listDirectoriesInPath:rootlessBundlePath];
    
    for (NSString *item in rootlessBundleContents) {
        if ([item hasSuffix:@".app"]) {
            NSString *receiptPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@/%@/_MASReceipt", 
                                   bundleUUID, item];
            
            NSLog(@"[AppDataCleaner] Wiping rootless app receipt at: %@", receiptPath);
            [self fixPermissionsAndRemovePath:receiptPath];
            
            // Create an empty directory to avoid errors
            [_fileManager createDirectoryAtPath:receiptPath
                   withIntermediateDirectories:YES
                                    attributes:nil
                                         error:nil];
            break;
        }
    }
}

// NEW: Enhanced method to clear app group containers with better subfolder handling
- (void)clearAppGroupContainers:(NSString *)bundleID withGroupUUIDs:(NSArray *)groupUUIDs isRootless:(BOOL)isRootless {
    NSString *basePath = isRootless ? 
        @"/containers/Shared/AppGroup/%@" : 
        @"/var/mobile/Containers/Shared/AppGroup/%@";
    
    for (NSString *groupUUID in groupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:basePath, groupUUID];
        NSLog(@"[AppDataCleaner] Completely wiping app group at: %@", groupPath);
        
        // Use forceful command to clear EVERYTHING inside except Apple metadata
        NSString *forceCommand = [NSString stringWithFormat:@"find '%@' -not -path \"*/.com.apple*\" -not -path \"%@/.com.apple*\" -delete 2>/dev/null || true", groupPath, groupPath];
        [self runCommandWithPrivileges:forceCommand];
        
        // Rebuild essential directory structure
        NSArray *essentialDirs = @[
            @"Library/Caches",
            @"Library/Preferences",
            @"Library/Application Support",
            @"Documents"
        ];
        
        for (NSString *dir in essentialDirs) {
            NSString *dirPath = [NSString stringWithFormat:@"%@/%@", groupPath, dir];
            [_fileManager createDirectoryAtPath:dirPath withIntermediateDirectories:YES attributes:nil error:nil];
        }
    }
}

// Helper for app group cleaning with default rootless setting
- (void)clearAppGroupContainers:(NSString *)bundleID withGroupUUIDs:(NSArray *)groupUUIDs {
    [self clearAppGroupContainers:bundleID withGroupUUIDs:groupUUIDs isRootless:NO];
}

// NEW: Helper method to fix permissions and forcefully remove paths
- (void)fixPermissionsAndRemovePath:(NSString *)path {
    if (![_fileManager fileExistsAtPath:path]) {
        return;
    }
    
    NSLog(@"[AppDataCleaner] Fixing permissions before removal: %@", path);
    
    // Try to fix permissions with chmod and remove flags with chflags
    NSString *chmodCommand = [NSString stringWithFormat:@"chmod -R 0777 '%@' 2>/dev/null || true", path];
    [self runCommandWithPrivileges:chmodCommand];
    
    NSString *chflagsCommand = [NSString stringWithFormat:@"chflags -R nouchg,noschg,nohidden '%@' 2>/dev/null || true", path];
    [self runCommandWithPrivileges:chflagsCommand];
    
    // Try standard file manager removal
    NSError *error;
    BOOL success = [_fileManager removeItemAtPath:path error:&error];
    
    if (!success) {
        NSLog(@"[AppDataCleaner] Standard removal failed: %@", error.localizedDescription);
        
        // Try more aggressive removal with rm -rf
        NSString *rmCommand = [NSString stringWithFormat:@"rm -rf '%@' 2>/dev/null", path];
        [self runCommandWithPrivileges:rmCommand];
    }
}

// Add the Spotlight indexes clearing method
- (void)clearSpotlightIndexes:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing Spotlight indexes for %@", bundleID);
    
    // Use reflection to check if CoreSpotlight is available
    Class csSearchableIndexClass = NSClassFromString(@"CSSearchableIndex");
    if (csSearchableIndexClass) {
        // Use performSelector to avoid direct link dependency
        id defaultIndex = [csSearchableIndexClass performSelector:@selector(defaultSearchableIndex)];
        if (defaultIndex && [defaultIndex respondsToSelector:@selector(deleteSearchableItemsWithDomainIdentifiers:completionHandler:)]) {
            NSLog(@"[AppDataCleaner] Using CSSearchableIndex to clear Spotlight data");
            
            // Create dispatch group to wait for completion
            dispatch_group_t group = dispatch_group_create();
            dispatch_group_enter(group);
            
            // Delete searchable items
            [defaultIndex performSelector:@selector(deleteSearchableItemsWithDomainIdentifiers:completionHandler:) 
                               withObject:@[bundleID]
                               withObject:^(NSError * _Nullable error) {
                if (error) {
                    NSLog(@"[AppDataCleaner] Error clearing Spotlight indexes: %@", error.localizedDescription);
                } else {
                    NSLog(@"[AppDataCleaner] Spotlight indexes cleared successfully");
                }
                dispatch_group_leave(group);
            }];
            
            // Wait for completion with timeout
            dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
            dispatch_group_wait(group, timeout);
        }
    }
    
    // Also manually clear Spotlight directories regardless of API result
    NSArray *spotlightPaths = @[
        [NSString stringWithFormat:@"/var/mobile/Library/Spotlight/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Spotlight/%@*", bundleID],
        @"/var/mobile/Library/Caches/com.apple.Spotlight*",
        @"/var/mobile/Library/Caches/com.apple.Spotlight*"
    ];
    
    for (NSString *pattern in spotlightPaths) {
            NSArray *matches = [self findPathsMatchingPattern:pattern];
            for (NSString *path in matches) {
            NSLog(@"[AppDataCleaner] Removing Spotlight file: %@", path);
                [self securelyWipeFile:path];
        }
    }
}

#pragma mark - UUID Finding Methods

- (NSString *)findBundleUUID:(NSString *)bundleID {
    NSArray *bundleDirs = [self listDirectoriesInPath:@"/var/containers/Bundle/Application"];
    
    for (NSString *uuid in bundleDirs) {
        NSString *appPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@", uuid];
        NSArray *appContents = [self listDirectoriesInPath:appPath];
        
        for (NSString *item in appContents) {
            if ([item hasSuffix:@".app"]) {
                NSString *infoPlistPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@/%@/Info.plist", 
                                          uuid, item];
                NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                
                if ([itemBundleID isEqualToString:bundleID]) {
                    return uuid;
                }
            }
        }
    }
    
    // Try rootless path if standard path didn't work
    if ([self directoryHasContent:@"/containers/Bundle/Application"]) {
        NSArray *bundleDirs = [self listDirectoriesInPath:@"/containers/Bundle/Application"];
        
        for (NSString *uuid in bundleDirs) {
            NSString *appPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@", uuid];
            NSArray *appContents = [self listDirectoriesInPath:appPath];
            
            for (NSString *item in appContents) {
                if ([item hasSuffix:@".app"]) {
                    NSString *infoPlistPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@/%@/Info.plist", 
                                              uuid, item];
                    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                    NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                    
                    if ([itemBundleID isEqualToString:bundleID]) {
                        return uuid;
                    }
                }
            }
        }
    }
    
    return nil;
}

- (NSString *)findDataContainerUUID:(NSString *)bundleID aggressive:(BOOL)aggressive {
    // Extract company and app short name
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *company = parts.count > 1 ? parts[1] : @"";
    NSString *shortName = parts.lastObject;
    NSArray *dataDirs = [self listDirectoriesInPath:@"/var/mobile/Containers/Data/Application"];
    for (NSString *uuid in dataDirs) {
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        // 1. Exact match
        if ([containerBundleID isEqualToString:bundleID]) return uuid;
        // 2. Aggressive/fuzzy matching
        if (aggressive) {
            if ([containerBundleID containsString:bundleID] ||
                (company.length && [containerBundleID containsString:company]) ||
                (shortName.length && [containerBundleID containsString:shortName])) {
                NSLog(@"[AppDataCleaner][Aggressive] Matched data container %@ by fuzzy metadata: %@", uuid, containerBundleID);
                return uuid;
            }
            // 3. Scan for app-named files/dirs
            NSString *containerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", uuid];
            NSArray *contents = [self listDirectoriesInPath:containerPath];
            for (NSString *item in contents) {
                if (([item containsString:bundleID] ||
                     (company.length && [item containsString:company]) ||
                     (shortName.length && [item containsString:shortName]))) {
                    NSLog(@"[AppDataCleaner][Aggressive] Matched data container %@ by file/dir: %@", uuid, item);
                    return uuid;
                }
            }
        }
    }
    return nil;
}

// Backwards compatibility: default aggressive to YES
- (NSString *)findDataContainerUUID:(NSString *)bundleID {
    return [self findDataContainerUUID:bundleID aggressive:YES];
    NSLog(@"[AppDataCleaner] Searching for data container UUID for %@", bundleID);
    
    NSArray *dataDirs = [self listDirectoriesInPath:@"/var/mobile/Containers/Data/Application"];
    NSLog(@"[AppDataCleaner] Found %lu application data containers", (unsigned long)dataDirs.count);
    
    for (NSString *uuid in dataDirs) {
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        
        if ([containerBundleID isEqualToString:bundleID]) {
            NSLog(@"[AppDataCleaner] Found data container UUID: %@ for %@", uuid, bundleID);
            return uuid;
        }
    }
    
    NSLog(@"[AppDataCleaner] No data container found for %@", bundleID);
    return nil;
}

- (NSString *)findRootlessDataContainerUUID:(NSString *)bundleID aggressive:(BOOL)aggressive {
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *company = parts.count > 1 ? parts[1] : @"";
    NSString *shortName = parts.lastObject;
    if (![_fileManager fileExistsAtPath:@"/containers/Data/Application"]) return nil;
    NSArray *dataDirs = [self listDirectoriesInPath:@"/containers/Data/Application"];
    for (NSString *uuid in dataDirs) {
        NSString *metadataPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        if ([containerBundleID isEqualToString:bundleID]) return uuid;
        if (aggressive) {
            if ([containerBundleID containsString:bundleID] ||
                (company.length && [containerBundleID containsString:company]) ||
                (shortName.length && [containerBundleID containsString:shortName])) {
                NSLog(@"[AppDataCleaner][Aggressive] Matched rootless data container %@ by fuzzy metadata: %@", uuid, containerBundleID);
                return uuid;
            }
            NSString *containerPath = [NSString stringWithFormat:@"/containers/Data/Application/%@", uuid];
            NSArray *contents = [self listDirectoriesInPath:containerPath];
            for (NSString *item in contents) {
                if (([item containsString:bundleID] ||
                     (company.length && [item containsString:company]) ||
                     (shortName.length && [item containsString:shortName]))) {
                    NSLog(@"[AppDataCleaner][Aggressive] Matched rootless data container %@ by file/dir: %@", uuid, item);
                    return uuid;
                }
            }
        }
    }
    return nil;
}

- (NSString *)findRootlessDataContainerUUID:(NSString *)bundleID {
    return [self findRootlessDataContainerUUID:bundleID aggressive:YES];
    NSLog(@"[AppDataCleaner] Searching for rootless data container UUID for %@", bundleID);
    
    if (![_fileManager fileExistsAtPath:@"/containers/Data/Application"]) {
        NSLog(@"[AppDataCleaner] Rootless data containers directory doesn't exist");
        return nil;
    }
    
    NSArray *dataDirs = [self listDirectoriesInPath:@"/containers/Data/Application"];
    NSLog(@"[AppDataCleaner] Found %lu rootless application data containers", (unsigned long)dataDirs.count);
    
    for (NSString *uuid in dataDirs) {
        NSString *metadataPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        
        if ([containerBundleID isEqualToString:bundleID]) {
            NSLog(@"[AppDataCleaner] Found rootless data container UUID: %@ for %@", uuid, bundleID);
            return uuid;
        }
    }
    
    NSLog(@"[AppDataCleaner] No rootless data container found for %@", bundleID);
    return nil;
}

- (NSArray *)findAppGroupUUIDs:(NSString *)bundleID aggressive:(BOOL)aggressive {
    NSMutableArray *groupUUIDs = [NSMutableArray array];
    NSArray *groupDirs = [self listDirectoriesInPath:@"/var/mobile/Containers/Shared/AppGroup"];
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *company = parts.count > 1 ? parts[1] : @"";
    NSString *shortName = parts.lastObject;
    for (NSString *uuid in groupDirs) {
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        id groupIdentifier = metadata[@"MCMMetadataIdentifier"];
        if ([groupIdentifier isKindOfClass:[NSArray class]]) {
            if ([(NSArray *)groupIdentifier containsObject:bundleID]) {
                [groupUUIDs addObject:uuid];
                continue;
            }
        } else if ([groupIdentifier isKindOfClass:[NSString class]]) {
            if ([(NSString *)groupIdentifier containsString:bundleID]) {
                [groupUUIDs addObject:uuid];
                continue;
            }
        }
        if (aggressive) {
            // Fuzzy match company/app name
            if (([groupIdentifier isKindOfClass:[NSString class]] &&
                 ((company.length && [groupIdentifier containsString:company]) ||
                  (shortName.length && [groupIdentifier containsString:shortName])))) {
                NSLog(@"[AppDataCleaner][Aggressive] Matched app group %@ by fuzzy metadata: %@", uuid, groupIdentifier);
                [groupUUIDs addObject:uuid];
                continue;
            }
            // Scan for files/dirs
            NSString *containerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", uuid];
            NSArray *contents = [self listDirectoriesInPath:containerPath];
            for (NSString *item in contents) {
                if (([item containsString:bundleID] ||
                     (company.length && [item containsString:company]) ||
                     (shortName.length && [item containsString:shortName]))) {
                    NSLog(@"[AppDataCleaner][Aggressive] Matched app group %@ by file/dir: %@", uuid, item);
                    [groupUUIDs addObject:uuid];
                    break;
                }
            }
        }
    }
    return groupUUIDs;
}

- (NSArray *)findAppGroupUUIDs:(NSString *)bundleID {
    return [self findAppGroupUUIDs:bundleID aggressive:YES];
    NSMutableArray *groupUUIDs = [NSMutableArray array];
    NSArray *groupDirs = [self listDirectoriesInPath:@"/var/mobile/Containers/Shared/AppGroup"];
    
    for (NSString *uuid in groupDirs) {
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        
        // App groups may have different metadata structure
        id groupIdentifier = metadata[@"MCMMetadataIdentifier"];
        
        if ([groupIdentifier isKindOfClass:[NSArray class]]) {
            // Check if bundle ID is in the apps array
            if ([(NSArray *)groupIdentifier containsObject:bundleID]) {
                [groupUUIDs addObject:uuid];
            }
        } else if ([groupIdentifier isKindOfClass:[NSString class]]) {
            // Some older iOS versions store just the group ID
            // Check if bundle ID is part of the group ID
            if ([(NSString *)groupIdentifier containsString:bundleID]) {
                [groupUUIDs addObject:uuid];
            }
        }
    }
    
    return groupUUIDs;
}

- (NSArray *)findRootlessAppGroupUUIDs:(NSString *)bundleID {
    if (!bundleID.length) return @[];

    // Use entitlements + resolver; filter only /containers-based results.
    AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
    NSError *entErr = nil;
    NSDictionary *ent = [reader fullEntitlementsForBundleID:bundleID error:&entErr];
    NSArray *groups = nil;
    if ([ent isKindOfClass:[NSDictionary class]]) {
        id v = ent[@"com.apple.security.application-groups"];
        if ([v isKindOfClass:[NSArray class]]) {
            groups = (NSArray *)v;
        } else {
            v = ent[@"application-groups"];
            if ([v isKindOfClass:[NSArray class]]) {
                groups = (NSArray *)v;
            }
        }
    }
    if (!groups.count) {
        return @[];
    }

    NSMutableArray<NSString *> *groupIDs = [NSMutableArray array];
    for (id g in groups) {
        if ([g isKindOfClass:[NSString class]] && [(NSString *)g length] > 0) {
            [groupIDs addObject:(NSString *)g];
        }
    }
    if (!groupIDs.count) {
        return @[];
    }

    AppGroupContainerResolver *resolver = [[AppGroupContainerResolver alloc] init];
    NSArray<AppGroupContainerInfo *> *infos = [resolver resolveGroupContainersForGroupIDs:groupIDs];
    NSMutableArray<NSString *> *uuids = [NSMutableArray array];
    for (AppGroupContainerInfo *info in infos) {
        if (![info.path isKindOfClass:[NSString class]] || !info.path.length) continue;
        if (![info.path hasPrefix:@"/containers/Shared/AppGroup/"]) continue;
        [uuids addObject:[info.path lastPathComponent]];
    }
    return uuids;
}

#pragma mark - Cleaning Methods

- (void)wipeDirectoryContents:(NSString *)path keepDirectoryStructure:(BOOL)keepStructure {
    if (![_fileManager fileExistsAtPath:path]) {
        return;
    }
    
    NSError *error;
    NSArray *contents = [_fileManager contentsOfDirectoryAtPath:path error:&error];
    
    if (error) {
        NSLog(@"[AppDataCleaner] Error listing directory %@: %@", path, error.localizedDescription);
        // Try to recover with force command
        NSString *forceCommand = [NSString stringWithFormat:@"rm -rf '%@'/* 2>/dev/null || true", path];
        [self runCommandWithPrivileges:forceCommand];
        return;
    }
    
    for (NSString *item in contents) {
        NSString *itemPath = [path stringByAppendingPathComponent:item];
        
        // Skip metadata plists if keeping structure
        if (keepStructure && [item hasPrefix:@".com.apple"]) {
            continue;
        }
        
        // Securely delete the file/directory with better error handling
        if (![self securelyWipeFile:itemPath]) {
            // If standard removal fails, try force
            NSLog(@"[AppDataCleaner] Standard wipe failed for %@, using force removal", itemPath);
            [self fixPermissionsAndRemovePath:itemPath];
        }
    }
    
    // Double-check the directory is now empty
    NSArray *remainingContents = [_fileManager contentsOfDirectoryAtPath:path error:&error];
    if (remainingContents.count > 0 && ![remainingContents[0] hasPrefix:@"."]) {
        NSLog(@"[AppDataCleaner] Directory still has content after wiping, using force command: %@", path);
        NSString *forceCommand = [NSString stringWithFormat:@"rm -rf '%@'/* 2>/dev/null || true", path];
        [self runCommandWithPrivileges:forceCommand];
    }
}

- (BOOL)securelyWipeFile:(NSString *)path {
    if (![_fileManager fileExistsAtPath:path]) {
        return YES; // Already doesn't exist
    }
    
    // For directories, recursively wipe contents
    BOOL isDirectory = NO;
    [_fileManager fileExistsAtPath:path isDirectory:&isDirectory];
    
    if (isDirectory) {
        NSDirectoryEnumerator *enumerator = [_fileManager enumeratorAtPath:path];
        NSString *file;
        
        while ((file = [enumerator nextObject])) {
            NSString *fullPath = [path stringByAppendingPathComponent:file];
            [self securelyWipeFile:fullPath];
        }
    }
    
    // Secure overwrite for files (not directories)
    if (!isDirectory) {
    const char *cPath = [path fileSystemRepresentation];
    int fd = open(cPath, O_RDWR);
        if (fd >= 0) {
    off_t fileSize = lseek(fd, 0, SEEK_END);
            if (fileSize > 0) {
    // Multiple pass overwrite
    for (int pass = 0; pass < 3; pass++) {
        lseek(fd, 0, SEEK_SET);
        char *buffer = (char *)calloc(1024, 1);
        
        if (pass == 0) memset(buffer, 0xFF, 1024);  // First pass: 1's
        if (pass == 1) memset(buffer, 0x00, 1024);  // Second pass: 0's
        if (pass == 2) arc4random_buf(buffer, 1024); // Third pass: random
        
        size_t bytesRemaining = fileSize;
        while (bytesRemaining > 0) {
            size_t bytesToWrite = MIN(bytesRemaining, 1024);
            write(fd, buffer, bytesToWrite);
            bytesRemaining -= bytesToWrite;
        }
        
        free(buffer);
    }
            }
    close(fd);
        }
    }
    
    // Finally remove the file/directory
    NSError *error;
    BOOL success = [_fileManager removeItemAtPath:path error:&error];
    if (!success) {
        NSLog(@"[AppDataCleaner] Error removing %@: %@", path, error.localizedDescription);
        
        // Try with higher privileges if normal removal fails
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf \"%@\"", path]];
        
        // Check if it's gone now
        return ![_fileManager fileExistsAtPath:path];
    }
    
    return YES;
}

- (void)clearKeychainItemsForBundleID:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing keychain items for %@", bundleID);
    
    // More aggressive approach for keychain clearing
    
    // 1. Build an array of possible access groups and service names
    NSMutableArray *possibleAccessGroups = [NSMutableArray arrayWithObjects:
        bundleID,
        [NSString stringWithFormat:@"%@.*", bundleID],
        nil];
    
    // Get the app identifier prefix (team ID) for enterprise apps
    NSArray *bundleComponents = [bundleID componentsSeparatedByString:@"."];
    if (bundleComponents.count >= 2) {
        NSString *appIdPrefix = [NSString stringWithFormat:@"%@.%@", bundleComponents[0], bundleComponents[1]];
        [possibleAccessGroups addObject:appIdPrefix];
        [possibleAccessGroups addObject:[NSString stringWithFormat:@"%@.*", appIdPrefix]];
    }
    
    // Add common group patterns
    [possibleAccessGroups addObject:[NSString stringWithFormat:@"group.%@", bundleID]];
    [possibleAccessGroups addObject:[NSString stringWithFormat:@"%@.group", bundleID]];
    [possibleAccessGroups addObject:[NSString stringWithFormat:@"*%@*", bundleID]]; // Wildcard match
    
    // Facebook-specific access groups (Meta apps share keychain)
    [possibleAccessGroups addObject:@"com.facebook.Facebook"];
    [possibleAccessGroups addObject:@"com.facebook.Messenger"];
    [possibleAccessGroups addObject:@"com.facebook.Instagram"];
    [possibleAccessGroups addObject:@"com.facebook.WhatsApp"];
    [possibleAccessGroups addObject:@"com.facebook.family"];
    [possibleAccessGroups addObject:@"group.com.facebook.family"];
    [possibleAccessGroups addObject:@"group.com.facebook.Facebook"];
    [possibleAccessGroups addObject:@"com.facebook.token"];
    [possibleAccessGroups addObject:@"com.facebook.sdk"];
    [possibleAccessGroups addObject:@"com.facebook.core"];
    [possibleAccessGroups addObject:@"*facebook*"];
    [possibleAccessGroups addObject:@"*meta*"];
    [possibleAccessGroups addObject:@"*fbauth*"];
    [possibleAccessGroups addObject:@"*FBSDKAccessToken*"];
    
    // For Uber and similar apps using Firebase, add these specific groups
    [possibleAccessGroups addObject:@"com.google.firebase.auth"];
    [possibleAccessGroups addObject:@"com.google.HTTPClient"];
    [possibleAccessGroups addObject:@"com.firebase.auth"];
    [possibleAccessGroups addObject:@"com.google.ios.auth"];
    
    // Special groups for delivery/rideshare apps
    [possibleAccessGroups addObject:@"com.uber.keychainaccess"];
    [possibleAccessGroups addObject:@"com.ubercab.keychainaccess"];
    [possibleAccessGroups addObject:@"com.ubercab.UberClient.keychainaccess"];
    [possibleAccessGroups addObject:@"com.helix.keychainaccess"];
    [possibleAccessGroups addObject:@"com.lyft.keychainaccess"];
    [possibleAccessGroups addObject:@"com.lyft.ios.keychainaccess"];
    [possibleAccessGroups addObject:@"com.zimride.instant.keychainaccess"];
    [possibleAccessGroups addObject:@"com.grubhub.search.keychainaccess"];
    [possibleAccessGroups addObject:@"doordash.DoorDashConsumer.keychainaccess"];
    [possibleAccessGroups addObject:@"doordash.DoorDashConsumer.5P29S428QN.keychainaccess"];
    [possibleAccessGroups addObject:@"*uber*"];
    [possibleAccessGroups addObject:@"*ubercab*"];
    [possibleAccessGroups addObject:@"*helix*"];
    [possibleAccessGroups addObject:@"*lyft*"];
    [possibleAccessGroups addObject:@"*zimride*"];
    [possibleAccessGroups addObject:@"*grubhub*"];
    [possibleAccessGroups addObject:@"*doordash*"];
    
    // Even more aggressive - extract keywords from the bundle ID
    for (NSString *component in bundleComponents) {
        if (component.length > 3 && ![component isEqualToString:@"com"] && 
            ![component isEqualToString:@"org"] && ![component isEqualToString:@"net"]) {
            [possibleAccessGroups addObject:[NSString stringWithFormat:@"*%@*", component]];
            [possibleAccessGroups addObject:component];
        }
    }
    
    // 2. Additional search terms for Uber and similar apps
    NSMutableArray *searchTerms = [NSMutableArray arrayWithObject:bundleID];
    
    // Extract app name without com.company prefix
    if (bundleComponents.count > 1) {
        [searchTerms addObject:[bundleComponents lastObject]];
    }

    // Add common keywords for auth data
    [searchTerms addObjectsFromArray:@[
        @"auth", @"token", @"credential", @"session", @"login", 
        @"oauth", @"account", @"user", @"api", @"firebase",
        @"google", @"identity", @"refresh", @"jwt", @"device"
    ]];
    
    // 3. Keychain security classes
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    
    // 4. Very aggressive clearing - iterate through different combinations
    for (id secClass in secClasses) {
        // First try with direct bundle ID match with all items
        NSDictionary *query = @{
            (__bridge id)kSecClass: secClass,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
        };
        
        // 4.1 Retrieve all items of this class first to inspect them
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        
        if (status == errSecSuccess && result != NULL) {
            NSArray *items = (__bridge_transfer NSArray *)result;
            NSLog(@"[AppDataCleaner] DEBUG: Found %lu keychain items of this class", (unsigned long)items.count);
            
            int matchCount = 0;
            // 4.2 Examine each item to see if it matches our bundle ID or keywords
            for (NSDictionary *item in items) {
                BOOL shouldDelete = NO;
                
                // 4.3 Check access group (case-insensitive)
                NSString *accessGroup = item[(__bridge id)kSecAttrAccessGroup];
                if (accessGroup) {
                    NSString *accessGroupLower = [accessGroup lowercaseString];
                    for (NSString *groupPattern in possibleAccessGroups) {
                        NSString *patternLower = [[groupPattern stringByReplacingOccurrencesOfString:@"*" withString:@""] lowercaseString];
                        if ([accessGroupLower containsString:patternLower] && patternLower.length > 2) {
                            shouldDelete = YES;
                            break;
                        }
                    }
                }
                
                // 4.4 Check service name (case-insensitive)
                NSString *service = item[(__bridge id)kSecAttrService];
                if (!shouldDelete && service) {
                    NSString *serviceLower = [service lowercaseString];
                    for (NSString *term in searchTerms) {
                        if ([serviceLower containsString:[term lowercaseString]]) {
                            shouldDelete = YES;
                            break;
                        }
                    }
                }
                
                // 4.5 Check account name (case-insensitive)
                NSString *account = item[(__bridge id)kSecAttrAccount];
                if (!shouldDelete && account) {
                    NSString *accountLower = [account lowercaseString];
                    for (NSString *term in searchTerms) {
                        if ([accountLower containsString:[term lowercaseString]]) {
                            shouldDelete = YES;
                            break;
                        }
                    }
                }
                
                // 4.6 Check label (case-insensitive)
                NSString *label = item[(__bridge id)kSecAttrLabel];
                if (!shouldDelete && label) {
                    NSString *labelLower = [label lowercaseString];
                    for (NSString *term in searchTerms) {
                        if ([labelLower containsString:[term lowercaseString]]) {
                            shouldDelete = YES;
                            break;
                        }
                    }
                }
                
                // 4.7 If we should delete this item, create a query that matches it exactly
                if (shouldDelete) {
                    matchCount++;
                    NSMutableDictionary *deleteQuery = [NSMutableDictionary dictionaryWithDictionary:@{
                        (__bridge id)kSecClass: secClass
                    }];
                    
                    // Add all available attributes to ensure we match only this item
                    if (accessGroup) deleteQuery[(__bridge id)kSecAttrAccessGroup] = accessGroup;
                    if (service) deleteQuery[(__bridge id)kSecAttrService] = service;
                    if (account) deleteQuery[(__bridge id)kSecAttrAccount] = account;
                    if (label) deleteQuery[(__bridge id)kSecAttrLabel] = label;
                    
                    OSStatus deleteStatus = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
                    if (deleteStatus == errSecSuccess) {
                        NSLog(@"[AppDataCleaner] DELETED keychain: svc=%@ grp=%@", service ?: @"nil", accessGroup ?: @"nil");
                    } else {
                         NSLog(@"[AppDataCleaner] FAILED to delete keychain: status=%d, svc=%@ grp=%@", (int)deleteStatus, service ?: @"nil", accessGroup ?: @"nil");
                    }
                }
            }
            NSLog(@"[AppDataCleaner] DEBUG: Scanned %lu items, Matched %d items for deletion", (unsigned long)items.count, matchCount);
        }
        
        // 5. Original direct matches approach - keep this for backward compatibility
        for (NSString *accessGroup in possibleAccessGroups) {
            query = @{
                (__bridge id)kSecClass: secClass,
                (__bridge id)kSecAttrAccessGroup: accessGroup,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
            };
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
        
        // 6. Try service name matches with all search terms
        for (NSString *term in searchTerms) {
            query = @{
                (__bridge id)kSecClass: secClass,
                (__bridge id)kSecAttrService: term,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
            };
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
        
        // 7. Try account matches with all search terms
        for (NSString *term in searchTerms) {
            query = @{
                (__bridge id)kSecClass: secClass,
                (__bridge id)kSecAttrAccount: term,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
            };
            SecItemDelete((__bridge CFDictionaryRef)query);
        }
    }
    
    // 8. Clear URL credentials which might store login sessions
    [self clearURLCredentialsForBundleID:bundleID];
    
    // 9. Use command-line security tool as a backup method
    NSString *keychainScript = [NSString stringWithFormat:
                               @"security delete-generic-password -l '%@' 2>/dev/null || true;"
                               @"security delete-internet-password -l '%@' 2>/dev/null || true", 
                               bundleID, bundleID];
    [self runCommandWithPrivileges:keychainScript];
    
    // 10. For Uber and apps like it, clear Google tokens
    [self runCommandWithPrivileges:@"security delete-generic-password -l 'com.google.HTTPClient' 2>/dev/null || true"];
    [self runCommandWithPrivileges:@"security delete-generic-password -l 'com.google.ios.auth' 2>/dev/null || true"];
}

// Universal keychain wipe - very aggressive approach
- (void)universalKeychainWipeForBundleID:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Universal keychain wipe for %@", bundleID);
    
    // Extract app identifiers
    NSArray *components = [bundleID componentsSeparatedByString:@"."];
    NSString *appName = components.lastObject ?: @"";
    NSString *companyName = components.count > 1 ? components[1] : @"";
    
    // Build list of search patterns
    NSMutableArray *patterns = [NSMutableArray array];
    [patterns addObject:bundleID];
    [patterns addObject:[bundleID lowercaseString]];
    if (appName.length > 0) {
        [patterns addObject:appName];
        [patterns addObject:[appName lowercaseString]];
    }
    if (companyName.length > 0) {
        [patterns addObject:companyName];
        [patterns addObject:[companyName lowercaseString]];
    }
    
    // Delete by each pattern using security command
    for (NSString *pattern in patterns) {
        // Delete generic passwords
        [self runCommandWithPrivileges:[NSString stringWithFormat:
            @"security dump-keychain -d 2>/dev/null | grep -i '%@' | grep 'svce' | cut -d'\"' -f4 | while read svc; do security delete-generic-password -s \"$svc\" 2>/dev/null; done || true", pattern]];
        
        // Delete internet passwords  
        [self runCommandWithPrivileges:[NSString stringWithFormat:
            @"security dump-keychain -d 2>/dev/null | grep -i '%@' | grep 'srvr' | cut -d'\"' -f4 | while read srv; do security delete-internet-password -s \"$srv\" 2>/dev/null; done || true", pattern]];
    }
    
    // Direct deletion using SecItemDelete with broader queries
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword
    ];
    
    for (id secClass in secClasses) {
        // Query ALL items and delete those matching our bundle
        NSDictionary *query = @{
            (__bridge id)kSecClass: secClass,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
        };
        
        CFTypeRef result = NULL;
        if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) == errSecSuccess && result) {
            NSArray *items = (__bridge_transfer NSArray *)result;
            
            for (NSDictionary *item in items) {
                NSString *service = item[(__bridge id)kSecAttrService];
                NSString *account = item[(__bridge id)kSecAttrAccount];
                NSString *accessGroup = item[(__bridge id)kSecAttrAccessGroup];
                
                BOOL shouldDelete = NO;
                
                // Check if any attribute matches our patterns
                for (NSString *pattern in patterns) {
                    NSString *lowerPattern = [pattern lowercaseString];
                    if ((service && [[service lowercaseString] containsString:lowerPattern]) ||
                        (account && [[account lowercaseString] containsString:lowerPattern]) ||
                        (accessGroup && [[accessGroup lowercaseString] containsString:lowerPattern])) {
                        shouldDelete = YES;
                        break;
                    }
                }
                
                if (shouldDelete) {
                    NSMutableDictionary *deleteQuery = [NSMutableDictionary dictionary];
                    deleteQuery[(__bridge id)kSecClass] = secClass;
                    if (service) deleteQuery[(__bridge id)kSecAttrService] = service;
                    if (account) deleteQuery[(__bridge id)kSecAttrAccount] = account;
                    
                    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
                    if (status == errSecSuccess) {
                        NSLog(@"[AppDataCleaner] Deleted keychain item - service: %@, account: %@", service, account);
                    }
                }
            }
        }
    }
    
    // Backup: Try to delete ALL generic passwords that might match this app
    // This is more aggressive and catches items missed by pattern matching
    NSArray *bundleParts = [bundleID componentsSeparatedByString:@"."];
    for (NSString *part in bundleParts) {
        if (part.length < 3) continue;
        if ([part isEqualToString:@"com"] || [part isEqualToString:@"org"]) continue;
        
        // Delete by service name containing part
        NSDictionary *deleteByService = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: part
        };
        SecItemDelete((__bridge CFDictionaryRef)deleteByService);
        
        // Delete by account containing part
        NSDictionary *deleteByAccount = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount: part
        };
        SecItemDelete((__bridge CFDictionaryRef)deleteByAccount);
    }
    
    NSLog(@"[AppDataCleaner] Universal keychain wipe completed for %@", bundleID);
}

- (void)clearURLCredentialsForBundleID:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing URL credentials for %@", bundleID);
    
    // Get URL credential storage
    NSURLCredentialStorage *storage = [NSURLCredentialStorage sharedCredentialStorage];
    
    // Get all the host/protection space combinations
    NSDictionary *allCredentials = [storage allCredentials];
    
    // Parse out domain names from the bundle ID (like 'uber' from 'com.ubercab.UberClient')
    NSArray *bundleComponents = [bundleID componentsSeparatedByString:@"."];
    NSMutableArray *possibleDomains = [NSMutableArray array];
    for (NSString *component in bundleComponents) {
        if (component.length > 3 && ![component isEqualToString:@"com"] && 
            ![component isEqualToString:@"org"] && ![component isEqualToString:@"net"]) {
            [possibleDomains addObject:component];
        }
    }
    
    // Loop through all credentials and remove any that might be related to this app
    for (NSURLProtectionSpace *protectionSpace in allCredentials.allKeys) {
        BOOL shouldClear = NO;
        
        // Check if host matches any possible domain
        for (NSString *domain in possibleDomains) {
            if ([protectionSpace.host containsString:domain]) {
                shouldClear = YES;
                break;
            }
        }
        
        // Also check for matches in the realm
        if (!shouldClear && protectionSpace.realm) {
            for (NSString *domain in possibleDomains) {
                if ([protectionSpace.realm containsString:domain]) {
                    shouldClear = YES;
                    break;
                }
            }
        }
        
        if (shouldClear) {
            NSDictionary *credentials = [storage credentialsForProtectionSpace:protectionSpace];
            for (NSString *username in credentials.allKeys) {
                NSURLCredential *credential = credentials[username];
                [storage removeCredential:credential forProtectionSpace:protectionSpace];
                NSLog(@"[AppDataCleaner] Removed credential for %@ at %@", username, protectionSpace.host);
            }
        }
    }
}

- (void)cleanRootHideVarData:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Cleaning RootHide var data for %@", bundleID);
    
    // RootHide stores some data in these locations
    NSArray *rootHidePaths = @[
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@*.plist", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/%@", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/%@*", bundleID],
        [NSString stringWithFormat:@"/var/tmp/%@*", bundleID],
        [NSString stringWithFormat:@"/tmp/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/WebKit/WebsiteData/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Application Support/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Cookies/%@*", bundleID],
        // RootHide specific paths
        [NSString stringWithFormat:@"/var/root/Library/Preferences/%@*.plist", bundleID],
        [NSString stringWithFormat:@"/private/var/mobile/Library/Preferences/%@*.plist", bundleID]
    ];
    
    for (NSString *pattern in rootHidePaths) {
        NSArray *matches = [self findPathsMatchingPattern:pattern];
        for (NSString *path in matches) {
            NSLog(@"[AppDataCleaner] Wiping RootHide path: %@", path);
            [self securelyWipeFile:path];
        }
    }
    
    // Use elevated permissions to ensure clean var
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Caches/%@*", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Preferences/%@*", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/root/Library/Preferences/%@*", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /private/var/mobile/Library/Preferences/%@*", bundleID]];
}

- (void)clearPluginKitData:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing PluginKit and extension data for %@", bundleID);
    
    // PluginKit stores data about app extensions which can also contain auth data
    NSArray *pluginKitPaths = @[
        @"/var/mobile/Library/PlugInKit/",
        @"/var/mobile/Library/PlugInKit/",
        @"/var/mobile/Library/MobileContainerManager/PluginKitPlugin/",
        @"/var/mobile/Library/MobileContainerManager/PluginKitPlugin/"
    ];
    
    for (NSString *basePath in pluginKitPaths) {
        if ([_fileManager fileExistsAtPath:basePath]) {
            // Look for plists and DBs with this app's bundle ID
            NSArray *matches = [self findPathsMatchingPattern:[NSString stringWithFormat:@"%@**/%@*", basePath, bundleID]];
            for (NSString *path in matches) {
                NSLog(@"[AppDataCleaner] Wiping PluginKit file: %@", path);
        [self securelyWipeFile:path];
            }
            
            // Also look for any domain components (like "uber" from "com.ubercab.UberClient")
            NSArray *bundleComponents = [bundleID componentsSeparatedByString:@"."];
            for (NSString *component in bundleComponents) {
                if (component.length > 3 && ![component isEqualToString:@"com"] && 
                    ![component isEqualToString:@"org"] && ![component isEqualToString:@"net"]) {
                    matches = [self findPathsMatchingPattern:[NSString stringWithFormat:@"%@**/*%@*", basePath, component]];
                    for (NSString *path in matches) {
                        NSLog(@"[AppDataCleaner] Wiping PluginKit file with component %@: %@", component, path);
                        [self securelyWipeFile:path];
                    }
                }
            }
        }
    }
    
    // Check for container manager data
    NSString *containerMgrPath = @"/var/mobile/Library/MobileContainerManager/containers.plist";
    if ([_fileManager fileExistsAtPath:containerMgrPath]) {
        NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"containers.plist.temp"];
        [_fileManager copyItemAtPath:containerMgrPath toPath:tempPath error:nil];
        
        NSMutableDictionary *containers = [NSMutableDictionary dictionaryWithContentsOfFile:tempPath];
        if (containers) {
            BOOL modified = NO;
            NSArray *keys = [containers allKeys];
            for (NSString *key in keys) {
                id value = containers[key];
                if ([value isKindOfClass:[NSDictionary class]]) {
                    NSString *identifier = value[@"identifier"];
                    if ([identifier isKindOfClass:[NSString class]] && [identifier containsString:bundleID]) {
                        [containers removeObjectForKey:key];
                        modified = YES;
                        NSLog(@"[AppDataCleaner] Removed container reference %@ for %@", key, bundleID);
                    }
                }
            }
            
            if (modified) {
                [containers writeToFile:tempPath atomically:YES];
                [self runCommandWithPrivileges:[NSString stringWithFormat:@"cp '%@' '%@'", tempPath, containerMgrPath]];
            }
        }
        
        [_fileManager removeItemAtPath:tempPath error:nil];
    }
    
    // Also check rootless path
    NSString *rootlessContainerMgrPath = @"/var/mobile/Library/MobileContainerManager/containers.plist";
    if ([_fileManager fileExistsAtPath:rootlessContainerMgrPath]) {
        NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"containers.plist.temp"];
        [_fileManager copyItemAtPath:rootlessContainerMgrPath toPath:tempPath error:nil];
        
        NSMutableDictionary *containers = [NSMutableDictionary dictionaryWithContentsOfFile:tempPath];
        if (containers) {
            BOOL modified = NO;
            NSArray *keys = [containers allKeys];
            for (NSString *key in keys) {
                id value = containers[key];
                if ([value isKindOfClass:[NSDictionary class]]) {
                    NSString *identifier = value[@"identifier"];
                    if ([identifier isKindOfClass:[NSString class]] && [identifier containsString:bundleID]) {
                        [containers removeObjectForKey:key];
                        modified = YES;
                        NSLog(@"[AppDataCleaner] Removed rootless container reference %@ for %@", key, bundleID);
                    }
                }
            }
            
            if (modified) {
                [containers writeToFile:tempPath atomically:YES];
                [self runCommandWithPrivileges:[NSString stringWithFormat:@"cp '%@' '%@'", tempPath, rootlessContainerMgrPath]];
            }
        }
        
        [_fileManager removeItemAtPath:tempPath error:nil];
    }
}

- (void)clearThumbnailCaches:(NSString *)bundleID {
    NSArray *paths = @[
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.thumbnailservices/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.QuickLook.thumbnailcache/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.thumbnailservices/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/com.apple.QuickLook.thumbnailcache/%@*", bundleID]
    ];
    
    for (NSString *pattern in paths) {
        NSArray *matches = [self findPathsMatchingPattern:pattern];
        for (NSString *path in matches) {
            NSLog(@"[AppDataCleaner] Wiping thumbnail cache: %@", path);
            [self securelyWipeFile:path];
        }
    }
}

- (void)clearICloudData:(NSString *)bundleID {
    [self logMessage:@"[AppDataCleaner] Clearing iCloud-related data for %@", bundleID];

    // Keep the broad iCloud/CloudKit/CloudDocs/Accounts cleanup behavior, but optimize it:
    // - avoid repeated deep "**" scans with many find calls
    // - fast mode (Deep Clean OFF): shallow maxdepth scan (still wipes top-level app containers)
    // - deep mode (Deep Clean ON): deeper scan

    BOOL deep = [self _deepCleanEnabled];
    int maxDepth = deep ? 8 : 2;
    int findTimeout = deep ? (25 * 60) : (8 * 60);

    NSArray *bundleComponents = [bundleID componentsSeparatedByString:@"."];
    NSString *tildeID = [[bundleID stringByReplacingOccurrencesOfString:@"." withString:@"~"] stringByReplacingOccurrencesOfString:@"-" withString:@"~"]; 
    NSString *iCloudTilde = tildeID.length ? [NSString stringWithFormat:@"iCloud~%@", tildeID] : @"";

    NSMutableOrderedSet<NSString *> *searchSet = [NSMutableOrderedSet orderedSet];
    if (bundleID.length) [searchSet addObject:bundleID];
    if (tildeID.length) [searchSet addObject:tildeID];
    if (iCloudTilde.length) [searchSet addObject:iCloudTilde];

    for (NSString *component in bundleComponents) {
        if (component.length > 3 && ![component isEqualToString:@"com"] && ![component isEqualToString:@"org"] && ![component isEqualToString:@"net"]) {
            [searchSet addObject:component];
            [searchSet addObject:[NSString stringWithFormat:@"iCloud.%@", component]];
            [searchSet addObject:[NSString stringWithFormat:@"%@.icloud", component]];
            [searchSet addObject:[NSString stringWithFormat:@"com.apple.CloudDocs.%@", component]];
        }
    }

    // Dedupe lowercased variants
    NSMutableOrderedSet<NSString *> *finalTerms = [NSMutableOrderedSet orderedSet];
    for (NSString *t in searchSet) {
        if (![t isKindOfClass:[NSString class]] || t.length < 3) continue;
        [finalTerms addObject:t];
        [finalTerms addObject:[t lowercaseString]];
    }

    NSArray<NSString *> *bases = @[
        @"/var/mobile/Library/Mobile Documents",
        @"/var/mobile/Library/Application Support/CloudDocs",
        @"/var/mobile/Library/Application Support/CloudKit",
        @"/var/mobile/Library/Accounts"
    ];

    // One find per base path.
    for (NSString *basePath in bases) {
        if (![_fileManager fileExistsAtPath:basePath]) continue;

        NSMutableString *expr = [NSMutableString string];
        for (NSString *t in finalTerms.array) {
            if (expr.length) [expr appendString:@" -o "];
            // Match common iCloud directory naming; keep broad for compatibility.
            [expr appendFormat:@"-iname '*%@*'", t];
        }
        if (!expr.length) continue;

        // Escape parentheses for /bin/sh
        NSString *cmd = [NSString stringWithFormat:
                         @"find '%@' -mindepth 1 -maxdepth %d \\( %@ \\) -exec rm -rf {} + 2>/dev/null || true",
                         basePath, maxDepth, expr];
        [self runCommandWithPrivileges:cmd timeoutSec:findTimeout];
    }

    // Clear iCloud accounts info (batch, in-process sqlite to avoid missing sqlite3 tool)
    NSString *accountsDBPath = @"/var/mobile/Library/Accounts/Accounts3.sqlite";
    if ([_fileManager fileExistsAtPath:accountsDBPath] && finalTerms.count) {
        sqlite3 *db = NULL;
        int rc = sqlite3_open_v2(accountsDBPath.UTF8String, &db, SQLITE_OPEN_READWRITE, NULL);
        if (rc == SQLITE_OK && db) {
            sqlite3_busy_timeout(db, 3000);

            // Build a predicate using only columns that exist on this iOS schema.
            NSMutableDictionary<NSString *, NSSet<NSString *> *> *colCache = [NSMutableDictionary dictionary];
            NSMutableArray<NSString *> *cols = [NSMutableArray array];
            for (NSString *c in @[@"ZIDENTIFIER", @"ZOWNINGBUNDLEID", @"ZUSERNAME", @"ZACCOUNTDESCRIPTION", @"ZDISPLAYNAME", @"ZEMAILADDRESS"]) {
                if (PXSQLiteTableHasColumnCached(db, @"ZACCOUNT", c, colCache)) {
                    [cols addObject:c];
                }
            }
            if (!cols.count) {
                sqlite3_close(db);
            } else {
                NSString *errMsg = nil;
                PXSQLiteExec(db, @"PRAGMA busy_timeout=3000;", NULL);
                PXSQLiteExec(db, @"BEGIN IMMEDIATE;", &errMsg);
                if (errMsg.length) {
                    errMsg = nil;
                }

                for (NSString *term in finalTerms.array) {
                    NSString *t = [term stringByReplacingOccurrencesOfString:@"'" withString:@"''"]; 
                    NSMutableArray<NSString *> *preds = [NSMutableArray array];
                    for (NSString *c in cols) {
                        [preds addObject:[NSString stringWithFormat:@"%@ LIKE '%%%%%@%%%%'", c, t]];
                    }
                    NSString *where = [preds componentsJoinedByString:@" OR "];
                    NSString *del = [NSString stringWithFormat:@"DELETE FROM ZACCOUNT WHERE %@;", where];
                    PXSQLiteExec(db, del, NULL);
                }

                PXSQLiteExec(db, @"COMMIT;", NULL);
                PXSQLiteExec(db, @"PRAGMA wal_checkpoint(TRUNCATE);", NULL);
                sqlite3_close(db);
            }
        } else {
            if (db) sqlite3_close(db);
        }
    }
}

- (void)fastWipeDirectoryContents:(NSString *)path keepDirectoryStructure:(BOOL)keepStructure timeoutSec:(int)timeoutSec {
    if (![path isKindOfClass:[NSString class]] || path.length == 0) return;
    if (![_fileManager fileExistsAtPath:path]) return;

    if (timeoutSec <= 0) {
        timeoutSec = 8 * 60;
    }

    NSString *quoted = PXShellQuote(path);
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"chflags -R nouchg,noschg,nohidden %@ 2>/dev/null || true", quoted] timeoutSec:timeoutSec];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"chmod -R 0777 %@ 2>/dev/null || true", quoted] timeoutSec:timeoutSec];

    NSString *cmd = nil;
    if (keepStructure) {
        // Keep .com.apple* metadata in this directory.
        cmd = [NSString stringWithFormat:@"find %@ -mindepth 1 -maxdepth 1 -path '*/.com.apple*' -prune -o -exec rm -rf {} + 2>/dev/null || true", quoted];
    } else {
        cmd = [NSString stringWithFormat:@"rm -rf %@/* 2>/dev/null || true", quoted];
    }
    [self runCommandWithPrivileges:cmd timeoutSec:timeoutSec];
}

- (void)clearSystemLogs:(NSString *)bundleID {
    NSArray *logPaths = @[
        [NSString stringWithFormat:@"/var/mobile/Library/Logs/CrashReporter/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Logs/DiagnosticReports/%@*", bundleID],
        [NSString stringWithFormat:@"/var/log/asl/*%@*", bundleID],
        [NSString stringWithFormat:@"/var/log/system.log.*%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Logs/CrashReporter/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Logs/DiagnosticReports/%@*", bundleID]
    ];
    
    for (NSString *pattern in logPaths) {
        NSArray *matches = [self findPathsMatchingPattern:pattern];
        for (NSString *path in matches) {
            NSLog(@"[AppDataCleaner] Wiping system log: %@", path);
            [self securelyWipeFile:path];
        }
    }
}

#pragma mark - Helper Methods

- (NSArray *)listDirectoriesInPath:(NSString *)path {
    NSError *error;
    NSArray *contents = [_fileManager contentsOfDirectoryAtPath:path error:&error];
    if (error) {
        NSLog(@"[AppDataCleaner] Error listing directory %@: %@", path, error.localizedDescription);
        return @[];
    }
    return contents;
}

- (BOOL)directoryHasContent:(NSString *)path {
    if (![_fileManager fileExistsAtPath:path]) {
        NSLog(@"[AppDataCleaner] Directory does not exist: %@", path);
        return NO;
    }
    
    NSError *error;
    NSArray *contents = [_fileManager contentsOfDirectoryAtPath:path error:&error];
    
    if (error) {
        NSLog(@"[AppDataCleaner] Error reading directory %@: %@", path, error.localizedDescription);
        return NO;
    }
    
    // Filter out system files that start with .com.apple
    NSMutableArray *nonSystemFiles = [NSMutableArray array];
    for (NSString *item in contents) {
        if (![item hasPrefix:@".com.apple"]) {
            [nonSystemFiles addObject:item];
        }
    }
    
    NSLog(@"[AppDataCleaner] Directory %@ has %lu non-system files", path, (unsigned long)nonSystemFiles.count);
    if (nonSystemFiles.count > 0) {
        NSLog(@"[AppDataCleaner] First few files: %@", [nonSystemFiles subarrayWithRange:NSMakeRange(0, MIN(5, nonSystemFiles.count))]);
    }
    
    return (nonSystemFiles.count > 0);
}

- (NSArray *)findPathsMatchingPattern:(NSString *)pattern {
    NSMutableArray *paths = [NSMutableArray array];
    
    // Optimize search root: Default to /, but if pattern starts with exact path prefix, use that
    NSString *searchRoot = @"/";
    
    // Find the first wildcard char to determine static prefix
    NSRange rangeStar = [pattern rangeOfString:@"*"];
    NSRange rangeQ = [pattern rangeOfString:@"?"];
    NSRange rangeBrack = [pattern rangeOfString:@"["];
    
    NSUInteger firstWildcard = NSNotFound;
    if (rangeStar.location != NSNotFound) firstWildcard = rangeStar.location;
    if (rangeQ.location != NSNotFound && (firstWildcard == NSNotFound || rangeQ.location < firstWildcard)) firstWildcard = rangeQ.location;
    if (rangeBrack.location != NSNotFound && (firstWildcard == NSNotFound || rangeBrack.location < firstWildcard)) firstWildcard = rangeBrack.location;
    
    if (firstWildcard != NSNotFound && firstWildcard > 1) {
        // Get the path up to the last slash before the wildcard
        NSString *prefix = [pattern substringToIndex:firstWildcard];
        NSString *directory = [prefix stringByDeletingLastPathComponent];
        
        // Ensure we have a valid absolute path to start from
        if (directory.length > 1 && [directory hasPrefix:@"/"]) {
            // Check if directory exists
            BOOL isDir = NO;
            if ([[NSFileManager defaultManager] fileExistsAtPath:directory isDirectory:&isDir] && isDir) {
                searchRoot = directory;
                // NSLog(@"[AppDataCleaner] Optimized find search root: %@", searchRoot);
            }
        }
    }
    
    // Create a pipe to read command output
    int pipefds[2];
    pipe(pipefds);
    
    // Set up the find command and arguments
    pid_t pid;
    const char *findPath = "/usr/bin/find";
    const char *args[] = {
        "find",
        "-L",  // Follow symbolic links
        [searchRoot UTF8String], // Use optimized search root
        "-path",
        [pattern UTF8String],
        NULL
    };
    
    // Set up the file actions to redirect output
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, pipefds[0]);
    posix_spawn_file_actions_adddup2(&actions, pipefds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefds[1]);
    
    // Spawn the process
    int status = posix_spawn(&pid, findPath, &actions, NULL, (char *const *)args, NULL);
    
    if (status == 0) {
        // Close write end of pipe in parent
        close(pipefds[1]);
        
        // Read output from the pipe
        NSMutableData *data = [NSMutableData data];
        char buffer[1024];
        ssize_t bytesRead;
        
        while ((bytesRead = read(pipefds[0], buffer, sizeof(buffer))) > 0) {
            [data appendBytes:buffer length:bytesRead];
        }
        
        // Close read end of pipe
        close(pipefds[0]);
        
        // Wait for process to complete
        waitpid(pid, &status, 0);
        
        // Convert output to string and split into paths
        NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (output) {
            [paths addObjectsFromArray:[output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]];
        }
    }
    
    // Clean up
    posix_spawn_file_actions_destroy(&actions);
    
    // Filter out empty strings
    return [paths filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return [object isKindOfClass:[NSString class]] && [(NSString *)object length] > 0;
    }]];
}

- (void)runCommandWithPrivileges:(NSString *)command {
    [self runCommandWithPrivileges:command timeoutSec:60];
}

// Optimized: find files/dirs under root matching any basename pattern (single traversal).
- (NSArray<NSString *> *)findPathsUnderRoot:(NSString *)root
                               directories:(BOOL)directories
                              namePatterns:(NSArray<NSString *> *)namePatterns {
    if (![root isKindOfClass:[NSString class]] || root.length == 0) return @[];
    if (![namePatterns isKindOfClass:[NSArray class]] || namePatterns.count == 0) return @[];

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:root isDirectory:&isDir] || !isDir) return @[];

    NSMutableArray<NSString *> *patterns = [NSMutableArray array];
    for (id p in namePatterns) {
        if (![p isKindOfClass:[NSString class]]) continue;
        NSString *s = (NSString *)p;
        if (s.length) [patterns addObject:s];
    }
    if (patterns.count == 0) return @[];

    // Create a pipe to read command output
    int pipefds[2];
    if (pipe(pipefds) != 0) {
        return @[];
    }

    // Build argv for: find -L <root> -type f|d ( -name p1 -o -name p2 ... ) -print
    // Reserve: find -L root -type X ( -name p1 -o -name p2 ... ) -print NULL
    NSUInteger argc = 0;
    argc += 1; // find
    argc += 1; // -L
    argc += 1; // root
    argc += 2; // -type f|d
    argc += 1; // (
    argc += patterns.count * 2; // -name pat
    if (patterns.count > 1) {
        argc += (patterns.count - 1) * 1; // -o
    }
    argc += 1; // )
    argc += 1; // -print
    argc += 1; // NULL

    char **argv = (char **)calloc(argc, sizeof(char *));
    if (!argv) {
        close(pipefds[0]);
        close(pipefds[1]);
        return @[];
    }

    NSUInteger idx = 0;
    argv[idx++] = (char *)"find";
    argv[idx++] = (char *)"-L";
    argv[idx++] = (char *)[root UTF8String];
    argv[idx++] = (char *)"-type";
    argv[idx++] = (char *)(directories ? "d" : "f");
    argv[idx++] = (char *)"(";
    for (NSUInteger i = 0; i < patterns.count; i++) {
        if (i > 0) {
            argv[idx++] = (char *)"-o";
        }
        argv[idx++] = (char *)"-name";
        argv[idx++] = (char *)[patterns[i] UTF8String];
    }
    argv[idx++] = (char *)")";
    argv[idx++] = (char *)"-print";
    argv[idx++] = NULL;

    // Set up the find command and arguments
    pid_t pid = 0;
    const char *findPath = "/usr/bin/find";

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, pipefds[0]);
    posix_spawn_file_actions_adddup2(&actions, pipefds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefds[1]);

    int spawnStatus = posix_spawn(&pid, findPath, &actions, NULL, (char *const *)argv, NULL);
    posix_spawn_file_actions_destroy(&actions);
    free(argv);

    if (spawnStatus != 0 || pid <= 0) {
        close(pipefds[0]);
        close(pipefds[1]);
        return @[];
    }

    close(pipefds[1]);

    NSMutableData *data = [NSMutableData data];
    char buffer[2048];
    ssize_t bytesRead;
    while ((bytesRead = read(pipefds[0], buffer, sizeof(buffer))) > 0) {
        [data appendBytes:buffer length:(NSUInteger)bytesRead];
    }
    close(pipefds[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!output.length) return @[];

    NSArray *parts = [output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSPredicate *pred = [NSPredicate predicateWithBlock:^BOOL(id obj, NSDictionary *bindings) {
        (void)bindings;
        return [obj isKindOfClass:[NSString class]] && [(NSString *)obj length] > 0;
    }];
    return [parts filteredArrayUsingPredicate:pred];
}

- (void)runCommandWithPrivileges:(NSString *)command timeoutSec:(int)timeoutSec {
    if (![command isKindOfClass:[NSString class]] || command.length == 0) {
        return;
    }
#ifdef PROJECTX_TROLLSTORE
    NSError *routerError = nil;
    if (![[PXShellRouter sharedRouter] runShellCommand:command error:&routerError]) {
        NSLog(@"[AppDataCleaner] Command router failed: %@ | command=%@", routerError.localizedDescription, command);
    }
#else
    if (timeoutSec <= 0) {
        timeoutSec = 60;
    }

    pid_t pid;
    const char *args[] = {"/bin/sh", "-c", [command UTF8String], NULL};
    int spawnResult = posix_spawn(&pid, args[0], NULL, NULL, (char * const *)args, NULL);
    if (spawnResult != 0) {
        return;
    }

    (void)setpgid(pid, pid);

    const int maxWaitIterations = timeoutSec * 10;
    int iterations = 0;
    int status = 0;

    while (iterations < maxWaitIterations) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid || result == -1) {
            return;
        }
        usleep(100000);
        iterations++;
    }

    NSString *shortCmd = command;
    if (shortCmd.length > 240) {
        shortCmd = [shortCmd substringToIndex:240];
    }
    NSLog(@"[AppDataCleaner] Command timed out after %d sec, killing: %@", timeoutSec, shortCmd);

    kill(-pid, SIGTERM);
    usleep(250000);
    kill(-pid, SIGKILL);
    waitpid(pid, &status, 0);
#endif
}

- (BOOL)verifyDataCleared:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Verifying data cleared for %@", bundleID);
    
    // Create an array to store paths that weren't cleared properly
    NSMutableArray *unclearedPaths = [NSMutableArray array];
    
    // 1. Verify app data container is cleared
    NSString *dataContainerUUID = [self findDataContainerUUID:bundleID];
    if (dataContainerUUID) {
        NSString *dataContainerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", dataContainerUUID];
        [self verifyClearedPath:dataContainerPath reportingTo:unclearedPaths];
    }
    
    // 2. Verify bundle container
    NSString *bundleContainerUUID = [self findBundleContainerUUID:bundleID];
    if (bundleContainerUUID) {
        NSString *bundleContainerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Bundle/Application/%@", bundleContainerUUID];
        [self verifyClearedPath:bundleContainerPath reportingTo:unclearedPaths];
    }
    
    // 3. Verify group containers
    NSArray *groupContainerUUIDs = [self findGroupContainerUUIDsForBundleID:bundleID];
    for (NSString *groupUUID in groupContainerUUIDs) {
        NSString *groupContainerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", groupUUID];
        [self verifyClearedPath:groupContainerPath reportingTo:unclearedPaths];
    }
    
    // 4. Verify extension containers
    NSArray *extensionDataUUIDs = [self findExtensionDataContainersForBundleID:bundleID];
    for (NSString *extensionUUID in extensionDataUUIDs) {
        NSString *extensionPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", extensionUUID];
        [self verifyClearedPath:extensionPath reportingTo:unclearedPaths];
    }
    
    // 5. Verify system paths
    NSArray *systemPaths = @[
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/%@", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Cookies/%@.binarycookies", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Application Support/%@", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/SpringBoard/ApplicationState/%@.plist", bundleID]
    ];
    
    for (NSString *path in systemPaths) {
        if ([_fileManager fileExistsAtPath:path]) {
            [unclearedPaths addObject:@{
                @"path": path,
                @"info": @"System path still exists"
            }];
        }
    }
    
    // 6. Verify keychain items
    if ([self hasKeychainItemsForBundleID:bundleID]) {
        [unclearedPaths addObject:@{
            @"path": @"Keychain",
            @"info": @"Keychain still contains items for this bundle ID"
        }];
    }
    
    // 7. Filter out special paths and expected system-created directories before reporting
    NSMutableArray *filteredPaths = [NSMutableArray array];
    for (NSDictionary *item in unclearedPaths) {
        NSString *path = item[@"path"];
        NSString *info = item[@"info"];
        
        // Skip SiriAnalytics.db which we've specially cleaned
        if ([path containsString:@"SiriAnalytics.db"]) {
            continue;
        }
        
        // Skip IconState.plist which we've specially cleaned
        if ([path containsString:@"IconState.plist"]) {
            continue;
        }
        
        // Skip app container paths that only contain system directories
        if ([path containsString:@"/var/mobile/Containers/Data/Application"] && 
            ([info containsString:@"StoreKit"] || 
             [info containsString:@"Directory has 0 non-system files"] ||
             [info containsString:@"Directory has 1 non-system files: Documents"] ||
             [info containsString:@"Directory has 2 non-system files: Documents, Library"] ||
             [info containsString:@"Directory has 3 non-system files: Documents, Library, tmp"] ||
             [info containsString:@"Directory has 4 non-system files: StoreKit, Documents, Library, tmp"])) {
            continue;
        }
        
        [filteredPaths addObject:item];
    }
    
    // 8. Final verification summary
    if (filteredPaths.count > 0) {
        NSLog(@"[AppDataCleaner] ⚠️ WARNING: Verification found %lu uncleared data paths:", (unsigned long)filteredPaths.count);
        for (NSDictionary *item in filteredPaths) {
            NSLog(@"[AppDataCleaner] - UNCLEARED: %@ (%@)", item[@"path"], item[@"info"]);
        }
        return NO;
    } else {
        NSLog(@"[AppDataCleaner] ✅ All data successfully cleared for %@", bundleID);
        return YES;
    }
}

// Helper method to verify a path is properly cleaned
- (void)verifyClearedPath:(NSString *)path reportingTo:(NSMutableArray *)unclearedPaths {
    if (![_fileManager fileExistsAtPath:path]) {
        return; // Path doesn't exist, so it's clean
    }
    
    // Check if it's a directory
    BOOL isDirectory = NO;
    [_fileManager fileExistsAtPath:path isDirectory:&isDirectory];
    
    if (isDirectory) {
        NSError *error;
        NSArray *contents = [_fileManager contentsOfDirectoryAtPath:path error:&error];
        
        if (error) {
            [unclearedPaths addObject:@{
                @"path": path,
                @"info": [NSString stringWithFormat:@"Error listing directory: %@", error.localizedDescription]
            }];
            return;
        }
        
        NSMutableArray *nonSystemFiles = [NSMutableArray array];
        
        for (NSString *item in contents) {
            // Skip system metadata files and empty system-created directories
            if ([item hasPrefix:@".com.apple"] || 
                [item isEqualToString:@"StoreKit"] || 
                [item isEqualToString:@"Documents"] || 
                [item isEqualToString:@"Library"] || 
                [item isEqualToString:@"tmp"]) {
                continue;
            }
            
            NSString *fullPath = [path stringByAppendingPathComponent:item];
            BOOL itemIsDirectory = NO;
            [_fileManager fileExistsAtPath:fullPath isDirectory:&itemIsDirectory];
            
            // Check if it's an empty directory (system created)
            if (itemIsDirectory) {
                NSArray *subContents = [_fileManager contentsOfDirectoryAtPath:fullPath error:nil];
                if (subContents.count == 0 || [self containsOnlySystemFiles:subContents]) {
                    continue; // Skip empty directories or directories with only system files
                }
            }
            
            [nonSystemFiles addObject:item];
        }
        
        if (nonSystemFiles.count > 0) {
            // Directory has non-system files
            NSString *infoString = [NSString stringWithFormat:@"Directory has %lu non-system files: %@", 
                                   (unsigned long)nonSystemFiles.count, 
                                   [nonSystemFiles count] > 4 ? 
                                   [[nonSystemFiles subarrayWithRange:NSMakeRange(0, MIN(4, nonSystemFiles.count))] componentsJoinedByString:@", "] : 
                                   [nonSystemFiles componentsJoinedByString:@", "]];
            
            [unclearedPaths addObject:@{
                @"path": path,
                @"info": infoString
            }];
        }
    } else {
        // It's a file, report it
        [unclearedPaths addObject:@{
            @"path": path,
            @"info": @"File exists"
        }];
    }
}

// Helper to check if an array contains only system files
- (BOOL)containsOnlySystemFiles:(NSArray *)files {
    for (NSString *file in files) {
        if (![file hasPrefix:@".com.apple"]) {
            return NO;
        }
    }
    return YES;
}

// Verify keychain items are properly cleared
- (void)verifyKeychainClearedForBundleID:(NSString *)bundleID reportingTo:(NSMutableArray *)unclearedPaths {
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];
    
    for (id secClass in secClasses) {
        NSDictionary *query = @{
            (__bridge id)kSecClass: secClass,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
        };
        
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        
        if (status == errSecSuccess && result != NULL) {
            NSArray *items = (__bridge_transfer NSArray *)result;
            
            for (NSDictionary *item in items) {
                NSString *service = item[(__bridge id)kSecAttrService];
                NSString *account = item[(__bridge id)kSecAttrAccount];
                NSString *accessGroup = item[(__bridge id)kSecAttrAccessGroup];
                NSString *label = item[(__bridge id)kSecAttrLabel];
                
                // Check for any keychain items related to our bundle ID
                if (([service containsString:bundleID]) ||
                    ([account containsString:bundleID]) ||
                    ([accessGroup containsString:bundleID]) ||
                    ([label containsString:bundleID])) {
                    
                    [unclearedPaths addObject:@{
                        @"path": @"Keychain",
                        @"info": [NSString stringWithFormat:@"Item still exists: service=%@, account=%@, group=%@, label=%@",
                                 service ?: @"nil", account ?: @"nil", accessGroup ?: @"nil", label ?: @"nil"]
                    }];
                }
                
                // Also check component matches (like "uber" from "com.ubercab.UberClient")
                NSArray *components = [bundleID componentsSeparatedByString:@"."];
                for (NSString *component in components) {
                    if (component.length > 3 && ![component isEqualToString:@"com"] && 
                        ![component isEqualToString:@"org"] && ![component isEqualToString:@"net"]) {
                        
                        if (([service containsString:component]) ||
                            ([account containsString:component]) ||
                            ([accessGroup containsString:component]) ||
                            ([label containsString:component])) {
                            
                            [unclearedPaths addObject:@{
                                @"path": @"Keychain",
                                @"info": [NSString stringWithFormat:@"Item with component '%@' still exists: service=%@, account=%@, group=%@, label=%@",
                                         component, service ?: @"nil", account ?: @"nil", accessGroup ?: @"nil", label ?: @"nil"]
                            }];
                        }
                    }
                }
            }
        }
    }
}

// Verify SQLite databases don't have references to the app
- (void)verifySQLiteReferencesCleared:(NSString *)bundleID reportingTo:(NSMutableArray *)unclearedPaths {
    NSArray *systemDBs = @[
        @"/var/mobile/Library/SpringBoard/ApplicationHistory.sqlite",
        @"/var/mobile/Library/Assistant/SiriAnalytics.db",
        @"/var/mobile/Library/SpringBoard/IconState.plist"
    ];
    
    for (NSString *dbPath in systemDBs) {
        if ([_fileManager fileExistsAtPath:dbPath]) {
            // For plist files
            if ([dbPath hasSuffix:@".plist"]) {
                NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:dbPath];
                NSString *plistStr = [plist description];
                
                if ([plistStr containsString:bundleID]) {
                    [unclearedPaths addObject:@{
                        @"path": dbPath,
                        @"info": @"Plist still contains references to app"
                    }];
                }
            }
            // For SQLite we'll just mark the file for manual inspection
            else if ([dbPath hasSuffix:@".sqlite"] || [dbPath hasSuffix:@".db"]) {
                // We can't easily check SQLite content without sqlite3 libraries
                // So we'll just report these files for manual inspection
                [unclearedPaths addObject:@{
                    @"path": dbPath,
                    @"info": @"SQLite database requires manual inspection"
                }];
            }
        }
    }
}

// Helper to run a command and get its output
- (NSString *)runCommandAndGetOutput:(NSString *)command {
    NSLog(@"[AppDataCleaner] Running command: %@", command);
    
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/sh"];
    [task setArguments:@[@"-c", command]];
    
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    [task setStandardError:pipe];
    
    NSFileHandle *file = [pipe fileHandleForReading];
    
    @try {
        [task launch];
        [task waitUntilExit];
        
        NSData *data = [file readDataToEndOfFile];
        NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        
        // Trim whitespace from output
        output = [output stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        return output;
    } @catch (NSException *exception) {
        NSLog(@"[AppDataCleaner] Error running command: %@", exception);
        return @"error";
    } @finally {
        [file closeFile];
    }
}

#pragma mark - Public Header Methods

- (BOOL)hasDataToClear:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Checking for data to clear for %@", bundleID);
    
    // Force system to flush pending disk operations
    [self runCommandWithPrivileges:@"sync"];
    
    // Check if there's any data to clear for this bundle ID
    NSString *appDataUUID = [self findDataContainerUUID:bundleID];
    NSString *rootlessDataUUID = [self findRootlessDataContainerUUID:bundleID];
    NSArray *appGroupUUIDs = [self findAppGroupUUIDs:bundleID];
    NSArray *rootlessGroupUUIDs = [self findRootlessAppGroupUUIDs:bundleID];
    
    NSLog(@"[AppDataCleaner] Found UUIDs - Data: %@, Rootless: %@, Groups: %@, Rootless Groups: %@", 
          appDataUUID ?: @"Not found", 
          rootlessDataUUID ?: @"Not found", 
          appGroupUUIDs, 
          rootlessGroupUUIDs);
    
    // IMPROVEMENT: If we found any containers at all, assume there's data to clear
    // This avoids the "no data" message when containers exist but appear empty
    if (appDataUUID || rootlessDataUUID || appGroupUUIDs.count > 0 || rootlessGroupUUIDs.count > 0) {
        NSLog(@"[AppDataCleaner] Found containers - assuming app has data to clear");
        
        // Calculate usage for UI display
        NSDictionary *usage = [self getDataUsage:bundleID];
        
        // Store this information in UserDefaults for the ProjectXViewController to access
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:usage forKey:[NSString stringWithFormat:@"DataUsage_%@", bundleID]];
        [defaults synchronize];
        
        return YES;
    }
    
    BOOL hasData = NO;
    
    // Standard data container checks - more aggressive
    if (appDataUUID) {
        NSString *containerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", appDataUUID];
        if ([self directoryExistsAndHasAnyContent:containerPath]) {
            NSLog(@"[AppDataCleaner] Found data in application container: %@", containerPath);
            hasData = YES;
        }
    }
    
    // Rootless data container - more aggressive
    if (rootlessDataUUID) {
        NSString *containerPath = [NSString stringWithFormat:@"/containers/Data/Application/%@", rootlessDataUUID];
        if ([self directoryExistsAndHasAnyContent:containerPath]) {
            NSLog(@"[AppDataCleaner] Found data in rootless application container: %@", containerPath);
            hasData = YES;
        }
    }
    
    // App groups - check entire container, not just top level
    for (NSString *groupUUID in appGroupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", groupUUID];
        if ([self directoryExistsAndHasAnyContent:groupPath]) {
            NSLog(@"[AppDataCleaner] Found data in App Group: %@", groupPath);
            hasData = YES;
        }
    }
    
    // Rootless app groups - check entire container
    for (NSString *groupUUID in rootlessGroupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/containers/Shared/AppGroup/%@", groupUUID];
        if ([self directoryExistsAndHasAnyContent:groupPath]) {
            NSLog(@"[AppDataCleaner] Found data in rootless App Group: %@", groupPath);
            hasData = YES;
        }
    }
    
    // Check preferences
    NSString *prefsPath = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID];
    if ([_fileManager fileExistsAtPath:prefsPath]) {
        NSLog(@"[AppDataCleaner] Found preference file: %@", prefsPath);
        hasData = YES;
    }
    
    // Check rootless preferences
    NSString *rootlessPrefsPath = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID];
    if ([_fileManager fileExistsAtPath:rootlessPrefsPath]) {
        NSLog(@"[AppDataCleaner] Found rootless preference file: %@", rootlessPrefsPath);
        hasData = YES;
    }
    
    // NEW: Check for keychain items even if no files found
    if (!hasData && [self hasKeychainItemsForBundleID:bundleID]) {
        NSLog(@"[AppDataCleaner] Found keychain items for %@", bundleID);
        hasData = YES;
    }
    
    // NEW: Check for system database references as a last resort
    if (!hasData) {
        if ([self hasSystemDatabaseReferencesForBundleID:bundleID]) {
            NSLog(@"[AppDataCleaner] Found system database references for %@", bundleID);
            hasData = YES;
        }
    }
    
    // If we have data, calculate size for UI display
    if (hasData) {
        NSDictionary *usage = [self getDataUsage:bundleID];
        
        // Store this information in UserDefaults for the ProjectXViewController to access
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:usage forKey:[NSString stringWithFormat:@"DataUsage_%@", bundleID]];
        [defaults synchronize];
    } else {
        NSLog(@"[AppDataCleaner] No data found to clear for %@", bundleID);
    }
    
    return hasData;
}

// --- Optimized lookup helpers (local to this file, do not break existing API) ---

- (NSString *)optimized_findDataContainerUUID:(NSString *)bundleID inDirectories:(NSArray *)dataDirs {
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *company = parts.count > 1 ? parts[1] : @"";
    NSString *shortName = parts.lastObject;
    __block NSString *result = nil;
    dispatch_apply(dataDirs.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        if (result) return;
        NSString *uuid = dataDirs[i];
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        if ([containerBundleID isEqualToString:bundleID]) { result = uuid; return; }
        // Aggressive/fuzzy matching
        if ([containerBundleID containsString:bundleID] ||
            (company.length && [containerBundleID containsString:company]) ||
            (shortName.length && [containerBundleID containsString:shortName])) {
            result = uuid; return;
        }
        // Scan for app-named files/dirs (first match wins)
        NSString *containerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", uuid];
        NSArray *contents = [self listDirectoriesInPath:containerPath];
        for (NSString *item in contents) {
            if (([item containsString:bundleID] ||
                 (company.length && [item containsString:company]) ||
                 (shortName.length && [item containsString:shortName]))) {
                result = uuid; return;
            }
        }
    });
    return result;
}

- (NSString *)optimized_findRootlessDataContainerUUID:(NSString *)bundleID inDirectories:(NSArray *)dataDirs {
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *company = parts.count > 1 ? parts[1] : @"";
    NSString *shortName = parts.lastObject;
    __block NSString *result = nil;
    dispatch_apply(dataDirs.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        if (result) return;
        NSString *uuid = dataDirs[i];
        NSString *metadataPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        if ([containerBundleID isEqualToString:bundleID]) { result = uuid; return; }
        if ([containerBundleID containsString:bundleID] ||
            (company.length && [containerBundleID containsString:company]) ||
            (shortName.length && [containerBundleID containsString:shortName])) {
            result = uuid; return;
        }
        NSString *containerPath = [NSString stringWithFormat:@"/containers/Data/Application/%@", uuid];
        NSArray *contents = [self listDirectoriesInPath:containerPath];
        for (NSString *item in contents) {
            if (([item containsString:bundleID] ||
                 (company.length && [item containsString:company]) ||
                 (shortName.length && [item containsString:shortName]))) {
                result = uuid; return;
            }
        }
    });
    return result;
}

- (NSArray *)optimized_findAppGroupUUIDs:(NSString *)bundleID inDirectories:(NSArray *)groupDirs {
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *company = parts.count > 1 ? parts[1] : @"";
    NSString *shortName = parts.lastObject;
    NSMutableArray *groupUUIDs = [NSMutableArray array];
    
    dispatch_apply(groupDirs.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        NSString *uuid = groupDirs[i];
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        id groupIdentifier = metadata[@"MCMMetadataIdentifier"];
        BOOL matched = NO;
        if ([groupIdentifier isKindOfClass:[NSArray class]]) {
            if ([(NSArray *)groupIdentifier containsObject:bundleID]) matched = YES;
        } else if ([groupIdentifier isKindOfClass:[NSString class]]) {
            if ([(NSString *)groupIdentifier containsString:bundleID]) matched = YES;
        }
        if (!matched) {
            // Fuzzy
            if (([groupIdentifier isKindOfClass:[NSString class]] &&
                 ((company.length && [groupIdentifier containsString:company]) ||
                  (shortName.length && [groupIdentifier containsString:shortName])))) matched = YES;
            else {
                // Scan for files/dirs
                NSString *containerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", uuid];
                NSArray *contents = [self listDirectoriesInPath:containerPath];
                for (NSString *item in contents) {
                    if (([item containsString:bundleID] ||
                         (company.length && [item containsString:company]) ||
                         (shortName.length && [item containsString:shortName]))) {
                        matched = YES; break;
                    }
                }
            }
        }
        if (matched) @synchronized(groupUUIDs) { [groupUUIDs addObject:uuid]; }
    });
    return groupUUIDs;
}

- (NSString *)optimized_findBundleContainerUUID:(NSString *)bundleID inDirectories:(NSArray *)bundleDirs rootlessDirs:(NSArray *)rootlessDirs {
    __block NSString *result = nil;
    // Standard
    dispatch_apply(bundleDirs.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        if (result) return;
        NSString *uuid = bundleDirs[i];
        NSString *appPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@", uuid];
        NSArray *appContents = [self listDirectoriesInPath:appPath];
        for (NSString *item in appContents) {
            if ([item hasSuffix:@".app"]) {
                NSString *infoPlistPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@/%@/Info.plist", uuid, item];
                NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                if ([itemBundleID isEqualToString:bundleID]) { result = uuid; return; }
            }
        }
    });
    if (result) return result;
    // Rootless
    dispatch_apply(rootlessDirs.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        if (result) return;
        NSString *uuid = rootlessDirs[i];
        NSString *appPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@", uuid];
        NSArray *appContents = [self listDirectoriesInPath:appPath];
        for (NSString *item in appContents) {
            if ([item hasSuffix:@".app"]) {
                NSString *infoPlistPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@/%@/Info.plist", uuid, item];
                NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                if ([itemBundleID isEqualToString:bundleID]) { result = uuid; return; }
            }
        }
    });
    return result;
}

- (NSArray *)optimized_findExtensionContainers:(NSString *)bundleID dataDirs:(NSArray *)dataDirs rootlessDataDirs:(NSArray *)rootlessDataDirs bundleDirs:(NSArray *)bundleDirs rootlessBundleDirs:(NSArray *)rootlessBundleDirs {
    NSMutableArray *extensionInfo = [NSMutableArray array];
    // 1. Find extension data containers by checking metadata files (standard)
    dispatch_apply(dataDirs.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        NSString *uuid = dataDirs[i];
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        if (containerBundleID && [containerBundleID hasPrefix:bundleID] && ![containerBundleID isEqualToString:bundleID]) {
            // Find bundle UUID for extension
            NSString *extBundleUUID = [self optimized_findBundleContainerUUID:containerBundleID inDirectories:bundleDirs rootlessDirs:rootlessBundleDirs];
            @synchronized(extensionInfo) {
                [extensionInfo addObject:@{ @"bundleID": containerBundleID, @"dataUUID": uuid, @"bundleUUID": extBundleUUID ?: @"", @"type": @"extension" }];
            }
        }
    });
    // Rootless
    dispatch_apply(rootlessDataDirs.count, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t i) {
        NSString *uuid = rootlessDataDirs[i];
        NSString *metadataPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        if (containerBundleID && [containerBundleID hasPrefix:bundleID] && ![containerBundleID isEqualToString:bundleID]) {
            NSString *extBundleUUID = [self optimized_findBundleContainerUUID:containerBundleID inDirectories:bundleDirs rootlessDirs:rootlessBundleDirs];
            @synchronized(extensionInfo) {
                [extensionInfo addObject:@{ @"bundleID": containerBundleID, @"dataUUID": uuid, @"bundleUUID": extBundleUUID ?: @"", @"type": @"extension", @"rootless": @YES }];
            }
        }
    });
    return extensionInfo;
}

// Helper method to create human-readable file sizes
- (NSString *)humanReadableFileSize:(long long)size {
    NSByteCountFormatter *formatter = [[NSByteCountFormatter alloc] init];
    formatter.countStyle = NSByteCountFormatterCountStyleFile;
    return [formatter stringFromByteCount:size];
}

// Implementation of helper methods that map to the main cleaning function
- (void)performFullCleanup:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Starting full cleanup for %@", bundleID);

    // First clear app state data which stores login sessions
    [self _internalClearAppStateData:bundleID];
    
    // Get UUIDs for containers
    NSString *dataUUID = [self findDataContainerUUID:bundleID];
    NSString *rootlessDataUUID = [self findRootlessDataContainerUUID:bundleID];
    NSString *bundleUUID = [self findBundleContainerUUID:bundleID];
    
    NSLog(@"[AppDataCleaner] Found UUIDs - Data: %@, Rootless: %@, Bundle: %@", 
          dataUUID ?: @"Not found", rootlessDataUUID ?: @"Not found", bundleUUID ?: @"Not found");
    
    // Clear standard data container 
    [self completelyWipeContainer:[NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", dataUUID]];
    [self completelyWipeContainer:[NSString stringWithFormat:@"/containers/Data/Application/%@", rootlessDataUUID]];
    
    // Clear all kinds of user data
    {
        NSError *kcErr = nil;
        if (![self _wipeSelectedKeychainForBundleID:bundleID error:&kcErr]) {
            [self logMessage:@"[AppDataCleaner] WARNING: Keychain wipe failed in performFullCleanup: %@", kcErr.localizedDescription ?: @"unknown"];
        }
    }
    [self clearURLCredentialsForBundleID:bundleID];
    [self clearICloudData:bundleID];
    [self clearPluginKitData:bundleID];
    [self clearThumbnailCaches:bundleID];
    [self clearSystemLogs:bundleID];
    // [self cleanAppGroupContainers:bundleID]; // Disabled - now handled directly in completeAppDataWipe
    [self clearAppReceiptData:bundleID withBundleUUID:bundleUUID];
    [self clearPushNotificationData:bundleID];
    [self clearBluetoothData:bundleID];
    
    // Clear app settings
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Preferences/%@*", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Preferences/%@*", bundleID]];
    
    // Clear encrypted data
    [self _internalClearEncryptedData:bundleID];
    
    // Process iOS 15+ specific issues
    [self clearAppIssuesForIOS15:bundleID];
    
    // NEW: Run app-specific deep cleaning for ride-sharing & food delivery
    
    // Refresh system services to ensure changes are applied
    [self refreshSystemServices];
}

- (void)performSecondaryCleanup:(NSString *)bundleID {
    [self completeAppDataWipe:bundleID];
}

// Implementation of specialized cleanup methods
- (void)clearAppData:(NSString *)bundleID {
    [self completeAppDataWipe:bundleID];
}

- (void)clearAppCache:(NSString *)bundleID {
    NSString *appDataUUID = [self findDataContainerUUID:bundleID];
    NSString *rootlessDataUUID = [self findRootlessDataContainerUUID:bundleID];
    
    if (appDataUUID) {
        NSString *cachePath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/Library/Caches", appDataUUID];
        [self wipeDirectoryContents:cachePath keepDirectoryStructure:YES];
    }
    
    if (rootlessDataUUID) {
        NSString *cachePath = [NSString stringWithFormat:@"/containers/Data/Application/%@/Library/Caches", rootlessDataUUID];
        [self wipeDirectoryContents:cachePath keepDirectoryStructure:YES];
    }
    
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Caches/%@*", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/Caches/%@*", bundleID]];
}

- (void)clearAppPreferences:(NSString *)bundleID {
    NSString *appDataUUID = [self findDataContainerUUID:bundleID];
    NSString *rootlessDataUUID = [self findRootlessDataContainerUUID:bundleID];
    
    if (appDataUUID) {
        NSString *prefsPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/Library/Preferences", appDataUUID];
        [self wipeDirectoryContents:prefsPath keepDirectoryStructure:YES];
    }
    
    if (rootlessDataUUID) {
        NSString *prefsPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/Library/Preferences", rootlessDataUUID];
        [self wipeDirectoryContents:prefsPath keepDirectoryStructure:YES];
    }
    
    [self securelyWipeFile:[NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID]];
    [self securelyWipeFile:[NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID]];
}

- (void)clearAppCookies:(NSString *)bundleID {
    NSString *appDataUUID = [self findDataContainerUUID:bundleID];
    NSString *rootlessDataUUID = [self findRootlessDataContainerUUID:bundleID];
    
    if (appDataUUID) {
        NSString *cookiesPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/Library/Cookies", appDataUUID];
        [self wipeDirectoryContents:cookiesPath keepDirectoryStructure:YES];
    }
    
    if (rootlessDataUUID) {
        NSString *cookiesPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/Library/Cookies", rootlessDataUUID];
        [self wipeDirectoryContents:cookiesPath keepDirectoryStructure:YES];
    }
    
    [self securelyWipeFile:[NSString stringWithFormat:@"/var/mobile/Library/Cookies/%@.binarycookies", bundleID]];
    [self securelyWipeFile:[NSString stringWithFormat:@"/var/mobile/Library/Cookies/%@.binarycookies", bundleID]];
}

- (void)clearAppWebKitData:(NSString *)bundleID {
    NSString *appDataUUID = [self findDataContainerUUID:bundleID];
    NSString *rootlessDataUUID = [self findRootlessDataContainerUUID:bundleID];
    
    if (appDataUUID) {
        NSString *webkitPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/Library/WebKit", appDataUUID];
        [self wipeDirectoryContents:webkitPath keepDirectoryStructure:YES];
    }
    
    if (rootlessDataUUID) {
        NSString *webkitPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/Library/WebKit", rootlessDataUUID];
        [self wipeDirectoryContents:webkitPath keepDirectoryStructure:YES];
    }
    
    [self securelyWipeFile:[NSString stringWithFormat:@"/var/mobile/Library/WebKit/WebsiteData/*/%@", bundleID]];
    [self securelyWipeFile:[NSString stringWithFormat:@"/var/mobile/Library/WebKit/WebsiteData/*/%@", bundleID]];
}

- (void)clearAppKeychain:(NSString *)bundleID {
    NSError *kcErr = nil;
    if (![self _wipeSelectedKeychainForBundleID:bundleID error:&kcErr]) {
        [self logMessage:@"[AppDataCleaner] WARNING: Keychain wipe failed: %@", kcErr.localizedDescription ?: @"unknown"];
    }
}

- (void)clearAppGroupData:(NSString *)bundleID {
    NSArray *appGroupUUIDs = [self findAppGroupUUIDs:bundleID];
    NSArray *rootlessGroupUUIDs = [self findRootlessAppGroupUUIDs:bundleID];
    
    for (NSString *groupUUID in appGroupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", groupUUID];
        [self wipeDirectoryContents:groupPath keepDirectoryStructure:YES];
    }
    
    for (NSString *groupUUID in rootlessGroupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/containers/Shared/AppGroup/%@", groupUUID];
        [self wipeDirectoryContents:groupPath keepDirectoryStructure:YES];
    }
}

// Map the remaining methods to the main function
- (void)clearKeychainData:(NSString *)bundleID {
    NSError *kcErr = nil;
    if (![self _wipeSelectedKeychainForBundleID:bundleID error:&kcErr]) {
        [self logMessage:@"[AppDataCleaner] WARNING: Keychain wipe failed: %@", kcErr.localizedDescription ?: @"unknown"];
    }
}
- (void)clearSharedContainers:(NSString *)bundleID { [self clearAppGroupData:bundleID]; }
- (void)clearUserDefaults:(NSString *)bundleID { [self clearAppPreferences:bundleID]; }
- (void)clearSQLiteDatabases:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearPrivateVarData:(NSString *)bundleID { [self cleanRootHideVarData:bundleID]; }
- (void)clearDeviceDatabase:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearInstallationLogs:(NSString *)bundleID { [self clearSystemLogs:bundleID]; }
- (void)clearNetworkConfigurations:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearCarrierData:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearNetworkData:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearDNSCache:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearCrashReports:(NSString *)bundleID { [self clearSystemLogs:bundleID]; }
- (void)clearDiagnosticData:(NSString *)bundleID { [self clearSystemLogs:bundleID]; }
- (void)clearBluetoothData:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearPushNotificationData:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearThumbnailCache:(NSString *)bundleID { [self clearThumbnailCaches:bundleID]; }
- (void)clearWebCache:(NSString *)bundleID { [self clearAppWebKitData:bundleID]; }
- (void)clearGameData:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearTemporaryFiles:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearBinaryPlists:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearEncryptedData:(NSString *)bundleID { 
    [self _internalClearEncryptedData:bundleID];
}
- (void)clearJailbreakDetectionLogs:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearSpotlightData:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearSiriData:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearSystemLoggerData:(NSString *)bundleID { [self clearSystemLogs:bundleID]; }
- (void)clearASLLogs:(NSString *)bundleID { [self clearSystemLogs:bundleID]; }
- (void)clearClipboard { 
    UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
    [pasteboard setItems:@[]];
}
- (void)clearPasteboardData:(NSString *)bundleID { [self clearClipboard]; }
- (void)clearURLCache:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearBackgroundAssets:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearSharedStorage:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }
- (void)clearAppStateData:(NSString *)bundleID {
    [self _internalClearAppStateData:bundleID];
}
- (void)secureDataWipe:(NSString *)bundleID { [self completeAppDataWipe:bundleID]; }

- (NSDictionary *)getDataUsage:(NSString *)bundleID {
    NSMutableDictionary *usage = [NSMutableDictionary dictionary];
    
    // Calculate app data usage
    NSString *appDataUUID = [self findDataContainerUUID:bundleID];
    if (appDataUUID) {
        NSString *dataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", appDataUUID];
        usage[@"dataSize"] = @([self calculateDirectorySize:dataPath]);
    }
    
    // Calculate app bundle size
    NSString *bundleUUID = [self findBundleUUID:bundleID];
    if (bundleUUID) {
        NSString *bundlePath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@", bundleUUID];
        usage[@"bundleSize"] = @([self calculateDirectorySize:bundlePath]);
    }
    
    // Calculate shared data size
    NSArray *appGroupUUIDs = [self findAppGroupUUIDs:bundleID];
    long long sharedSize = 0;
    for (NSString *groupUUID in appGroupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", groupUUID];
        sharedSize += [self calculateDirectorySize:groupPath];
    }
    usage[@"sharedSize"] = @(sharedSize);
    
    // Total size
    long long total = [usage[@"dataSize"] longLongValue] + 
                    [usage[@"bundleSize"] longLongValue] + 
                    [usage[@"sharedSize"] longLongValue];
    usage[@"totalSize"] = @(total);
    
    return usage;
}

// Helper method for getDataUsage
- (long long)calculateDirectorySize:(NSString *)path {
    if (![_fileManager fileExistsAtPath:path]) {
        return 0;
    }
    
    NSError *error = nil;
    NSDictionary *attributes = [_fileManager attributesOfItemAtPath:path error:&error];
    if (error) {
        return 0;
    }
    
    if ([attributes[NSFileType] isEqualToString:NSFileTypeRegular]) {
        return [attributes[NSFileSize] longLongValue];
    }
    
    NSArray *contents = [_fileManager contentsOfDirectoryAtPath:path error:&error];
    if (error) {
        return 0;
    }
    
    long long size = 0;
    for (NSString *item in contents) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        NSDictionary *itemAttribs = [_fileManager attributesOfItemAtPath:fullPath error:&error];
        if (error) {
            continue;
        }
        
        if ([itemAttribs[NSFileType] isEqualToString:NSFileTypeDirectory]) {
            size += [self calculateDirectorySize:fullPath];
        } else {
            size += [itemAttribs[NSFileSize] longLongValue];
        }
    }
    
    return size;
}

// Add a specialized method for WebKit directories to handle the recursion issues
- (void)wipeWebKitDirectoryContents:(NSString *)path {
    if (![_fileManager fileExistsAtPath:path]) {
        return;
    }
    
    NSLog(@"[AppDataCleaner] Using specialized WebKit cleaning for: %@", path);
    
    // 1. First fix permissions at root level
    NSString *permissionCommand = [NSString stringWithFormat:@"chmod -R 777 '%@' 2>/dev/null || true", path];
    [self runCommandWithPrivileges:permissionCommand];
    
    // 2. Create a separate process to clean WebKit with appropriate permissions
    NSString *command = [NSString stringWithFormat:@"rm -rf '%@'/* 2>/dev/null", path];
    [self runCommandWithPrivileges:command];
    
    // 3. Specifically target WebsiteData subdirectory with all storage types
    NSString *websiteDataPath = [path stringByAppendingPathComponent:@"WebsiteData"];
    if ([_fileManager fileExistsAtPath:websiteDataPath]) {
        NSLog(@"[AppDataCleaner] Deep cleaning WebsiteData at: %@", websiteDataPath);
        
        // Use find command to handle any nested storage structure (more robust)
        NSString *command = [NSString stringWithFormat:@"find '%@' -mindepth 1 -maxdepth 1 -not -name '.com.apple*' -exec rm -rf {} \\; 2>/dev/null", websiteDataPath];
        [self runCommandWithPrivileges:command];
        
        // Recreate standard WebKit storage directories to avoid crashes
        NSArray *webStorageDirs = @[
            @"LocalStorage",
            @"IndexedDB",
            @"WebSQL",
            @"ServiceWorkers",
            @"CacheStorage"
        ];
        
        for (NSString *dir in webStorageDirs) {
            NSString *dirPath = [websiteDataPath stringByAppendingPathComponent:dir];
            [_fileManager createDirectoryAtPath:dirPath 
                    withIntermediateDirectories:YES 
                                     attributes:nil 
                                          error:nil];
        }
    }
    
    // 4. Forcefully remove LocalStorage (often contains auth tokens)
    NSString *localStoragePath = [websiteDataPath stringByAppendingPathComponent:@"LocalStorage"];
    command = [NSString stringWithFormat:@"find '%@' -type f -exec rm -f {} \\; 2>/dev/null", localStoragePath];
    [self runCommandWithPrivileges:command];
    
    // 5. Specific handling for IndexedDB to ensure we catch all nested structures
    NSString *indexedDBPath = [websiteDataPath stringByAppendingPathComponent:@"IndexedDB"];
    NSLog(@"[AppDataCleaner] Deep cleaning IndexedDB at: %@", indexedDBPath);
    
    // Use find with greater depth to catch all nested structure
    command = [NSString stringWithFormat:@"find '%@' -type f -exec rm -f {} \\; 2>/dev/null", indexedDBPath];
    [self runCommandWithPrivileges:command];
    command = [NSString stringWithFormat:@"find '%@' -type d -name 'v*' -exec rm -rf {} \\; 2>/dev/null", indexedDBPath];
    [self runCommandWithPrivileges:command];
}

// Add new method to handle app state data cleaning for modern apps
// Add new method to handle app state data cleaning for modern apps
- (void)_internalClearAppStateData:(NSString *)bundleID {
    [self logMessage:@"[AppDataCleaner] Clearing app state data for %@", bundleID];
    
    // 1. Direct file paths (Fastest)
    NSArray *directPaths = @[
        [NSString stringWithFormat:@"/var/mobile/Library/SpringBoard/ApplicationState/%@.plist", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.%@.plist", bundleID]
    ];
    
    for (NSString *path in directPaths) {
        [self securelyWipeFile:path];
    }
    
    // 2. Scan specific directories for files containing bundleID (Much faster than find /)
    
    // FrontBoard
    [self scanAndWipeInDirectory:@"/var/mobile/Library/FrontBoard" matching:bundleID];
    
    // LiveActivities
    [self scanAndWipeInDirectory:@"/var/mobile/Library/LiveActivities" matching:bundleID];
    
    // SpringBoard RecentlyTerminatedAppState
    [self scanAndWipeInDirectory:@"/var/mobile/Library/SpringBoard/RecentlyTerminatedAppState" matching:bundleID];
    
    // BackgroundTasks - recursive scan needed but limited depth
    [self scanAndWipeInDirectory:@"/var/mobile/Library/BackgroundTasks" matching:bundleID];
    
    // TCC
    [self scanAndWipeInDirectory:@"/var/mobile/Library/TCC" matching:bundleID];
    
    // 3. Special handling for difficult paths (Containers)
    // Instead of scanning all containers, we use a targeted approach if possible, or skip deeply nested widely scattered scans if not critical.
    // For com.apple.nsurlsessiond, we can try a more limited scan if essential, but often the main cleanup handles the app's own container.
    // We will skip scanning /var/mobile/Library/Containers/*/Data/System/... to avoid timeout as it involves iterating thousands of folders.
}

// Helper to scan a directory and wipe files/folders matching a string
- (void)scanAndWipeInDirectory:(NSString *)directory matching:(NSString *)matchString {
    if (![_fileManager fileExistsAtPath:directory]) return;
    
    NSDirectoryEnumerator *enumerator = [_fileManager enumeratorAtURL:[NSURL fileURLWithPath:directory]
                                           includingPropertiesForKeys:@[NSURLNameKey, NSURLIsDirectoryKey]
                                                              options:NSDirectoryEnumerationSkipsHiddenFiles
                                                         errorHandler:nil];
    
    for (NSURL *fileURL in enumerator) {
        NSString *filename = [fileURL lastPathComponent];
        if ([filename containsString:matchString]) {
            NSString *path = [fileURL path];
            [self logMessage:@"[AppDataCleaner] Wiping matched state file: %@", path];
            [self securelyWipeFile:path];
            // If we deleted a directory, stick to standard enumeration or beware of modification during enumeration
            // securelyWipeFile handles file deletion.
        }
    }
}

// Override the existing clearAppStateData method to call our internal implementation

// Fix for line ~1757 - Replace the duplicate clearEncryptedData
- (void)_internalClearEncryptedData:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing encrypted data for %@", bundleID);
    
    // 1. Check for encrypted plist files in preferences
    NSArray *encryptedPrefs = [self findPathsMatchingPattern:[NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@*.enc*", bundleID]];
    encryptedPrefs = [encryptedPrefs arrayByAddingObjectsFromArray:
                     [self findPathsMatchingPattern:[NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@*.encrypted*", bundleID]]];
    encryptedPrefs = [encryptedPrefs arrayByAddingObjectsFromArray:
                     [self findPathsMatchingPattern:[NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@*.secure*", bundleID]]];
    
    for (NSString *path in encryptedPrefs) {
        [self securelyWipeFile:path];
    }
    
    // 2. Also check alternate preference locations
    NSArray<NSString *> *prefBases = @[
        @"/private/var/mobile/Library/Preferences",
        @"/var/jb/var/mobile/Library/Preferences",
        @"/private/var/jb/var/mobile/Library/Preferences"
    ];
    NSMutableArray *rootlessEncryptedPrefs = [NSMutableArray array];
    for (NSString *base in prefBases) {
        if (![_fileManager fileExistsAtPath:base]) continue;
        [rootlessEncryptedPrefs addObjectsFromArray:[self findPathsMatchingPattern:[NSString stringWithFormat:@"%@/%@*.enc*", base, bundleID]]];
        [rootlessEncryptedPrefs addObjectsFromArray:[self findPathsMatchingPattern:[NSString stringWithFormat:@"%@/%@*.encrypted*", base, bundleID]]];
        [rootlessEncryptedPrefs addObjectsFromArray:[self findPathsMatchingPattern:[NSString stringWithFormat:@"%@/%@*.secure*", base, bundleID]]];
    }
    
    for (NSString *path in rootlessEncryptedPrefs) {
        [self securelyWipeFile:path];
    }

    // Deep Clean toggle: default OFF (fast mode assumes wiped containers are clean).
    // When OFF, skip expensive recursive scans under app containers.
    if (![self _deepCleanEnabled]) {
        NSLog(@"[AppDataCleaner] Deep Clean OFF: skipping deep container encrypted/token scans");
        return;
    }
    
    // 3. Find data container for more thorough search
    NSString *dataUUID = [self findDataContainerUUID:bundleID];
    if (dataUUID) {
        NSString *dataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", dataUUID];
        
        // 4. Target all encrypted storage formats in data container
        NSArray *encryptionPatterns = @[
            @"*.enc*", @"*.encrypted*", @"*.secure*", @"*.token*", @"*Token*",
            @"*Auth*", @"*auth*", @"*cred*", @"*Cred*", @"*secret*", @"*Secret*",
            @"*login*", @"*Login*", @"*session*", @"*Session*", @"*api*key*",
            @"*firebase*", @"*google*auth*", @"*oauth*", @"*jwt*"
        ];
        
        // Single traversal for all patterns (major perf win).
        NSArray<NSString *> *matches = [self findPathsUnderRoot:dataPath directories:NO namePatterns:encryptionPatterns];
        for (NSString *path in matches) {
            NSLog(@"[AppDataCleaner] Wiping encrypted file: %@", path);
            [self securelyWipeFile:path];
        }
        
        // 5. Specifically target Google/Firebase auth folders
        NSArray *googlePaths = [self findPathsUnderRoot:dataPath directories:YES namePatterns:@[@"Google*", @"google*"]];
        for (NSString *path in googlePaths) {
            NSLog(@"[AppDataCleaner] Wiping Google auth directory: %@", path);
            [self fastWipeDirectoryContents:path keepDirectoryStructure:YES timeoutSec:8 * 60];
        }
        
        // 6. Target Firebase-related files
        NSArray *firebasePaths = [self findPathsUnderRoot:dataPath directories:YES namePatterns:@[@"Firebase*", @"firebase*"]];
        for (NSString *path in firebasePaths) {
            NSLog(@"[AppDataCleaner] Wiping Firebase directory: %@", path);
            [self fastWipeDirectoryContents:path keepDirectoryStructure:YES timeoutSec:8 * 60];
        }
        
        // 7. Target OAuth directories
        NSArray *oauthPaths = [self findPathsUnderRoot:dataPath directories:YES namePatterns:@[@"*oauth*", @"*OAuth*"]];
        for (NSString *path in oauthPaths) {
            NSLog(@"[AppDataCleaner] Wiping OAuth directory: %@", path);
            [self fastWipeDirectoryContents:path keepDirectoryStructure:YES timeoutSec:8 * 60];
        }
        
        // 8. Uber-specific directories (other apps use similar patterns)
        NSArray *authDirs = @[
            @"Library/Application Support/Credentials",
            @"Library/Application Support/Authentication",
            @"Library/Application Support/GoogleService-Info",
            @"Library/Application Support/Google/FIRApp",
            @"Library/Application Support/com.firebase",
            @"Library/Caches/com.google.firebase",
            @"Library/Caches/com.firebase",
            @"Library/HTTPStorages"
        ];
        
        for (NSString *dir in authDirs) {
            NSString *fullPath = [dataPath stringByAppendingPathComponent:dir];
            if ([_fileManager fileExistsAtPath:fullPath]) {
                NSLog(@"[AppDataCleaner] Wiping auth directory: %@", fullPath);
                [self fastWipeDirectoryContents:fullPath keepDirectoryStructure:YES timeoutSec:10 * 60];
            }
        }
    }
    
    // 9. Check app group containers
    NSArray *appGroupUUIDs = [self findAppGroupUUIDs:bundleID];
    for (NSString *groupUUID in appGroupUUIDs) {
        NSString *groupPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", groupUUID];
        
        // Look for encrypted/auth files in group containers
        NSArray *encryptionPatterns = @[
            @"*.enc*", @"*.encrypted*", @"*.secure*", @"*.token*", @"*Token*",
            @"*Auth*", @"*auth*", @"*cred*", @"*Cred*", @"*secret*", @"*Secret*"
        ];
        
        NSArray<NSString *> *matches = [self findPathsUnderRoot:groupPath directories:NO namePatterns:encryptionPatterns];
        for (NSString *path in matches) {
            NSLog(@"[AppDataCleaner] Wiping encrypted file in group: %@", path);
            [self securelyWipeFile:path];
        }
    }
}

// Override the existing clearEncryptedData method to call our internal implementation

// Add this method to handle clearing secure storage

// Add this new method to explicitly find extension containers
- (NSArray *)findExtensionContainers:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Finding extension containers for %@", bundleID);
    NSMutableArray *extensionInfo = [NSMutableArray array];
    
    // 1. Find extension data containers by checking metadata files (standard)
    NSArray *allDataContainers = [self listDirectoriesInPath:@"/var/mobile/Containers/Data/Application"];
    
    for (NSString *uuid in allDataContainers) {
        NSString *metadataPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
        
        // Check if this is an extension of our app (extensions often have the app's bundle ID as a prefix)
        if (containerBundleID && 
            [containerBundleID hasPrefix:bundleID] && 
            ![containerBundleID isEqualToString:bundleID]) {
            
            NSLog(@"[AppDataCleaner] Found extension data container: %@ for %@", uuid, containerBundleID);
            
            // Also search for the corresponding bundle UUID
            NSString *extBundleUUID = [self findBundleUUIDForExtension:containerBundleID];
            
            [extensionInfo addObject:@{
                @"bundleID": containerBundleID,
                @"dataUUID": uuid,
                @"bundleUUID": extBundleUUID ?: @"",
                @"type": @"extension"
            }];
        }
    }
    
    // 2. Check rootless path too
    if ([self directoryHasContent:@"/containers/Data/Application"]) {
        NSArray *rootlessDataContainers = [self listDirectoriesInPath:@"/containers/Data/Application"];
        
        for (NSString *uuid in rootlessDataContainers) {
            NSString *metadataPath = [NSString stringWithFormat:@"/containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
            NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
            NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
            
            if (containerBundleID && 
                [containerBundleID hasPrefix:bundleID] && 
                ![containerBundleID isEqualToString:bundleID]) {
                
                NSLog(@"[AppDataCleaner] Found rootless extension data container: %@ for %@", uuid, containerBundleID);
                
                // Find rootless bundle UUID
                NSString *extBundleUUID = [self findRootlessBundleUUIDForExtension:containerBundleID];
                
                [extensionInfo addObject:@{
                    @"bundleID": containerBundleID,
                    @"dataUUID": uuid,
                    @"bundleUUID": extBundleUUID ?: @"",
                    @"type": @"extension",
                    @"rootless": @YES
                }];
            }
        }
    }
    
    // 3. Also check PluginKitPlugin containers which can contain extension data
    NSArray *pluginKitPaths = [self findPathsMatchingPattern:@"/var/mobile/Containers/Data/PluginKitPlugin/*"];
    for (NSString *pluginPath in pluginKitPaths) {
        NSString *metadataPath = [pluginPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        
        NSString *containerID = metadata[@"MCMMetadataIdentifier"];
        if (containerID && [containerID hasPrefix:bundleID]) {
            NSString *uuid = [pluginPath lastPathComponent];
            NSLog(@"[AppDataCleaner] Found PluginKit container: %@ for %@", uuid, containerID);
            
            [extensionInfo addObject:@{
                @"bundleID": containerID,
                @"dataUUID": uuid,
                @"type": @"pluginkit"
            }];
        }
    }
    
    // 4. Check rootless PluginKitPlugin containers
    pluginKitPaths = [self findPathsMatchingPattern:@"/containers/Data/PluginKitPlugin/*"];
    for (NSString *pluginPath in pluginKitPaths) {
        NSString *metadataPath = [pluginPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        
        NSString *containerID = metadata[@"MCMMetadataIdentifier"];
        if (containerID && [containerID hasPrefix:bundleID]) {
            NSString *uuid = [pluginPath lastPathComponent];
            NSLog(@"[AppDataCleaner] Found rootless PluginKit container: %@ for %@", uuid, containerID);
            
            [extensionInfo addObject:@{
                @"bundleID": containerID,
                @"dataUUID": uuid,
                @"type": @"pluginkit",
                @"rootless": @YES
            }];
        }
    }
    
    NSLog(@"[AppDataCleaner] Found %lu extension containers for %@", (unsigned long)extensionInfo.count, bundleID);
    return extensionInfo;
}

// Find bundle UUID for an extension
- (NSString *)findBundleUUIDForExtension:(NSString *)extensionBundleID {
    NSArray *bundleDirs = [self listDirectoriesInPath:@"/var/containers/Bundle/Application"];
    
    for (NSString *uuid in bundleDirs) {
        NSString *appPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@", uuid];
        NSArray *appContents = [self listDirectoriesInPath:appPath];
        
        // Extensions are often in a Plugins or PlugIns directory
        for (NSString *item in appContents) {
            if ([item hasSuffix:@".app"] || [item hasSuffix:@".appex"] || 
                [item isEqualToString:@"PlugIns"] || [item isEqualToString:@"Plugins"]) {
                
                // Check if this is the extension's bundle
                if ([item hasSuffix:@".appex"]) {
                    NSString *infoPlistPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@/%@/Info.plist", 
                                             uuid, item];
                    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                    NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                    
                    if ([itemBundleID isEqualToString:extensionBundleID]) {
                        return uuid;
                    }
                } 
                // Check in Plugins/PlugIns directory for extension bundles
                else if ([item isEqualToString:@"PlugIns"] || [item isEqualToString:@"Plugins"]) {
                    NSString *pluginsPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@/%@", uuid, item];
                    NSArray *plugins = [self listDirectoriesInPath:pluginsPath];
                    
                    for (NSString *plugin in plugins) {
                        if ([plugin hasSuffix:@".appex"]) {
                            NSString *infoPlistPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@/%@/%@/Info.plist", 
                                                     uuid, item, plugin];
                            NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                            NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                            
                            if ([itemBundleID isEqualToString:extensionBundleID]) {
                                return uuid;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return nil;
}

// Find rootless bundle UUID for an extension
- (NSString *)findRootlessBundleUUIDForExtension:(NSString *)extensionBundleID {
    if (![self directoryHasContent:@"/containers/Bundle/Application"]) {
        return nil;
    }
    
    NSArray *bundleDirs = [self listDirectoriesInPath:@"/containers/Bundle/Application"];
    
    for (NSString *uuid in bundleDirs) {
        NSString *appPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@", uuid];
        NSArray *appContents = [self listDirectoriesInPath:appPath];
        
        // Same logic as standard bundle, but with rootless paths
        for (NSString *item in appContents) {
            if ([item hasSuffix:@".app"] || [item hasSuffix:@".appex"] || 
                [item isEqualToString:@"PlugIns"] || [item isEqualToString:@"Plugins"]) {
                
                if ([item hasSuffix:@".appex"]) {
                    NSString *infoPlistPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@/%@/Info.plist", 
                                             uuid, item];
                    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                    NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                    
                    if ([itemBundleID isEqualToString:extensionBundleID]) {
                        return uuid;
                    }
                } 
                else if ([item isEqualToString:@"PlugIns"] || [item isEqualToString:@"Plugins"]) {
                    NSString *pluginsPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@/%@", uuid, item];
                    NSArray *plugins = [self listDirectoriesInPath:pluginsPath];
                    
                    for (NSString *plugin in plugins) {
                        if ([plugin hasSuffix:@".appex"]) {
                            NSString *infoPlistPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@/%@/%@/Info.plist", 
                                                     uuid, item, plugin];
                            NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                            NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                            
                            if ([itemBundleID isEqualToString:extensionBundleID]) {
                                return uuid;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return nil;
}

// Method to clear extension containers
- (void)clearExtensionContainers:(NSArray *)extensionInfo forApp:(NSString *)bundleID {
    if (extensionInfo.count == 0) {
        NSLog(@"[AppDataCleaner] No extension containers found to clear for %@", bundleID);
        return;
    }
    
    NSLog(@"[AppDataCleaner] Clearing %lu extension containers for %@", (unsigned long)extensionInfo.count, bundleID);
    
    for (NSDictionary *extension in extensionInfo) {
        NSString *extensionBundleID = extension[@"bundleID"];
        NSString *dataUUID = extension[@"dataUUID"];
        NSString *bundleUUID = extension[@"bundleUUID"];
        NSString *type = extension[@"type"];
        BOOL isRootless = [extension[@"rootless"] boolValue];
        
        // 1. Clear extension data container
        if (dataUUID.length > 0) {
            NSString *basePath = isRootless ? 
                @"/containers/Data/" : 
                @"/var/mobile/Containers/Data/";
            
            NSString *containerType = [type isEqualToString:@"pluginkit"] ? @"PluginKitPlugin" : @"Application";
            NSString *dataPath = [NSString stringWithFormat:@"%@%@/%@", basePath, containerType, dataUUID];
            
            NSLog(@"[AppDataCleaner] Clearing extension data container: %@", dataPath);
            
            // Fix permissions first
            [self fixPermissionsForPath:dataPath];
            
            // Clear important directories
            NSArray *subDirs = @[
                        @"Documents",
                        @"Library/Caches",
                        @"Library/Preferences",
                        @"Library/WebKit",
                        @"Library/Application Support",
                @"tmp"
            ];
            
            for (NSString *subDir in subDirs) {
                NSString *fullPath = [dataPath stringByAppendingPathComponent:subDir];
                
                if ([subDir isEqualToString:@"Library/WebKit"]) {
                    [self wipeWebKitDirectoryContents:fullPath];
                } else {
                    [self wipeDirectoryContents:fullPath keepDirectoryStructure:YES];
                }
            }
            
            // Clear databases
            NSArray *dbFiles = [self findPathsMatchingPattern:[NSString stringWithFormat:@"%@/Library/**/*.sqlite*", dataPath]];
            for (NSString *dbPath in dbFiles) {
                [self securelyWipeFile:dbPath];
                [self securelyWipeFile:[dbPath stringByAppendingString:@"-journal"]];
                [self securelyWipeFile:[dbPath stringByAppendingString:@"-wal"]];
                [self securelyWipeFile:[dbPath stringByAppendingString:@"-shm"]];
            }
        }
        
        // 2. Clear extension bundle receipt if available
        if (bundleUUID.length > 0) {
            NSString *basePath = isRootless ?
                @"/containers/Bundle/Application/" :
                @"/var/containers/Bundle/Application/";
            
            // Extensions can be directly in the bundle directory or in PlugIns/Plugins subdirectory
            NSString *bundlePath = [NSString stringWithFormat:@"%@%@", basePath, bundleUUID];
            NSArray *bundleContents = [self listDirectoriesInPath:bundlePath];
            
            for (NSString *item in bundleContents) {
                // Direct .appex file
                if ([item hasSuffix:@".appex"]) {
                    NSString *infoPlistPath = [NSString stringWithFormat:@"%@%@/Info.plist", bundlePath, item];
                    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                    NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                    
                    if ([itemBundleID isEqualToString:extensionBundleID]) {
                        NSString *receiptPath = [NSString stringWithFormat:@"%@%@/_MASReceipt", bundlePath, item];
                        NSLog(@"[AppDataCleaner] Clearing extension receipt: %@", receiptPath);
                        [self fixPermissionsAndRemovePath:receiptPath];
                    }
                }
                // Check in PlugIns/Plugins directory
                else if ([item isEqualToString:@"PlugIns"] || [item isEqualToString:@"Plugins"]) {
                    NSString *pluginsPath = [NSString stringWithFormat:@"%@%@", bundlePath, item];
                    NSArray *plugins = [self listDirectoriesInPath:pluginsPath];
                    
                    for (NSString *plugin in plugins) {
                        if ([plugin hasSuffix:@".appex"]) {
                            NSString *infoPlistPath = [NSString stringWithFormat:@"%@/%@/Info.plist", pluginsPath, plugin];
                            NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                            NSString *itemBundleID = infoPlist[@"CFBundleIdentifier"];
                            
                            if ([itemBundleID isEqualToString:extensionBundleID]) {
                                NSString *receiptPath = [NSString stringWithFormat:@"%@/%@/_MASReceipt", pluginsPath, plugin];
                                NSLog(@"[AppDataCleaner] Clearing extension receipt in plugins: %@", receiptPath);
                                [self fixPermissionsAndRemovePath:receiptPath];
                            }
                        }
                    }
                }
            }
        }
        
        // 3. Clear extension keychain items (best-effort)
        {
            NSError *kcErr = nil;
            if (![self _wipeSelectedKeychainForBundleID:extensionBundleID error:&kcErr]) {
                [self logMessage:@"[AppDataCleaner] WARNING: Extension keychain wipe failed (%@): %@", extensionBundleID, kcErr.localizedDescription ?: @"unknown"];
            }
        }
        
        // 4. Clear extension preferences
        NSString *prefsPath = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", extensionBundleID];
        [self securelyWipeFile:prefsPath];
        
        NSString *rootlessPrefsPath = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", extensionBundleID];
        [self securelyWipeFile:rootlessPrefsPath];
    }
}

// Helper method to fix permissions on a path
- (void)fixPermissionsForPath:(NSString *)path {
    if (![_fileManager fileExistsAtPath:path]) {
        return;
    }
    
    NSLog(@"[AppDataCleaner] Fixing permissions for path: %@", path);
    
    // Command to fix permissions of the entire directory
    NSString *chmodCommand = [NSString stringWithFormat:@"chmod -R 0777 '%@' 2>/dev/null || true", path];
    [self runCommandWithPrivileges:chmodCommand];
    
    // Remove any immutable or hidden flags
    NSString *chflagsCommand = [NSString stringWithFormat:@"chflags -R nouchg,noschg,nohidden '%@' 2>/dev/null || true", path];
    [self runCommandWithPrivileges:chflagsCommand];
}

// Add a new method for aggressive cleanup of stubborn files
- (void)performAggressiveCleanupFor:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Performing aggressive cleanup for %@", bundleID);
    
    // Kill the app first to ensure no files are in use
    PXKillallByName(bundleID, SIGKILL);
    
    // Get the data container
    NSString *dataUUID = [self findDataContainerUUID:bundleID];
    if (dataUUID) {
        NSString *dataContainerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Data/Application/%@", dataUUID];
        
        // Add additional aggressive cleaning of the Documents directory
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@/Documents' -type f -exec rm -f {} \\; 2>/dev/null || true", dataContainerPath]];
        
        // Force proper permissions on Library
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"chmod -R 755 '%@/Library' 2>/dev/null || true", dataContainerPath]];
        
        // Find and remove all database files which may contain authentication data
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -name '*.db*' -exec rm -f {} \\; 2>/dev/null || true", dataContainerPath]];
        
        // NEW: Use the comprehensive container wipe
        [self completelyWipeContainer:dataContainerPath];
    }
    
    // Ensure keychain items are really gone
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"security delete-generic-password -l '%@' 2>/dev/null || true;security delete-internet-password -l '%@' 2>/dev/null || true", bundleID, bundleID]];
    
    // Clear PushStore which can contain tokens
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/SpringBoard/PushStore/%@* 2>/dev/null || true", bundleID]];
    
    // Clear UsageLog which tracks app usage
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf /var/mobile/Library/UsageLog/%@* 2>/dev/null || true", bundleID]];
    
    // Clear WebKit LocalStorage which may contain credentials
    [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/WebKit/WebsiteData/LocalStorage/* 2>/dev/null || true"];
    
    // Clear account data specific to this app
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '/var/mobile/Library/Accounts/%@*' 2>/dev/null || true", bundleID]];
    
    // NEW: Clean the SiriAnalytics database
    [self cleanSiriAnalyticsDatabase:bundleID];
    
    // NEW: Clean IconState.plist
    [self cleanIconStatePlist:bundleID];
    
    // NEW: Clean LaunchServices database
    [self cleanLaunchServicesDatabase:bundleID];
}

- (NSString *)findBundleContainerUUID:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Searching for bundle container UUID for %@", bundleID);
    
    // 1. Check standard app bundle containers path
    NSString *bundlesPath = @"/var/containers/Bundle/Application";
    if (![_fileManager fileExistsAtPath:bundlesPath]) {
        bundlesPath = @"/var/mobile/Containers/Bundle/Application";
    }
    
    NSError *error;
    NSArray *contents = [_fileManager contentsOfDirectoryAtPath:bundlesPath error:&error];
    
    if (error) {
        NSLog(@"[AppDataCleaner] Error listing app bundle containers: %@", error.localizedDescription);
        return nil;
    }
    
    // 2. Iterate through UUIDs to find our app
    for (NSString *uuid in contents) {
        NSString *appPath = [bundlesPath stringByAppendingPathComponent:uuid];
        NSArray *appContents = [_fileManager contentsOfDirectoryAtPath:appPath error:nil];
        
        for (NSString *item in appContents) {
            if ([item hasSuffix:@".app"]) {
                NSString *infoPlistPath = [NSString stringWithFormat:@"%@/%@/Info.plist", appPath, item];
                NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                
                if ([infoPlist[@"CFBundleIdentifier"] isEqualToString:bundleID]) {
                    NSLog(@"[AppDataCleaner] Found bundle container UUID: %@ for %@", uuid, bundleID);
                    return uuid;
                }
            }
        }
    }
    
    // 3. Also check rootless path
    NSString *rootlessBundlesPath = @"/containers/Bundle/Application";
    if ([_fileManager fileExistsAtPath:rootlessBundlesPath]) {
        contents = [_fileManager contentsOfDirectoryAtPath:rootlessBundlesPath error:&error];
        
        if (error) {
            NSLog(@"[AppDataCleaner] Error listing rootless app bundle containers: %@", error.localizedDescription);
            return nil;
        }
        
        for (NSString *uuid in contents) {
            NSString *appPath = [rootlessBundlesPath stringByAppendingPathComponent:uuid];
            NSArray *appContents = [_fileManager contentsOfDirectoryAtPath:appPath error:nil];
            
            for (NSString *item in appContents) {
                if ([item hasSuffix:@".app"]) {
                    NSString *infoPlistPath = [NSString stringWithFormat:@"%@/%@/Info.plist", appPath, item];
                    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                    
                    if ([infoPlist[@"CFBundleIdentifier"] isEqualToString:bundleID]) {
                        NSLog(@"[AppDataCleaner] Found rootless bundle container UUID: %@ for %@", uuid, bundleID);
                        return uuid;
                    }
                }
            }
        }
    }
    
    NSLog(@"[AppDataCleaner] No bundle container UUID found for %@", bundleID);
    return nil;
}

- (void)clearAppReceiptData:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing App Store receipt for %@", bundleID);
    
    // 1. Find the bundle container UUID
    NSString *bundleUUID = [self findBundleContainerUUID:bundleID];
    if (!bundleUUID) {
        NSLog(@"[AppDataCleaner] Could not find bundle UUID to clear receipt");
        return;
    }
    
    // 2. Clear the standard receipt path
    NSString *receiptPath = [NSString stringWithFormat:@"/var/containers/Bundle/Application/%@/*/._MASReceipt", bundleUUID];
    NSArray *receipts = [self findPathsMatchingPattern:receiptPath];
    for (NSString *path in receipts) {
        NSLog(@"[AppDataCleaner] Wiping app receipt at: %@", path);
        [self wipeDirectoryContents:path keepDirectoryStructure:YES];
    }
    
    // 3. Try alternate paths with glob expansion
    NSString *altReceiptPath = [NSString stringWithFormat:@"/var/mobile/Containers/Bundle/Application/%@/*/_MASReceipt", bundleUUID];
    receipts = [self findPathsMatchingPattern:altReceiptPath];
    for (NSString *path in receipts) {
        NSLog(@"[AppDataCleaner] Wiping app receipt at: %@", path);
        [self wipeDirectoryContents:path keepDirectoryStructure:YES];
    }
    
    // 4. Check rootless paths too
    NSString *rootlessReceiptPath = [NSString stringWithFormat:@"/containers/Bundle/Application/%@/*/_MASReceipt", bundleUUID];
    receipts = [self findPathsMatchingPattern:rootlessReceiptPath];
    for (NSString *path in receipts) {
        NSLog(@"[AppDataCleaner] Wiping rootless app receipt at: %@", path);
        [self wipeDirectoryContents:path keepDirectoryStructure:YES];
    }
}

// Add these methods to our collection for the most comprehensive clearing

// MEDIA STORAGE: Add method to clean media traces that apps sometimes leave behind
- (void)clearMediaData:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing media data for %@", bundleID);
    
    // Parse app name from bundle ID
    NSArray *components = [bundleID componentsSeparatedByString:@"."];
    NSString *appName = [components lastObject];
    
    if (appName.length > 3) {  // Skip short/generic names
        // Check Camera Roll for app-generated photos
        NSString *dcimPath = @"/var/mobile/Media/DCIM/100APPLE/";
        if ([_fileManager fileExistsAtPath:dcimPath]) {
            NSString *command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                                dcimPath, appName];
            [self runCommandWithPrivileges:command];
        }
        
        // Check Downloads folder
        NSString *downloadsPath = @"/var/mobile/Media/Downloads/";
        if ([_fileManager fileExistsAtPath:downloadsPath]) {
            NSString *command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                                downloadsPath, appName];
            [self runCommandWithPrivileges:command];
        }
        
        // Check for attachments in Messages
        NSString *attachmentsPath = @"/var/mobile/Library/SMS/Attachments/";
        if ([_fileManager fileExistsAtPath:attachmentsPath]) {
            NSString *command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                                attachmentsPath, appName];
            [self runCommandWithPrivileges:command];
        }
    }
    
    // Check for app's media in general Library locations
    NSArray *mediaPaths = @[
        @"/var/mobile/Media/PhotoData/LocalItems/",
        @"/var/mobile/Media/PhotoData/Caches/",
        @"/var/mobile/Media/PhotoData/Thumbnails/",
        @"/var/mobile/Media/PhotoStreamsData/",
        @"/var/mobile/Media/Photos/Thumbnails/",
        @"/var/mobile/Library/Photos/"
    ];
    
    for (NSString *basePath in mediaPaths) {
        if ([_fileManager fileExistsAtPath:basePath]) {
            NSString *command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                                basePath, bundleID];
            [self runCommandWithPrivileges:command];
            
            if (appName.length > 3) {
                command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                          basePath, appName];
                [self runCommandWithPrivileges:command];
            }
        }
    }
}

// HEALTH DATA: Some apps like fitness trackers can store health data
- (void)clearHealthData:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing health data for %@", bundleID);
    
    NSArray *healthPaths = @[
        @"/var/mobile/Library/Health/",
        @"/var/mobile/Library/HealthKit/",
        @"/var/mobile/Library/Health/",
        @"/var/mobile/Library/HealthKit/"
    ];
    
    for (NSString *basePath in healthPaths) {
        if ([_fileManager fileExistsAtPath:basePath]) {
            NSString *command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                                basePath, bundleID];
            [self runCommandWithPrivileges:command];
        }
    }
}

// SAFARI DATA: Some apps use SafariViewController and leave data there
- (void)clearSafariData:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Clearing Safari data for %@", bundleID);
    
    NSArray *components = [bundleID componentsSeparatedByString:@"."];
    NSString *appName = [components lastObject];
    
    NSArray *safariPaths = @[
        @"/var/mobile/Library/Safari/History.db",
        @"/var/mobile/Library/Safari/Bookmarks.db",
        @"/var/mobile/Library/Safari/TopSites.db",
        @"/var/mobile/Library/Safari/RecentlyClosedTabs.plist",
        @"/var/mobile/Library/Safari/Tabs/"
    ];
    
    for (NSString *path in safariPaths) {
        if ([_fileManager fileExistsAtPath:path]) {
            if ([path hasSuffix:@".db"]) {
                // Use sqlite3 to delete records related to the app
                NSString *sqlCommand = [NSString stringWithFormat:
                                      @"sqlite3 '%@' \"DELETE FROM history_items WHERE url LIKE '%%%@%%';\"",
                                      path, bundleID];
                [self runCommandWithPrivileges:sqlCommand];
                
                if (appName.length > 3) {
                    sqlCommand = [NSString stringWithFormat:
                                @"sqlite3 '%@' \"DELETE FROM history_items WHERE title LIKE '%%%@%%';\"",
                                path, appName];
                    [self runCommandWithPrivileges:sqlCommand];
                }
                
                // Vacuum database
                sqlCommand = [NSString stringWithFormat:@"sqlite3 '%@' \"VACUUM;\"", path];
                [self runCommandWithPrivileges:sqlCommand];
            } else if ([path.lastPathComponent isEqualToString:@"Tabs"]) {
                // Find and delete tab files related to the app
                NSString *command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                                    path, bundleID];
                [self runCommandWithPrivileges:command];
                
                if (appName.length > 3) {
                    command = [NSString stringWithFormat:@"find '%@' -name '*%@*' -exec rm -f {} \\; 2>/dev/null || true", 
                              path, appName];
                    [self runCommandWithPrivileges:command];
                }
            }
        }
    }
}

// NEW: Method to completely wipe a container directory
- (void)completelyWipeContainer:(NSString *)containerPath {
    if (![_fileManager fileExistsAtPath:containerPath]) {
        return;
    }
    
    NSLog(@"[AppDataCleaner] Completely wiping container: %@", containerPath);

    BOOL deep = [self _deepCleanEnabled];
    int chmodTimeout = deep ? (10 * 60) : (3 * 60);
    int findTimeout = deep ? (20 * 60) : (8 * 60);

    // Set all permissions before removal
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"chmod -R 777 '%@'", containerPath] timeoutSec:chmodTimeout];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -type d -exec chmod 777 {} \\;", containerPath] timeoutSec:chmodTimeout];
    
    // Preserve iOS container metadata files (do not rewrite them).
    // Modifying these can break MCM/LaunchServices container mapping and cause "Data container not found".
    NSArray *systemFiles = @[
        @".com.apple.containermanagerd.metadata.plist",
        @".com.apple.mobile_container_manager.metadata.plist"
    ];
    for (NSString *systemFile in systemFiles) {
        NSString *fullPath = [containerPath stringByAppendingPathComponent:systemFile];
        if ([_fileManager fileExistsAtPath:fullPath]) {
            NSLog(@"[AppDataCleaner] Preserving system file: %@", fullPath);
        }
    }
    
    // Remove all non-system files first (preserve .com.apple.mobile_container_manager* and .com.apple.containermanagerd*)
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -type f -not -name '.com.apple.mobile_container_manager*' -not -name '.com.apple.containermanagerd*' -exec rm -f {} \\;", containerPath] timeoutSec:findTimeout];
    
    // Then remove empty non-system directories from bottom up
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -depth -type d -not -name '.com.apple.mobile_container_manager*' -not -name '.com.apple.containermanagerd*' -empty -delete", containerPath] timeoutSec:findTimeout];
    
    // Create minimal structure to avoid iOS crashes
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"mkdir -p '%@/Documents' '%@/Library/Caches' '%@/Library/Preferences' '%@/tmp'", 
        containerPath, containerPath, containerPath, containerPath] timeoutSec:60];
    
    // Set proper permissions on the directories
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"chmod 755 '%@/Documents' '%@/Library' '%@/Library/Caches' '%@/Library/Preferences' '%@/tmp'", 
        containerPath, containerPath, containerPath, containerPath, containerPath] timeoutSec:60];
    
    // Touch standard files that apps might expect
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"touch '%@/Documents/.nomedia' '%@/Library/Preferences/.initialized'", 
        containerPath, containerPath] timeoutSec:60];
}

// NEW: Method to clean IconState.plist
- (void)cleanIconStatePlist:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Cleaning SpringBoard IconState.plist for %@", bundleID);
    
    // First, backup the original plist
    [self runCommandWithPrivileges:@"cp '/var/mobile/Library/SpringBoard/IconState.plist' '/var/tmp/IconState.plist'"];
    [self runCommandWithPrivileges:@"chmod 644 '/var/tmp/IconState.plist'"];
    
    // Convert binary plist to XML format for easy text processing
    [self runCommandWithPrivileges:@"plutil -convert xml1 '/var/tmp/IconState.plist'"];
    
    // Aggressively remove any references to this app by bundle ID
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"grep -v '%@' '/var/tmp/IconState.plist' > '/var/tmp/IconState_filtered.plist'", bundleID]];
    
    // Convert back to binary format
    [self runCommandWithPrivileges:@"plutil -convert binary1 '/var/tmp/IconState_filtered.plist'"];
    
    // Replace the original plist with the filtered one
    [self runCommandWithPrivileges:@"cp '/var/tmp/IconState_filtered.plist' '/var/mobile/Library/SpringBoard/IconState.plist'"];
    
    // Clean up the temporary files
    [self runCommandWithPrivileges:@"rm -f '/var/tmp/IconState.plist' '/var/tmp/IconState_filtered.plist'"];
    
    // Additional aggressive cleanup of IconState
    // Use a more comprehensive approach to also clean any partial fragments
    // Extract app name from bundle ID (e.g., "UberClient" from "com.ubercab.UberClient")
    NSArray *components = [bundleID componentsSeparatedByString:@"."];
    NSString *appName = components.lastObject;
    
    // Dump, filter, and restore method  
    [self runCommandWithPrivileges:@"cp '/var/mobile/Library/SpringBoard/IconState.plist' '/var/tmp/IconState2.plist'"];
    [self runCommandWithPrivileges:@"chmod 644 '/var/tmp/IconState2.plist'"];
    [self runCommandWithPrivileges:@"plutil -convert xml1 '/var/tmp/IconState2.plist'"];
    
    if (appName && appName.length > 0) {
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"grep -v '%@' '/var/tmp/IconState2.plist' > '/var/tmp/IconState2_filtered.plist'", appName]];
        [self runCommandWithPrivileges:@"plutil -convert binary1 '/var/tmp/IconState2_filtered.plist'"];
        [self runCommandWithPrivileges:@"cp '/var/tmp/IconState2_filtered.plist' '/var/mobile/Library/SpringBoard/IconState.plist'"];
        [self runCommandWithPrivileges:@"rm -f '/var/tmp/IconState2.plist' '/var/tmp/IconState2_filtered.plist'"];
    }
    
    // Also clean up DefaultIconState.plist as a safety measure
    if ([_fileManager fileExistsAtPath:@"/var/mobile/Library/SpringBoard/DefaultIconState.plist"]) {
        [self runCommandWithPrivileges:@"cp '/var/mobile/Library/SpringBoard/DefaultIconState.plist' '/var/tmp/DefaultIconState.plist'"];
        [self runCommandWithPrivileges:@"chmod 644 '/var/tmp/DefaultIconState.plist'"];
        [self runCommandWithPrivileges:@"plutil -convert xml1 '/var/tmp/DefaultIconState.plist'"];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"grep -v '%@' '/var/tmp/DefaultIconState.plist' > '/var/tmp/DefaultIconState_filtered.plist'", bundleID]];
        [self runCommandWithPrivileges:@"plutil -convert binary1 '/var/tmp/DefaultIconState_filtered.plist'"];
        [self runCommandWithPrivileges:@"cp '/var/tmp/DefaultIconState_filtered.plist' '/var/mobile/Library/SpringBoard/DefaultIconState.plist'"];
        [self runCommandWithPrivileges:@"rm -f '/var/tmp/DefaultIconState.plist' '/var/tmp/DefaultIconState_filtered.plist'"];
    }
}

// NEW: Method to clean SiriAnalytics database
- (void)cleanSiriAnalyticsDatabase:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Cleaning SiriAnalytics database for %@", bundleID);
    
    // Extract app name from bundle ID (e.g., "UberClient" from "com.ubercab.UberClient")
    NSArray *components = [bundleID componentsSeparatedByString:@"."];
    NSString *appName = components.lastObject;
    
    // Delete from main table
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM main WHERE bundleid = '%@';\"", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM main WHERE app_id = '%@';\"", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM app_usage WHERE bundleid = '%@';\"", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM usage_contexts WHERE data LIKE '%%%@%%';\"", bundleID]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM analytics WHERE data LIKE '%%%@%%';\"", bundleID]];
    
    // Also check by app name
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM main WHERE bundleid LIKE '%%%@%%';\"", appName]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM main WHERE app_id LIKE '%%%@%%';\"", appName]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM app_usage WHERE bundleid LIKE '%%%@%%';\"", appName]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM usage_contexts WHERE data LIKE '%%%@%%';\"", appName]];
    [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM analytics WHERE data LIKE '%%%@%%';\"", appName]];
    
    // Also delete by company name if available (e.g., "ubercab" from "com.ubercab.UberClient")
    if (components.count > 1) {
        NSString *companyName = components[1];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM main WHERE bundleid LIKE '%%%@%%';\"", companyName]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM app_usage WHERE bundleid LIKE '%%%@%%';\"", companyName]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM usage_contexts WHERE data LIKE '%%%@%%';\"", companyName]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"DELETE FROM analytics WHERE data LIKE '%%%@%%';\"", companyName]];
    }
    
    // Force data flush by running VACUUM
    [self runCommandWithPrivileges:@"sqlite3 '/var/mobile/Library/Assistant/SiriAnalytics.db' \"VACUUM;\""];
    
    // For verification purposes, ensure the database can't be flagged during verification
    [self runCommandWithPrivileges:@"touch -r /var/mobile/Library/Assistant/SiriAnalytics.db /System/Library/PrivateFrameworks/AssistantServices.framework/AssistantServices"];
}

// NEW: Method to clean LaunchServices database
- (void)cleanLaunchServicesDatabase:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Cleaning LaunchServices database for %@", bundleID);
    
    // Remove SBAppTagsFileManager which stores app categorization
    [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/CoreServices/SpringBoard.app/SBAppTagsFileManager"];
    [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/CoreServices/SpringBoard.app/SBIconModelCache.plist"];
    
    // Also remove rootless versions
    [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/CoreServices/SpringBoard.app/SBAppTagsFileManager"];
    [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/CoreServices/SpringBoard.app/SBIconModelCache.plist"];
    
    // Find and remove LaunchServices caches
    NSArray *lsCachePaths = [self findPathsMatchingPattern:@"/var/mobile/Library/Caches/com.apple.LaunchServices-*"];
    for (NSString *path in lsCachePaths) {
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", path]];
    }
    
    // Find and remove rootless LaunchServices caches
    lsCachePaths = [self findPathsMatchingPattern:@"/var/mobile/Library/Caches/com.apple.LaunchServices-*"];
    for (NSString *path in lsCachePaths) {
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", path]];
    }
}

// NEW: Method to refresh system services to apply changes
- (void)refreshSystemServices {
    [self logMessage:@"[AppDataCleaner] Refreshing system services (SAFE MODE)..."];
    
    // REMOVED: Send HUP signal to SpringBoard - CAUSES RESPRING
    // [self runCommandWithPrivileges:@"killall -HUP SpringBoard 2>/dev/null || true"];
    
    // Enhanced: Force system caches to be cleared
    [self runCommandWithPrivileges:@"sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true"];
    
    // Enhanced: Clear application launch cache (Safe to restart cfprefsd)
    PXKillallByName(@"cfprefsd", SIGTERM);
    
    // Enhanced: Clear system connectivity caches
    PXKillallByName(@"nsurlsessiond", SIGTERM);
    
    // REMOVED: Force cache regen in filesystem - MAY CAUSE RESPRING
    // [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/Caches/com.apple.LaunchServices-* 2>/dev/null || true"];
    
    // Enhanced: Force database vacuum on key databases to remove deleted data
    NSArray *dbsToVacuum = @[
        @"/var/mobile/Library/SpringBoard/ApplicationState.db"
    ];
    
    for (NSString *dbPath in dbsToVacuum) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:dbPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"VACUUM;\" 2>/dev/null || true", dbPath]];
        }
    }
}

#pragma mark - Container Discovery Methods

- (BOOL)hasKeychainItemsForBundleID:(NSString *)bundleID {
    // This will require Security.framework access
    // For now we'll use a simple check to see if there are any keychain items for this app
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrService] = bundleID;
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status == errSecSuccess) {
        NSArray *items = (__bridge_transfer NSArray *)result;
        return items.count > 0;
    }
    
    // Try again with a different approach - check for access groups
    query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrAccessGroup] = bundleID;
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    
    result = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status == errSecSuccess) {
        NSArray *items = (__bridge_transfer NSArray *)result;
        return items.count > 0;
    }
    
    return NO;
}

// Support methods (aliases for backwards compatibility)
- (NSString *)findDataContainerUUIDForBundleID:(NSString *)bundleID {
    return [self findDataContainerUUID:bundleID];
}

- (NSString *)findBundleContainerUUIDForBundleID:(NSString *)bundleID {
    return [self findBundleContainerUUID:bundleID];
}

- (NSArray *)findGroupContainerUUIDsForBundleID:(NSString *)bundleID {
    if (!bundleID.length) return @[];

    // Resolve app groups from entitlements (authoritative), then map to UUID/path.
    AppEntitlementsReader *reader = [[AppEntitlementsReader alloc] init];
    NSError *entErr = nil;
    NSDictionary *ent = [reader fullEntitlementsForBundleID:bundleID error:&entErr];
    NSArray *groups = nil;
    if ([ent isKindOfClass:[NSDictionary class]]) {
        id v = ent[@"com.apple.security.application-groups"];
        if ([v isKindOfClass:[NSArray class]]) {
            groups = (NSArray *)v;
        } else {
            v = ent[@"application-groups"];
            if ([v isKindOfClass:[NSArray class]]) {
                groups = (NSArray *)v;
            }
        }
    }
    if (!groups.count) {
        return @[];
    }

    NSMutableArray<NSString *> *groupIDs = [NSMutableArray array];
    for (id g in groups) {
        if ([g isKindOfClass:[NSString class]] && [(NSString *)g length] > 0) {
            [groupIDs addObject:(NSString *)g];
        }
    }
    if (!groupIDs.count) {
        return @[];
    }

    AppGroupContainerResolver *resolver = [[AppGroupContainerResolver alloc] init];
    NSArray<AppGroupContainerInfo *> *infos = [resolver resolveGroupContainersForGroupIDs:groupIDs];
    NSMutableArray<NSString *> *uuids = [NSMutableArray array];
    for (AppGroupContainerInfo *info in infos) {
        if ([info.uuid isKindOfClass:[NSString class]] && info.uuid.length) {
            [uuids addObject:info.uuid];
        } else if ([info.path isKindOfClass:[NSString class]] && info.path.length) {
            [uuids addObject:[info.path lastPathComponent]];
        }
    }
    return uuids;
}

- (void)_wipeRelatedDataContainersForBundleIDs:(NSArray<NSString *> *)bundleIDs {
    if (![bundleIDs isKindOfClass:[NSArray class]] || bundleIDs.count == 0) return;

    for (NSString *bid in bundleIDs) {
        if (![bid isKindOfClass:[NSString class]] || bid.length == 0) continue;
        [self logMessage:@"[AppDataCleaner] Wiping related data containers for %@", bid];

        // Rootful and rootless: scan metadata identifiers and wipe all matches.
        NSArray<NSString *> *bases = @[
            @"/var/mobile/Containers/Data/Application",
            @"/containers/Data/Application"
        ];
        for (NSString *base in bases) {
            if (![_fileManager fileExistsAtPath:base]) continue;
            NSArray *uuids = [self listDirectoriesInPath:base];
            for (NSString *uuid in uuids) {
                if (![uuid isKindOfClass:[NSString class]] || !uuid.length) continue;
                NSString *metadataPath = [NSString stringWithFormat:@"%@/%@/.com.apple.mobile_container_manager.metadata.plist", base, uuid];
                NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
                NSString *ident = [metadata[@"MCMMetadataIdentifier"] isKindOfClass:[NSString class]] ? metadata[@"MCMMetadataIdentifier"] : nil;
                if (!ident.length) continue;

                // Exact match or prefix match (some services use suffixes).
                BOOL match = [ident isEqualToString:bid] || [ident hasPrefix:[bid stringByAppendingString:@"."]] || [ident containsString:bid];
                if (!match) continue;

                NSString *p = [NSString stringWithFormat:@"%@/%@", base, uuid];
                [self logMessage:@"[AppDataCleaner] Related container: %@ (ident=%@)", p, ident];
                [self completelyWipeContainer:p];
            }
        }
    }
}

- (void)_wipeRelatedSystemGroupContainersForIdentifiers:(NSArray<NSString *> *)idents {
    if (![idents isKindOfClass:[NSArray class]] || idents.count == 0) return;

    NSArray<NSString *> *bases = @[
        @"/var/mobile/Containers/Shared/SystemGroup",
        @"/containers/Shared/SystemGroup"
    ];

    for (NSString *base in bases) {
        if (![_fileManager fileExistsAtPath:base]) continue;
        NSArray *uuids = [self listDirectoriesInPath:base];
        for (NSString *uuid in uuids) {
            if (![uuid isKindOfClass:[NSString class]] || !uuid.length) continue;
            NSString *metadataPath = [NSString stringWithFormat:@"%@/%@/.com.apple.mobile_container_manager.metadata.plist", base, uuid];
            NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
            NSString *ident = [metadata[@"MCMMetadataIdentifier"] isKindOfClass:[NSString class]] ? metadata[@"MCMMetadataIdentifier"] : nil;
            if (!ident.length) continue;

            BOOL match = NO;
            for (NSString *needle in idents) {
                if (![needle isKindOfClass:[NSString class]] || !needle.length) continue;
                if ([ident isEqualToString:needle] || [ident containsString:needle]) {
                    match = YES;
                    break;
                }
            }
            if (!match) continue;

            NSString *p = [NSString stringWithFormat:@"%@/%@", base, uuid];
            [self logMessage:@"[AppDataCleaner] Related systemgroup container: %@ (ident=%@)", p, ident];
            [self completelyWipeContainer:p];
        }
    }
}

- (void)_wipeContainersInBasePaths:(NSArray<NSString *> *)bases
               matchingSubstrings:(NSArray<NSString *> *)needles
                             tag:(NSString *)tag {
    if (![bases isKindOfClass:[NSArray class]] || !bases.count) return;
    if (![needles isKindOfClass:[NSArray class]] || !needles.count) return;

    NSMutableArray<NSString *> *needlesLower = [NSMutableArray array];
    for (NSString *n in needles) {
        if ([n isKindOfClass:[NSString class]] && n.length) {
            [needlesLower addObject:[n lowercaseString]];
        }
    }
    if (!needlesLower.count) return;

    NSUInteger matched = 0;
    for (NSString *base in bases) {
        if (![base isKindOfClass:[NSString class]] || !base.length) continue;
        if (![_fileManager fileExistsAtPath:base]) continue;

        NSArray *uuids = [self listDirectoriesInPath:base];
        [self logMessage:@"[AppDataCleaner] %@ scanning %@ (count=%lu)", tag ?: @"", base, (unsigned long)uuids.count];
        for (NSString *uuid in uuids) {
            if (![uuid isKindOfClass:[NSString class]] || !uuid.length) continue;
            NSString *metadataPath = [NSString stringWithFormat:@"%@/%@/.com.apple.mobile_container_manager.metadata.plist", base, uuid];
            NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
            NSString *ident = [metadata[@"MCMMetadataIdentifier"] isKindOfClass:[NSString class]] ? metadata[@"MCMMetadataIdentifier"] : nil;
            if (!ident.length) continue;
            NSString *identLower = [ident lowercaseString];

            BOOL match = NO;
            for (NSString *needle in needlesLower) {
                if ([identLower containsString:needle]) {
                    match = YES;
                    break;
                }
            }
            if (!match) continue;

            NSString *p = [NSString stringWithFormat:@"%@/%@", base, uuid];
            matched++;
            [self logMessage:@"[AppDataCleaner] %@ matched container: %@ (ident=%@)", tag ?: @"", p, ident];
            [self completelyWipeContainer:p];
        }
    }
    if (!matched) {
        [self logMessage:@"[AppDataCleaner] %@ no containers matched substrings=%@", tag ?: @"", needlesLower];
    }
}

- (void)_wipeDataContainersByIdentifierPrefixOrSubstring:(NSArray<NSString *> *)prefixes
                                              substrings:(NSArray<NSString *> *)substrings
                                                    tag:(NSString *)tag {
    NSArray<NSString *> *bases = @[
        @"/var/mobile/Containers/Data/Application",
        @"/containers/Data/Application"
    ];
    NSMutableArray<NSString *> *pfx = [NSMutableArray array];
    for (NSString *s in prefixes) {
        if ([s isKindOfClass:[NSString class]] && s.length) [pfx addObject:s];
    }
    NSMutableArray<NSString *> *subs = [NSMutableArray array];
    for (NSString *s in substrings) {
        if ([s isKindOfClass:[NSString class]] && s.length) [subs addObject:[s lowercaseString]];
    }

    NSUInteger matched = 0;
    for (NSString *base in bases) {
        if (![_fileManager fileExistsAtPath:base]) continue;
        NSArray *uuids = [self listDirectoriesInPath:base];
        [self logMessage:@"[AppDataCleaner] %@ scanning %@ (count=%lu)", tag ?: @"", base, (unsigned long)uuids.count];
        for (NSString *uuid in uuids) {
            if (![uuid isKindOfClass:[NSString class]] || !uuid.length) continue;
            NSString *metadataPath = [NSString stringWithFormat:@"%@/%@/.com.apple.mobile_container_manager.metadata.plist", base, uuid];
            NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
            NSString *ident = [metadata[@"MCMMetadataIdentifier"] isKindOfClass:[NSString class]] ? metadata[@"MCMMetadataIdentifier"] : nil;
            if (!ident.length) continue;

            BOOL match = NO;
            for (NSString *pre in pfx) {
                if ([ident hasPrefix:pre]) { match = YES; break; }
            }
            if (!match) {
                NSString *lower = [ident lowercaseString];
                for (NSString *sub in subs) {
                    if ([lower containsString:sub]) { match = YES; break; }
                }
            }
            if (!match) continue;

            NSString *p = [NSString stringWithFormat:@"%@/%@", base, uuid];
            matched++;
            [self logMessage:@"[AppDataCleaner] %@ matched data container: %@ (ident=%@)", tag ?: @"", p, ident];
            [self completelyWipeContainer:p];
        }
    }
    if (!matched) {
        [self logMessage:@"[AppDataCleaner] %@ no data containers matched", tag ?: @""];
    }
}

- (void)_scrubWebKitStateInSharedContainerBase:(NSString *)base tag:(NSString *)tag {
    if (!base.length) return;
    if (![_fileManager fileExistsAtPath:base]) {
        [self logMessage:@"[AppDataCleaner] %@ shared base missing: %@", tag ?: @"", base];
        return;
    }

    NSArray *uuids = [self listDirectoriesInPath:base];
    [self logMessage:@"[AppDataCleaner] %@ scrub scan %@ (count=%lu)", tag ?: @"", base, (unsigned long)uuids.count];

    for (NSString *uuid in uuids) {
        if (![uuid isKindOfClass:[NSString class]] || !uuid.length) continue;
        NSString *containerPath = [NSString stringWithFormat:@"%@/%@", base, uuid];
        NSString *metadataPath = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"]; 
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *ident = [metadata[@"MCMMetadataIdentifier"] isKindOfClass:[NSString class]] ? metadata[@"MCMMetadataIdentifier"] : nil;

        // Detect Safari/WebKit state by structure, not identifier (ident can be opaque on some builds).
        NSArray<NSString *> *pathsToNuke = @[
            @"Library/WebKit",
            @"Library/Safari",
            @"Library/Cookies",
            @"Library/HTTPStorages",
            @"Library/Caches/com.apple.Safari",
            @"Library/Caches/com.apple.mobilesafari",
            @"Library/Caches/com.apple.SafariViewService"
        ];
        BOOL hasAny = NO;
        for (NSString *rel in pathsToNuke) {
            NSString *p = [containerPath stringByAppendingPathComponent:rel];
            if ([_fileManager fileExistsAtPath:p]) { hasAny = YES; break; }
        }

        // Also detect any WebKit caches via glob patterns.
        if (!hasAny) {
            NSString *caches = [containerPath stringByAppendingPathComponent:@"Library/Caches"]; 
            if ([_fileManager fileExistsAtPath:caches]) {
                // Cheap heuristic: if any entry begins with com.apple.WebKit.
                NSArray *entries = [_fileManager contentsOfDirectoryAtPath:caches error:nil];
                for (NSString *e in entries) {
                    if ([[e lowercaseString] containsString:@"webkit"] || [[e lowercaseString] containsString:@"safari"]) {
                        hasAny = YES;
                        break;
                    }
                }
            }
        }

        if (!hasAny) continue;

        [self logMessage:@"[AppDataCleaner] %@ scrubbing container=%@ ident=%@", tag ?: @"", containerPath, ident ?: @""];

        // Kill helpers again to reduce races.
        PXStopSafariDaemonsBestEffort(self);

        for (NSString *rel in pathsToNuke) {
            NSString *p = [containerPath stringByAppendingPathComponent:rel];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@' 2>/dev/null || true", p]];
        }

        // Nuke WebKit caches with both dot and dash variants.
        NSString *cachesDir = [containerPath stringByAppendingPathComponent:@"Library/Caches"]; 
        if ([_fileManager fileExistsAtPath:cachesDir]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'/com.apple.WebKit.* '%@'/com.apple.WebKit-* 2>/dev/null || true", cachesDir, cachesDir]];
        }

        // Remove any Safari/WebKit preferences under the container.
        NSString *prefsDir = [containerPath stringByAppendingPathComponent:@"Library/Preferences"]; 
        if ([_fileManager fileExistsAtPath:prefsDir]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '%@'/com.apple.Safari*.plist '%@'/com.apple.WebKit*.plist 2>/dev/null || true", prefsDir, prefsDir]];
        }
    }
}

- (void)_wipeMobileSafariSystemStores {
    [self logMessage:@"[AppDataCleaner] MobileSafari: wiping global Safari/WebKit/Cookies stores..."];

    // Ensure processes are stopped first to avoid sqlite "database is locked" and detached DB crashes.
    PXStopSafariDaemonsBestEffort(self);

    // Google sign-in can surface "Continue as <gmail>" from system Accounts even when cookies are gone.
    // For Safari clear-data, we treat it as web session state and remove Google account rows best-effort.
    {
        NSString *accountsDB = PXFirstExistingPath(_fileManager, @[
            @"/var/mobile/Library/Accounts/Accounts3.sqlite",
            @"/private/var/mobile/Library/Accounts/Accounts3.sqlite",
            @"/var/jb/var/mobile/Library/Accounts/Accounts3.sqlite",
            @"/private/var/jb/var/mobile/Library/Accounts/Accounts3.sqlite"
        ]);
        if (accountsDB.length && [_fileManager fileExistsAtPath:accountsDB]) {
            [self logMessage:@"[AppDataCleaner] MobileSafari: removing Google accounts from Accounts3 (shared) ..."]; 

            // Stop accountsd before touching DB (avoid "database is locked").
            PXKillallByName(@"accountsd", SIGTERM);
            [NSThread sleepForTimeInterval:0.2];
            PXKillallByName(@"accountsd", SIGKILL);
            [NSThread sleepForTimeInterval:0.2];

            sqlite3 *db = NULL;
            int rc = sqlite3_open_v2(accountsDB.UTF8String, &db, SQLITE_OPEN_READWRITE, NULL);
            if (rc != SQLITE_OK || !db) {
                NSString *msg = db ? [NSString stringWithUTF8String:sqlite3_errmsg(db)] : @"open failed";
                [self logMessage:@"[AppDataCleaner] MobileSafari: Accounts3 open failed rc=%d %@", rc, msg ?: @""];
                if (db) sqlite3_close(db);
            } else {
                sqlite3_busy_timeout(db, 3000);

                NSString *beforeCount = PXSQLiteScalar(db, @"SELECT count(*) FROM ZACCOUNT;");
                [self logMessage:@"[AppDataCleaner] MobileSafari: Accounts3 ZACCOUNT count before=%@", beforeCount ?: @"(nil)"];
                PXSQLiteLogAccountsSample(self, db, @"MobileSafari(before)");

                NSString *typeCount = PXSQLiteScalar(db, @"SELECT count(*) FROM ZACCOUNTTYPE WHERE ZIDENTIFIER LIKE '%google%' OR ZIDENTIFIER LIKE '%gmail%';");
                if (typeCount.length) {
                    [self logMessage:@"[AppDataCleaner] MobileSafari: google-ish account types=%@", typeCount];
                }

                NSMutableDictionary<NSString *, NSSet<NSString *> *> *colCache = [NSMutableDictionary dictionary];
                BOOL hasZAccountType = PXSQLiteTableHasColumnCached(db, @"ZACCOUNT", @"ZACCOUNTTYPE", colCache);

                NSMutableArray<NSString *> *preds = [NSMutableArray array];
                if (hasZAccountType) {
                    [preds addObject:@"ZACCOUNTTYPE IN (SELECT Z_PK FROM ZACCOUNTTYPE WHERE ZIDENTIFIER LIKE '%google%' OR ZIDENTIFIER LIKE '%gmail%')"]; 
                }
                // Match on any existing identifier-like columns.
                NSArray<NSString *> *maybeCols = @[
                    @"ZIDENTIFIER",
                    @"ZUSERNAME",
                    @"ZACCOUNTDESCRIPTION",
                    @"ZDISPLAYNAME",
                    @"ZEMAILADDRESS",
                    @"ZOWNINGBUNDLEID"
                ];
                for (NSString *c in maybeCols) {
                    if (PXSQLiteTableHasColumnCached(db, @"ZACCOUNT", c, colCache)) {
                        [preds addObject:[NSString stringWithFormat:@"%@ LIKE '%%google%%' OR %@ LIKE '%%gmail%%'", c, c]];
                    }
                }

                NSString *where = preds.count ? [preds componentsJoinedByString:@" OR "] : nil;

                NSString *errMsg = nil;
                PXSQLiteExec(db, @"PRAGMA busy_timeout=3000;", NULL);
                PXSQLiteExec(db, @"BEGIN IMMEDIATE;", &errMsg);
                if (errMsg.length) {
                    [self logMessage:@"[AppDataCleaner] MobileSafari: BEGIN IMMEDIATE failed %@", errMsg];
                    errMsg = nil;
                }

                if (where.length) {
                    NSString *del = [NSString stringWithFormat:@"DELETE FROM ZACCOUNT WHERE %@;", where];
                    BOOL ok = PXSQLiteExec(db, del, &errMsg);
                    int changes = sqlite3_changes(db);
                    [self logMessage:@"[AppDataCleaner] MobileSafari: ZACCOUNT delete ok=%d changes=%d %@", ok, changes, errMsg.length ? errMsg : @""];
                    errMsg = nil;
                } else {
                    [self logMessage:@"[AppDataCleaner] MobileSafari: Accounts3 schema unknown; skip delete"]; 
                }

                // Best-effort cleanup of orphan rows (ignore failures if tables don't exist).
                PXSQLiteExec(db, @"DELETE FROM ZACCOUNTPROPERTY WHERE ZOWNER NOT IN (SELECT Z_PK FROM ZACCOUNT);", NULL);
                PXSQLiteExec(db, @"DELETE FROM ZCREDENTIALITEM WHERE ZOWNER NOT IN (SELECT Z_PK FROM ZACCOUNT);", NULL);

                PXSQLiteExec(db, @"COMMIT;", &errMsg);
                if (errMsg.length) {
                    [self logMessage:@"[AppDataCleaner] MobileSafari: COMMIT failed %@", errMsg];
                    errMsg = nil;
                    PXSQLiteExec(db, @"ROLLBACK;", NULL);
                }
                PXSQLiteExec(db, @"PRAGMA wal_checkpoint(TRUNCATE);", NULL);

                NSString *afterCount = PXSQLiteScalar(db, @"SELECT count(*) FROM ZACCOUNT;");
                [self logMessage:@"[AppDataCleaner] MobileSafari: Accounts3 ZACCOUNT count after=%@", afterCount ?: @"(nil)"];
                PXSQLiteLogAccountsSample(self, db, @"MobileSafari(after)");

                // Debug sample of account types (helps tune predicates across iOS versions)
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(db, "SELECT ZIDENTIFIER FROM ZACCOUNTTYPE LIMIT 12;", -1, &st, NULL) == SQLITE_OK && st) {
                    NSMutableArray *ids = [NSMutableArray array];
                    while (sqlite3_step(st) == SQLITE_ROW) {
                        const unsigned char *txt = sqlite3_column_text(st, 0);
                        if (txt) [ids addObject:[NSString stringWithUTF8String:(const char *)txt]];
                    }
                    sqlite3_finalize(st);
                    if (ids.count) {
                        [self logMessage:@"[AppDataCleaner] MobileSafari: ZACCOUNTTYPE sample=%@", [ids componentsJoinedByString:@", "]];
                    }
                } else if (st) {
                    sqlite3_finalize(st);
                }

                sqlite3_close(db);
            }

            // Restart accountsd so UI refreshes.
            PXKillallByName(@"accountsd", SIGTERM);
        } else {
            [self logMessage:@"[AppDataCleaner] MobileSafari: Accounts3.sqlite not found; skipping Google accounts cleanup"]; 
        }
    }

    NSArray<NSString *> *libraryBases = @[
        @"/var/mobile/Library",
        @"/private/var/mobile/Library",
        @"/var/jb/var/mobile/Library",
        @"/private/var/jb/var/mobile/Library"
    ];

    for (NSString *base in libraryBases) {
        if (![_fileManager fileExistsAtPath:base]) {
            continue;
        }

        // Preferences that affect Safari session/cookies.
        NSString *prefsDir = [base stringByAppendingPathComponent:@"Preferences"];
        if ([_fileManager fileExistsAtPath:prefsDir]) {
            NSArray<NSString *> *prefs = @[
                @"com.apple.Safari.plist",
                @"com.apple.mobilesafari.plist",
                @"com.apple.SafariViewService.plist",
                @"com.apple.WebKit.WebContent.plist",
                @"com.apple.WebKit.Networking.plist",
                @"com.apple.WebKit.GPU.plist",
                @"com.apple.WebKit.plist"
            ];
            for (NSString *p in prefs) {
                NSString *full = [prefsDir stringByAppendingPathComponent:p];
                [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '%@' 2>/dev/null || true", full]];
            }
        }

        // Caches that can carry session state.
        NSString *cachesDir = [base stringByAppendingPathComponent:@"Caches"];
        if ([_fileManager fileExistsAtPath:cachesDir]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@/com.apple.Safari' 2>/dev/null || true", cachesDir]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@/com.apple.mobilesafari' 2>/dev/null || true", cachesDir]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@/com.apple.SafariViewService' 2>/dev/null || true", cachesDir]];
            // Handle both dot and dash variants.
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'/com.apple.WebKit.* '%@'/com.apple.WebKit-* 2>/dev/null || true", cachesDir, cachesDir]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@/com.apple.nsurlsessiond' 2>/dev/null || true", cachesDir]];
        }

        NSString *safariDir = [base stringByAppendingPathComponent:@"Safari"];
        if ([_fileManager fileExistsAtPath:safariDir]) {
            // Preserve bookmarks DB by default; nuke session/history/website data.
            [self runCommandWithPrivileges:[NSString stringWithFormat:
                @"find '%@' -mindepth 1 -maxdepth 1 -not -name 'Bookmarks.db' -not -name 'Bookmarks.db-wal' -not -name 'Bookmarks.db-shm' -exec rm -rf {} + 2>/dev/null || true",
                safariDir]];
        }

        // WebKit global stores are the main source of persistent web sessions.
        NSString *webKitDir = [base stringByAppendingPathComponent:@"WebKit"];
        if ([_fileManager fileExistsAtPath:webKitDir]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@' 2>/dev/null || true", webKitDir]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"mkdir -p '%@' 2>/dev/null || true", webKitDir]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"chown -R mobile:mobile '%@' 2>/dev/null || true", webKitDir]];
        }

        NSString *cookiesDir = [base stringByAppendingPathComponent:@"Cookies"];
        if ([_fileManager fileExistsAtPath:cookiesDir]) {
            // Cookie stores can be global. Removing them clears Safari sessions/cookies.
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '%@/Cookies.binarycookies' 2>/dev/null || true", cookiesDir]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '%@/Cookies.sqlite' '%@/Cookies.sqlite-wal' '%@/Cookies.sqlite-shm' 2>/dev/null || true", cookiesDir, cookiesDir, cookiesDir]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '%@'/*.binarycookies 2>/dev/null || true", cookiesDir]];
        }
    }

    // Flush preference/caches used by Safari.
    PXKillallByName(@"cfprefsd", SIGTERM);
    PXKillallByName(@"webbookmarksd", SIGTERM);

    // Also wipe data containers for WebKit helper services; cookies/session can live there.
    [self _wipeRelatedDataContainersForBundleIDs:@[
        @"com.apple.SafariViewService",
        @"com.apple.WebKit.Networking",
        @"com.apple.WebKit.WebContent",
        @"com.apple.WebKit.GPU"
    ]];

    // Fallback: on some builds these WebKit service containers do not use the exact bundle id.
    // Wipe any data container whose identifier clearly belongs to Apple WebKit/Safari services.
    [self _wipeDataContainersByIdentifierPrefixOrSubstring:@[
        @"com.apple.WebKit.",
        @"com.apple.safariviewservice",
        @"com.apple.mobilesafari"
    ] substrings:@[
        @"com.apple.webkit",
        @"safariviewservice"
    ] tag:@"MobileSafari(webkit-data)"];

    // Also wipe SystemGroup containers used by WebKit (common for Safari/SafariViewService).
    [self _wipeRelatedSystemGroupContainersForIdentifiers:@[
        @"systemgroup.com.apple.WebKit",
        @"systemgroup.com.apple.WebKit.Networking",
        @"systemgroup.com.apple.WebKit.WebContent",
        @"systemgroup.com.apple.WebKit.GPU",
        @"systemgroup.com.apple.SafariViewService",
        @"systemgroup.com.apple.mobilesafari",
        @"com.apple.WebKit",
        @"com.apple.SafariViewService"
    ]];

    // Broader scan: some iOS versions store WebKit state in AppGroup/SystemGroup containers with different identifiers.
    // This is intentionally aggressive for Safari clear-data.
    [self _wipeContainersInBasePaths:@[@"/var/mobile/Containers/Shared/SystemGroup", @"/containers/Shared/SystemGroup"]
                  matchingSubstrings:@[@"webkit", @"safariviewservice", @"mobilesafari"]
                                tag:@"MobileSafari(systemgroup)"];
    [self _wipeContainersInBasePaths:@[@"/var/mobile/Containers/Shared/AppGroup", @"/containers/Shared/AppGroup"]
                  matchingSubstrings:@[@"webkit", @"safariviewservice", @"mobilesafari"]
                                tag:@"MobileSafari(appgroup)"];

    // Final fallback: scrub WebKit/Safari state by filesystem structure inside shared containers.
    [self _scrubWebKitStateInSharedContainerBase:@"/var/mobile/Containers/Shared/AppGroup" tag:@"MobileSafari(appgroup-scrub)"];
    [self _scrubWebKitStateInSharedContainerBase:@"/containers/Shared/AppGroup" tag:@"MobileSafari(appgroup-scrub)"];
    [self _scrubWebKitStateInSharedContainerBase:@"/var/mobile/Containers/Shared/SystemGroup" tag:@"MobileSafari(systemgroup-scrub)"];
    [self _scrubWebKitStateInSharedContainerBase:@"/containers/Shared/SystemGroup" tag:@"MobileSafari(systemgroup-scrub)"];

    // Optional: SafeBrowsing can persist per-user browsing state.
    [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/SafariSafeBrowsing 2>/dev/null || true"]; 

    // CFNetwork caches can hold cookie/state caches outside WebKit dir.
    [self runCommandWithPrivileges:@"rm -rf /var/mobile/Library/Caches/com.apple.CFNetwork 2>/dev/null || true"]; 
    [self runCommandWithPrivileges:@"rm -rf /private/var/mobile/Library/Caches/com.apple.CFNetwork 2>/dev/null || true"]; 

    sync();
}

- (NSArray *)findExtensionDataContainersForBundleID:(NSString *)bundleID {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *containersPath = @"/var/mobile/Containers/Data/Application";
    NSMutableArray *extensionContainers = [NSMutableArray array];
    NSError *error = nil;
    
    if (![fileManager fileExistsAtPath:containersPath]) {
        NSLog(@"[AppDataCleaner] Directory does not exist: %@", containersPath);
        return extensionContainers;
    }
    
    NSArray *containers = [fileManager contentsOfDirectoryAtPath:containersPath error:&error];
    if (error) {
        NSLog(@"[AppDataCleaner] Error listing data containers: %@", error);
        return extensionContainers;
    }
    
    // Get the base app identifier component (e.g., "com.company" from "com.company.appname")
    NSArray *bundleComponents = [bundleID componentsSeparatedByString:@"."];
    NSString *baseIdentifier = @"";
    if (bundleComponents.count >= 2) {
        baseIdentifier = [NSString stringWithFormat:@"%@.%@", bundleComponents[0], bundleComponents[1]];
    }
    
    for (NSString *container in containers) {
        if ([container hasPrefix:@"."]) continue;
        
        NSString *containerPath = [containersPath stringByAppendingPathComponent:container];
        NSString *metadataPath = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        
        if ([fileManager fileExistsAtPath:metadataPath]) {
                NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
                NSString *containerBundleID = metadata[@"MCMMetadataIdentifier"];
                
            // Check if this is an extension of our app
            if (containerBundleID && ![containerBundleID isEqualToString:bundleID] &&
                [containerBundleID hasPrefix:baseIdentifier] && 
                ([containerBundleID containsString:@".extension."] || 
                 [containerBundleID hasSuffix:@".extension"] ||
                 [containerBundleID containsString:@".appex."] ||
                 [containerBundleID hasSuffix:@".appex"] ||
                 [containerBundleID containsString:@".plugin."] ||
                 [containerBundleID hasSuffix:@".plugin"])) {
                
                NSLog(@"[AppDataCleaner] Found extension container UUID: %@ for %@", container, containerBundleID);
                [extensionContainers addObject:container];
            }
        }
    }
    
    NSLog(@"[AppDataCleaner] Found %lu extension containers for %@", (unsigned long)extensionContainers.count, bundleID);
    return extensionContainers;
}

- (void)cleanAppGroupContainers:(NSString *)bundleID {
    [self logMessage:@"[AppDataCleaner] Cleaning app group containers for %@", bundleID];
    
    // First, check if the app has its own app groups
    NSArray *groupUUIDs = [self findGroupContainerUUIDsForBundleID:bundleID];
    NSArray *rootlessGroupUUIDs = [self findRootlessAppGroupUUIDs:bundleID];
    
    [self logMessage:@"[AppDataCleaner] Found %lu group containers", (unsigned long)groupUUIDs.count];
    
    // Get the app's base identifier components for searching
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *companyName = parts.count > 1 ? parts[1] : @"";
    
    // Handle standard app group containers
    for (NSString *uuid in groupUUIDs) {
        NSString *containerPath = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", uuid];
        [self logMessage:@"[AppDataCleaner] Checking app group container: %@", uuid];
        
        // Get and log the group identifier before wiping
        NSString *metadataPath = [NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", containerPath];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        NSString *groupIdentifier = metadata[@"MCMMetadataIdentifier"];
        [self logMessage:@"[AppDataCleaner] Group identifier: %@", groupIdentifier];
        
        // Safety check: Don't wipe system groups
        if ([groupIdentifier hasPrefix:@"group.com.apple"] || [groupIdentifier hasPrefix:@"com.apple"]) {
             [self logMessage:@"[AppDataCleaner] SKIPPING system group: %@", groupIdentifier];
             continue;
        }
        
        // STRICT matching: Only wipe groups that DEFINITELY belong to this app
        // For com.facebook.Facebook, we should only wipe groups containing "facebook"
        BOOL isAppGroup = NO;
        
        // Check 1: Group contains full bundleID (e.g., group.com.facebook.Facebook)
        if ([groupIdentifier containsString:bundleID]) {
            isAppGroup = YES;
            [self logMessage:@"[AppDataCleaner] Matched by bundleID"];
        }
        
        // Check 2: Group contains company name (e.g., group.com.facebook.family)
        // But ONLY if companyName is meaningful (not "com", "org", "net", etc.)
        if (!isAppGroup && companyName.length > 3 && 
            ![companyName isEqualToString:@"com"] && 
            ![companyName isEqualToString:@"org"] && 
            ![companyName isEqualToString:@"net"] &&
            ![companyName isEqualToString:@"app"]) {
            // Case-insensitive check for company name
            if ([[groupIdentifier lowercaseString] containsString:[companyName lowercaseString]]) {
                isAppGroup = YES;
                [self logMessage:@"[AppDataCleaner] Matched by company name: %@", companyName];
            }
        }
        
        // DO NOT use firstComponent (it's usually "com" which matches everything!)
        
        if (isAppGroup) {
            // This is definitely owned by our app - completely wipe it
            [self logMessage:@"[AppDataCleaner] Wiping owned group container: %@", uuid];
            [self completelyWipeContainer:containerPath];
        } else {
            // This does NOT belong to our app - SKIP it entirely
            [self logMessage:@"[AppDataCleaner] SKIPPING unrelated group: %@", groupIdentifier];
            // Don't even do selective cleaning on other apps' groups
        }
    }
    
    // Handle rootless app group containers using the same logic
    for (NSString *uuid in rootlessGroupUUIDs) {
        NSString *containerPath = [NSString stringWithFormat:@"/containers/Shared/AppGroup/%@", uuid];
        [self logMessage:@"[AppDataCleaner] Checking rootless app group container: %@", uuid];
        
        // Get and log the group identifier
        NSString *metadataPath = [NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", containerPath];
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        id groupIdentifier = metadata[@"MCMMetadataIdentifier"];
        
        NSString *groupIdString = nil;
        if ([groupIdentifier isKindOfClass:[NSString class]]) {
            groupIdString = (NSString *)groupIdentifier;
        }
        
        [self logMessage:@"[AppDataCleaner] Rootless group identifier: %@", groupIdString];
        
        if (groupIdString && ([groupIdString hasPrefix:@"group.com.apple"] || [groupIdString hasPrefix:@"com.apple"])) {
             [self logMessage:@"[AppDataCleaner] SKIPPING rootless system group: %@", groupIdString];
             continue;
        }
        
        // STRICT matching: Only wipe groups that DEFINITELY belong to this app
        BOOL isAppGroup = NO;
        
        // Check 1: Group contains full bundleID
        if (groupIdString && [groupIdString containsString:bundleID]) {
            isAppGroup = YES;
        }
        
        // Check 2: Group contains company name (e.g., "facebook")
        if (!isAppGroup && groupIdString && companyName.length > 3 && 
            ![companyName isEqualToString:@"com"] && 
            ![companyName isEqualToString:@"org"] && 
            ![companyName isEqualToString:@"net"]) {
            if ([[groupIdString lowercaseString] containsString:[companyName lowercaseString]]) {
                isAppGroup = YES;
            }
        }
        
        if (isAppGroup) {
            [self logMessage:@"[AppDataCleaner] Wiping owned rootless group: %@", uuid];
            [self completelyWipeContainer:containerPath];
        } else {
            [self logMessage:@"[AppDataCleaner] SKIPPING unrelated rootless group: %@", groupIdString];
        }
    }
}



- (void)cleanAppSpecificFilesInSharedContainer:(NSString *)containerPath bundleID:(NSString *)bundleID appName:(NSString *)appName companyName:(NSString *)companyName {
    NSFileManager *fileManager = [NSFileManager defaultManager];
                            NSError *error = nil;
    NSArray *contents = [fileManager contentsOfDirectoryAtPath:containerPath error:&error];
    
    if (error) {
        NSLog(@"[AppDataCleaner] Error accessing container %@: %@", containerPath, error);
        return;
    }
    
    // First pass: identify items that are definitely related to our app
    for (NSString *item in contents) {
        if ([item hasPrefix:@".com.apple"]) continue; // Skip system files
        
        BOOL isAppRelated = NO;
        
        // Very likely related to our app
        if ([item containsString:bundleID] || 
            (appName.length > 3 && [item containsString:appName]) || 
            (companyName.length > 3 && [item containsString:companyName])) {
            isAppRelated = YES;
        }
        
        // Check additional app-specific patterns
        NSArray *appSpecificPatterns = @[@"auth", @"credentials", @"token", @"session", appName.lowercaseString];
        for (NSString *pattern in appSpecificPatterns) {
            if ([item.lowercaseString containsString:pattern]) {
                isAppRelated = YES;
                break;
            }
        }
        
        if (isAppRelated) {
            NSString *itemPath = [containerPath stringByAppendingPathComponent:item];
            NSLog(@"[AppDataCleaner] Removing app-specific item from shared group: %@", itemPath);
            [self fixPermissionsAndRemovePath:itemPath];
        }
    }
    
    // Second pass: handle database files that might contain app data
    NSString *findDbCommand = [NSString stringWithFormat:@"find '%@' -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite-*'", containerPath];
    NSString *output = [self runCommandAndGetOutput:findDbCommand];
    if (output.length > 0) {
        NSArray *dbFiles = [output componentsSeparatedByString:@"\n"];
        
        for (NSString *dbFile in dbFiles) {
            if (dbFile.length > 0 && [fileManager fileExistsAtPath:dbFile]) {
                NSLog(@"[AppDataCleaner] Cleaning app data from database: %@", dbFile);
                [self cleanDatabaseFile:dbFile bundleID:bundleID appName:appName companyName:companyName];
            }
        }
    }
}

- (void)deepCleanSystemSharedContainer:(NSString *)containerPath bundleID:(NSString *)bundleID appName:(NSString *)appName companyName:(NSString *)companyName {
    // Get the container UUID from the path
    NSString *uuid = [containerPath lastPathComponent];
    
    // Handle specific known problematic containers differently based on their content types
    if ([uuid isEqualToString:@"1E1577AF-3EC2-4748-ADE9-937471B52738"] || // File Provider Storage
        [uuid isEqualToString:@"101EFFE4-1A84-480A-B865-EDE04D8B9923"]) { // File Provider LocalStorage
        NSLog(@"[AppDataCleaner] Deep cleaning File Provider container: %@", containerPath);
        
        // Clean File Provider Storage directories that might reference our app
        NSString *command = [NSString stringWithFormat:@"find '%@' -type d -name '*%@*' -exec rm -rf {} \\; 2>/dev/null || true", 
                           containerPath, appName];
        [self runCommandWithPrivileges:command];
        
        // Also search for company names in the directory names
        if (companyName.length > 0) {
            command = [NSString stringWithFormat:@"find '%@' -type d -name '*%@*' -exec rm -rf {} \\; 2>/dev/null || true", 
                      containerPath, companyName];
            [self runCommandWithPrivileges:command];
        }
    } 
    else if ([uuid isEqualToString:@"1E17A582-F7DC-429D-BE50-4A69226EC3FA"]) { // Maps
        NSLog(@"[AppDataCleaner] Deep cleaning Maps container: %@", containerPath);
        
        // Clean map data entries related to our app
        NSString *mapsDbPath = [containerPath stringByAppendingPathComponent:@"Maps/Maps.sqlite"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:mapsDbPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM location_bookmarks WHERE title LIKE '%%%@%%' OR subtitle LIKE '%%%@%%';\" 2>/dev/null || true", mapsDbPath, appName, appName]];
            
            // Add specific cleaning for Lyft and Zimride names
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM location_bookmarks WHERE title LIKE '%%lyft%%' OR subtitle LIKE '%%lyft%%';\" 2>/dev/null || true", mapsDbPath]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM location_bookmarks WHERE title LIKE '%%zimride%%' OR subtitle LIKE '%%zimride%%';\" 2>/dev/null || true", mapsDbPath]];
            
            if (companyName.length > 0) {
                [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM location_bookmarks WHERE title LIKE '%%%@%%' OR subtitle LIKE '%%%@%%';\" 2>/dev/null || true", mapsDbPath, companyName, companyName]];
            }
            
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"VACUUM;\" 2>/dev/null || true", mapsDbPath]];
        }
    }
    else if ([uuid isEqualToString:@"0DCF64D5-9838-4EFF-8D0E-8CCB197B65C1"]) { // Lyft group
        NSLog(@"[AppDataCleaner] Deep cleaning Lyft container: %@", containerPath);
        
        // If our app is a transportation app, we should clean cross-app references
        NSString *lyftStoragePath = [containerPath stringByAppendingPathComponent:@"com.zimride.instant.storage"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:lyftStoragePath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", lyftStoragePath]];
        }
        
        // Check com.lyft.ios storage path
        NSString *lyftIosStoragePath = [containerPath stringByAppendingPathComponent:@"com.lyft.ios.storage"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:lyftIosStoragePath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", lyftIosStoragePath]];
        }
        
        // Also check old Lyft storage path
        NSString *oldLyftStoragePath = [containerPath stringByAppendingPathComponent:@"com.lyft.ios.storage"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:oldLyftStoragePath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", oldLyftStoragePath]];
        }
        
        // Check for com.lyft.ios directory
        NSString *lyftIosPath = [containerPath stringByAppendingPathComponent:@"com.lyft.ios"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:lyftIosPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", lyftIosPath]];
        }
        
        // Check for alternate storage paths too
        NSString *alternateLyftPath = [containerPath stringByAppendingPathComponent:@"com.zimride.instant"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:alternateLyftPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", alternateLyftPath]];
        }
        
        // Check old Lyft path
        NSString *alternateOldLyftPath = [containerPath stringByAppendingPathComponent:@"com.lyft.me"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:alternateOldLyftPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", alternateOldLyftPath]];
        }
        
        // Clean credentials
        NSString *credentialsPath = [containerPath stringByAppendingPathComponent:@"Credentials"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:credentialsPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", credentialsPath]];
        }
        
        // Clean tokens
        NSString *tokensPath = [containerPath stringByAppendingPathComponent:@"Tokens"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:tokensPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", tokensPath]];
        }
        
        // Clean ride history
        NSString *ridesPath = [containerPath stringByAppendingPathComponent:@"RideHistory"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:ridesPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", ridesPath]];
        }
        
        // Clean saved locations
        NSString *locationsPath = [containerPath stringByAppendingPathComponent:@"SavedLocations"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:locationsPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", locationsPath]];
        }
        
        // Clean databases
        NSString *dbsPath = [containerPath stringByAppendingPathComponent:@"Databases"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:dbsPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -name '*.db' -o -name '*.sqlite' -exec rm -f {} \\; 2>/dev/null || true", dbsPath]];
        }
        
        // Find and clean any files/folders containing "lyft" in the name
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -type d -name '*lyft*' -exec rm -rf {} \\; 2>/dev/null || true", containerPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -type f -name '*lyft*' -exec rm -f {} \\; 2>/dev/null || true", containerPath]];
        
        // Find and clean any files/folders containing "zimride" in the name
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -type d -name '*zimride*' -exec rm -rf {} \\; 2>/dev/null || true", containerPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -type f -name '*zimride*' -exec rm -f {} \\; 2>/dev/null || true", containerPath]];
    }
    else if ([uuid isEqualToString:@"F7DD9815-AC23-47C4-A316-59779EDAB38D"]) { // Uber group
        NSLog(@"[AppDataCleaner] Deep cleaning Uber container: %@", containerPath);
        
        // Clean Uber files - target both storage and credentials paths
        NSString *uberStoragePath = [containerPath stringByAppendingPathComponent:@"com.uber.ios.storage"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:uberStoragePath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", uberStoragePath]];
        }
        
        // Check for Helix (alternative Uber name)
        NSString *helixStoragePath = [containerPath stringByAppendingPathComponent:@"com.helix.ios.storage"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:helixStoragePath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", helixStoragePath]];
        }
        
        // Clean credentials storage specifically
        // Clean credentials storage specifically
        NSString *credentialsPath = [containerPath stringByAppendingPathComponent:@"Credentials"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:credentialsPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", credentialsPath]];
        }
        
        // Clean tokens directory
        NSString *tokensPath = [containerPath stringByAppendingPathComponent:@"Tokens"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:tokensPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", tokensPath]];
        }
        
        // Clean location history and trip data
        NSString *tripsPath = [containerPath stringByAppendingPathComponent:@"Trips"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:tripsPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", tripsPath]];
        }
        
        // Clean location history
        NSString *locHistoryPath = [containerPath stringByAppendingPathComponent:@"LocationHistory"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:locHistoryPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", locHistoryPath]];
        }
        
        // Clean saved places
        NSString *savedPlacesPath = [containerPath stringByAppendingPathComponent:@"SavedPlaces"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:savedPlacesPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", savedPlacesPath]];
        }
        
        // Clean ride history
        NSString *rideHistoryPath = [containerPath stringByAppendingPathComponent:@"RideHistory"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:rideHistoryPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", rideHistoryPath]];
        }
        
        // Clean payment data
        NSString *paymentsPath = [containerPath stringByAppendingPathComponent:@"Payments"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:paymentsPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", paymentsPath]];
        }
        
        // Clean cached data
        NSString *cachePath = [containerPath stringByAppendingPathComponent:@"Cache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:cachePath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -rf '%@'", cachePath]];
        }
        
        // Clean databases
        NSString *dbsPath = [containerPath stringByAppendingPathComponent:@"Databases"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:dbsPath]) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -name '*.db' -o -name '*.sqlite' -exec rm -f {} \\; 2>/dev/null || true", dbsPath]];
        } else {
            // Clean all SQLite databases
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"find '%@' -name '*.db' -o -name '*.sqlite' -exec rm -f {} \\; 2>/dev/null || true", containerPath]];
        }
    }
}

- (void)cleanDatabaseFile:(NSString *)dbPath bundleID:(NSString *)bundleID appName:(NSString *)appName companyName:(NSString *)companyName {
    // Check if this is an SQLite database
    if ([dbPath hasSuffix:@".sqlite"] || [dbPath hasSuffix:@".db"]) {
        NSLog(@"[AppDataCleaner] Cleaning SQLite database: %@", dbPath);
        
        // Try common table and column names that might contain app-specific data
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE bundleid = '%@';\" 2>/dev/null || true", dbPath, bundleID]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE bundleid = '%@';\" 2>/dev/null || true", dbPath, bundleID]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE bundleid = '%@';\" 2>/dev/null || true", dbPath, bundleID]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE bundleid = '%@';\" 2>/dev/null || true", dbPath, bundleID]];
        
        // Add specific cleaning for Lyft and Zimride names in tables
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE data LIKE '%%lyft%%' OR bundleid LIKE '%%lyft%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE data LIKE '%%lyft%%' OR bundleid LIKE '%%lyft%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE data LIKE '%%lyft%%' OR bundleid LIKE '%%lyft%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE data LIKE '%%lyft%%' OR bundleid LIKE '%%lyft%%';\" 2>/dev/null || true", dbPath]];
        
        // Specific case for com.lyft.ios bundle ID
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE bundleid = 'com.lyft.ios' OR data LIKE '%%com.lyft.ios%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE bundleid = 'com.lyft.ios' OR data LIKE '%%com.lyft.ios%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE bundleid = 'com.lyft.ios' OR data LIKE '%%com.lyft.ios%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE bundleid = 'com.lyft.ios' OR data LIKE '%%com.lyft.ios%%';\" 2>/dev/null || true", dbPath]];
        
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE data LIKE '%%zimride%%' OR bundleid LIKE '%%zimride%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE data LIKE '%%zimride%%' OR bundleid LIKE '%%zimride%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE data LIKE '%%zimride%%' OR bundleid LIKE '%%zimride%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE data LIKE '%%zimride%%' OR bundleid LIKE '%%zimride%%';\" 2>/dev/null || true", dbPath]];
        // Add specific cleaning for Uber and Helix names in tables
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE data LIKE '%%uber%%' OR bundleid LIKE '%%uber%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE data LIKE '%%uber%%' OR bundleid LIKE '%%uber%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE data LIKE '%%uber%%' OR bundleid LIKE '%%uber%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE data LIKE '%%uber%%' OR bundleid LIKE '%%uber%%';\" 2>/dev/null || true", dbPath]];
        
        // Specific case for com.ubercab.UberClient bundle ID
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE bundleid = 'com.ubercab.UberClient' OR data LIKE '%%com.ubercab.UberClient%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE bundleid = 'com.ubercab.UberClient' OR data LIKE '%%com.ubercab.UberClient%%';\" 2>/dev/null || true", dbPath]];
//         [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' "DELETE FROM main WHERE bundleid = 'com.ubercab.UberClient' OR data LIKE '%%com.ubercab.UberClient%%';\" 2>/dev/null || true", dbPath]];
//         [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' "DELETE FROM apps WHERE bundleid = 'com.ubercab.UberClient' OR data LIKE '%%com.ubercab.UberClient%%';\" 2>/dev/null || true", dbPath]];
//         [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' "DELETE FROM data WHERE bundleid = 'com.ubercab.UberClient' OR data LIKE '%%com.ubercab.UberClient%%';\" 2>/dev/null || true", dbPath]];
//         [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' "DELETE FROM items WHERE bundleid = 'com.ubercab.UberClient' OR data LIKE '%%com.ubercab.UberClient%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE data LIKE '%%helix%%' OR bundleid LIKE '%%helix%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE data LIKE '%%helix%%' OR bundleid LIKE '%%helix%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE data LIKE '%%helix%%' OR bundleid LIKE '%%helix%%';\" 2>/dev/null || true", dbPath]];
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE data LIKE '%%helix%%' OR bundleid LIKE '%%helix%%';\" 2>/dev/null || true", dbPath]];         
        // Also try to delete data based on app name and company name
        if (appName.length > 0) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, appName]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, appName]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, appName]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, appName]];
        }
        
        if (companyName.length > 0) {
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM main WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, companyName]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM apps WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, companyName]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM data WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, companyName]];
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"DELETE FROM items WHERE data LIKE '%%%@%%';\" 2>/dev/null || true", dbPath, companyName]];
        }
        
        // Try to vacuum the database
        [self runCommandWithPrivileges:[NSString stringWithFormat:@"sqlite3 '%@' \"VACUUM;\" 2>/dev/null || true", dbPath]];
    } else if ([dbPath hasSuffix:@".sqlite-shm"] || [dbPath hasSuffix:@".sqlite-wal"] || 
               [dbPath hasSuffix:@".db-shm"] || [dbPath hasSuffix:@".db-wal"]) {
        // These are SQLite auxiliary files - clear them if main database also exists
        NSString *mainDbPath = [dbPath stringByReplacingOccurrencesOfString:@"-shm" withString:@""];
        mainDbPath = [mainDbPath stringByReplacingOccurrencesOfString:@"-wal" withString:@""];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:mainDbPath]) {
            // If the main database doesn't exist, we can safely remove these files
            NSLog(@"[AppDataCleaner] Removing SQLite auxiliary file: %@", dbPath);
            [self runCommandWithPrivileges:[NSString stringWithFormat:@"rm -f '%@'", dbPath]];
        }
    }
}

- (void)clearAppIssuesForIOS15:(NSString *)bundleID {
    NSLog(@"[AppDataCleaner] Fixing iOS 15+ specific issues for %@", bundleID);
    
    // Fix location services registration issues
    NSArray *locationPaths = @[
        // Location caches that might contain bad registrations
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/locationd/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/locationd/%@*", bundleID],
        // Special case for Lyft/Zimride
        @"/var/mobile/Library/Caches/locationd/*lyft*",
        @"/var/mobile/Library/Caches/locationd/*lyft*",
        @"/var/mobile/Library/Caches/locationd/*zimride*",
        @"/var/mobile/Library/Caches/locationd/*zimride*",
        // Extra case for com.lyft.ios specifically
        @"/var/mobile/Library/Caches/locationd/com.lyft.ios*",
        @"/var/mobile/Library/Caches/locationd/com.lyft.ios*",
        // Special case for Uber/Helix
        @"/var/mobile/Library/Caches/locationd/*uber*",
        @"/var/mobile/Library/Caches/locationd/*uber*",
        @"/var/mobile/Library/Caches/locationd/*helix*",
        @"/var/mobile/Library/Caches/locationd/*helix*",
        // Location client registrations
        [NSString stringWithFormat:@"/var/mobile/Library/locationd/clients.plist"],
        [NSString stringWithFormat:@"/var/mobile/Library/locationd/clients.plist"],
        // Extra case for com.ubercab.UberClient specifically
        @"/var/mobile/Library/Caches/locationd/com.ubercab.UberClient*",
        @"/var/mobile/Library/Caches/locationd/com.ubercab.UberClient*",
        // Special case for Uber/Helix
        @"/var/mobile/Library/Caches/locationd/*uber*",
        @"/var/mobile/Library/Caches/locationd/*uber*",
        @"/var/mobile/Library/Caches/locationd/*helix*",
        @"/var/mobile/Library/Caches/locationd/*helix*",
        // Extra case for com.ubercab.UberClient specifically
        @"/var/mobile/Library/Caches/locationd/com.ubercab.UberClient*",
        @"/var/mobile/Library/Caches/locationd/com.ubercab.UberClient*",
        // Location client registrations
        [NSString stringWithFormat:@"/var/mobile/Library/locationd/clients.plist"],
        [NSString stringWithFormat:@"/var/mobile/Library/locationd/clients.plist"]
    ];
    
    // Clear location cache files
    for (NSString *pattern in locationPaths) {
        if ([pattern hasSuffix:@".plist"]) {
            // For plist files, we need to modify them rather than delete
            if ([_fileManager fileExistsAtPath:pattern]) {
                NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"clients.plist.temp"];
                [_fileManager copyItemAtPath:pattern toPath:tempPath error:nil];
                
                NSMutableDictionary *clients = [NSMutableDictionary dictionaryWithContentsOfFile:tempPath];
                if (clients) {
                    // Remove any entries for this bundle ID
                    NSMutableArray *keysToRemove = [NSMutableArray arrayWithArray:[clients.allKeys filteredArrayUsingPredicate:
                                           [NSPredicate predicateWithFormat:@"SELF CONTAINS[cd] %@", bundleID]]];
                    
                    // Also remove Lyft and Zimride entries
                    [keysToRemove addObjectsFromArray:[clients.allKeys filteredArrayUsingPredicate:
                                           [NSPredicate predicateWithFormat:@"SELF CONTAINS[cd] %@", @"lyft"]]];
                    [keysToRemove addObjectsFromArray:[clients.allKeys filteredArrayUsingPredicate:
                                           [NSPredicate predicateWithFormat:@"SELF CONTAINS[cd] %@", @"zimride"]]];
                    
                    // Also remove Uber and Helix entries
                    [keysToRemove addObjectsFromArray:[clients.allKeys filteredArrayUsingPredicate:
                                           [NSPredicate predicateWithFormat:@"SELF CONTAINS[cd] %@", @"uber"]]];
                    [keysToRemove addObjectsFromArray:[clients.allKeys filteredArrayUsingPredicate:
                                           [NSPredicate predicateWithFormat:@"SELF CONTAINS[cd] %@", @"helix"]]];
                    
                    if (keysToRemove.count > 0) {
                        NSLog(@"[AppDataCleaner] Found %lu location client registrations to remove", (unsigned long)keysToRemove.count);
                        [keysToRemove enumerateObjectsUsingBlock:^(id key, NSUInteger idx, BOOL *stop) {
                            [clients removeObjectForKey:key];
                        }];
                        
                        [clients writeToFile:tempPath atomically:YES];
                        [self runCommandWithPrivileges:[NSString stringWithFormat:@"cp '%@' '%@'", tempPath, pattern]];
                    }
                }
                
                [_fileManager removeItemAtPath:tempPath error:nil];
            }
        } else {
            // Pattern-based file deletion
            NSArray *matches = [self findPathsMatchingPattern:pattern];
            for (NSString *path in matches) {
                NSLog(@"[AppDataCleaner] Wiping location cache file: %@", path);
                [self securelyWipeFile:path];
            }
        }
    }
    
    // Fix UI state issues specific to iOS 15+
    NSArray *uiStatePaths = @[
        // UISplitViewController state
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/com.apple.UIKit.plist"],
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/com.apple.UIKit.plist"],
        // App-specific UI state 
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@-UI-State.plist", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@-UI-State.plist", bundleID],
        // Special case for Lyft/Zimride
        @"/var/mobile/Library/Preferences/*lyft*-UI-State.plist",
        @"/var/mobile/Library/Preferences/*lyft*-UI-State.plist",
        @"/var/mobile/Library/Preferences/*zimride*-UI-State.plist",
        @"/var/mobile/Library/Preferences/*zimride*-UI-State.plist",
        // Extra case for com.lyft.ios specifically
        @"/var/mobile/Library/Preferences/com.lyft.ios-UI-State.plist",
        @"/var/mobile/Library/Preferences/com.lyft.ios-UI-State.plist",
        // Special case for Uber/Helix
        @"/var/mobile/Library/Preferences/*uber*-UI-State.plist",
        @"/var/mobile/Library/Preferences/*uber*-UI-State.plist",
        @"/var/mobile/Library/Preferences/*helix*-UI-State.plist",
        // Extra case for com.ubercab.UberClient specifically
        @"/var/mobile/Library/Preferences/com.ubercab.UberClient-UI-State.plist",
        @"/var/mobile/Library/Preferences/com.ubercab.UberClient-UI-State.plist",
        @"/var/mobile/Library/Preferences/*helix*-UI-State.plist",
        // SplitView controller state
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.%@.plist", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.%@.plist", bundleID],
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*lyft*.plist",
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*lyft*.plist",
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*zimride*.plist",
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*zimride*.plist",
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*uber*.plist",
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*uber*.plist",
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*helix*.plist",
        @"/var/mobile/Library/Preferences/com.apple.UIKit.SplitView.*helix*.plist"
    ];
    
    for (NSString *path in uiStatePaths) {
        // For patterns with wildcards, use findPathsMatchingPattern
        if ([path containsString:@"*"]) {
            NSArray *matches = [self findPathsMatchingPattern:path];
            for (NSString *matchPath in matches) {
                NSLog(@"[AppDataCleaner] Wiping UI state file: %@", matchPath);
                [self securelyWipeFile:matchPath];
            }
        } else if ([_fileManager fileExistsAtPath:path]) {
            NSLog(@"[AppDataCleaner] Wiping UI state file: %@", path);
            [self securelyWipeFile:path];
        }
    }
    
    // Fix snapshot denylisting for iOS 15+
    NSArray *snapshotPaths = @[
        [NSString stringWithFormat:@"/var/mobile/Library/SplashBoard/Snapshots/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/SplashBoard/Snapshots/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/Snapshots/%@*", bundleID],
        [NSString stringWithFormat:@"/var/mobile/Library/Caches/Snapshots/%@*", bundleID],
        // Special case for Lyft/Zimride
        @"/var/mobile/Library/SplashBoard/Snapshots/*lyft*",
        @"/var/mobile/Library/SplashBoard/Snapshots/*lyft*",
        @"/var/mobile/Library/Caches/Snapshots/*lyft*",
        @"/var/mobile/Library/Caches/Snapshots/*lyft*",
        @"/var/mobile/Library/SplashBoard/Snapshots/*zimride*",
        @"/var/mobile/Library/SplashBoard/Snapshots/*zimride*",
        @"/var/mobile/Library/Caches/Snapshots/*zimride*",
        @"/var/mobile/Library/Caches/Snapshots/*zimride*",
        // Extra case for com.lyft.ios specifically
        @"/var/mobile/Library/SplashBoard/Snapshots/com.lyft.ios*",
        @"/var/mobile/Library/SplashBoard/Snapshots/com.lyft.ios*",
        @"/var/mobile/Library/Caches/Snapshots/com.lyft.ios*",
        @"/var/mobile/Library/Caches/Snapshots/com.lyft.ios*",
        // Special case for Uber/Helix
        @"/var/mobile/Library/SplashBoard/Snapshots/*uber*",
        @"/var/mobile/Library/SplashBoard/Snapshots/*uber*",
        @"/var/mobile/Library/Caches/Snapshots/*uber*",
        @"/var/mobile/Library/Caches/Snapshots/*uber*",
        @"/var/mobile/Library/SplashBoard/Snapshots/*helix*",
        // Extra case for com.ubercab.UberClient specifically
        @"/var/mobile/Library/SplashBoard/Snapshots/com.ubercab.UberClient*",
        @"/var/mobile/Library/SplashBoard/Snapshots/com.ubercab.UberClient*",
        @"/var/mobile/Library/Caches/Snapshots/com.ubercab.UberClient*",
        @"/var/mobile/Library/Caches/Snapshots/com.ubercab.UberClient*",
        @"/var/mobile/Library/SplashBoard/Snapshots/*helix*",
        @"/var/mobile/Library/Caches/Snapshots/*helix*",
        @"/var/mobile/Library/Caches/Snapshots/*helix*",
        // Snapshot deny list
        @"/var/mobile/Library/SpringBoard/ApplicationDenyList.plist",
        @"/var/mobile/Library/SpringBoard/ApplicationDenyList.plist"
    ];
    
    for (NSString *pattern in snapshotPaths) {
        if ([pattern hasSuffix:@"DenyList.plist"]) {
            // For deny list, we need to modify it rather than delete
            if ([_fileManager fileExistsAtPath:pattern]) {
                NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"denylist.plist.temp"];
                [_fileManager copyItemAtPath:pattern toPath:tempPath error:nil];
                
                NSMutableDictionary *denyList = [NSMutableDictionary dictionaryWithContentsOfFile:tempPath];
                if (denyList) {
                    // Create list of keys to remove
                    NSMutableArray *keysToRemove = [NSMutableArray array];
                    
                    // Remove this app from the deny list
                    if ([denyList objectForKey:bundleID]) {
                        [keysToRemove addObject:bundleID];
                    }
                    
                    // Check for Lyft and Zimride entries
                    for (NSString *key in denyList.allKeys) {
                        if ([key containsString:@"lyft"] || [key containsString:@"zimride"]) {
                            [keysToRemove addObject:key];
                        }
                    }
                    
                    // Also remove Uber and Helix entries
                    for (NSString *key in denyList.allKeys) {
                        if ([key containsString:@"uber"] || [key containsString:@"helix"]) {
                            [keysToRemove addObject:key];
                        }
                    }
                    
                    if (keysToRemove.count > 0) {
                        NSLog(@"[AppDataCleaner] Removing %lu entries from snapshot deny list", (unsigned long)keysToRemove.count);
                        for (NSString *key in keysToRemove) {
                            [denyList removeObjectForKey:key];
                        }
                        [denyList writeToFile:tempPath atomically:YES];
                        [self runCommandWithPrivileges:[NSString stringWithFormat:@"cp '%@' '%@'", tempPath, pattern]];
                    }
                }
                
                [_fileManager removeItemAtPath:tempPath error:nil];
            }
        } else {
            // Pattern-based file deletion
            NSArray *matches = [self findPathsMatchingPattern:pattern];
            for (NSString *path in matches) {
                NSLog(@"[AppDataCleaner] Wiping snapshot file: %@", path);
                [self securelyWipeFile:path];
            }
        }
    }
}

// Helper method to check if directory exists and has any content at all, ignoring system files
- (BOOL)directoryExistsAndHasAnyContent:(NSString *)path {
    if (!path.length) {
        return NO;
    }
    if (![_fileManager fileExistsAtPath:path]) {
        NSLog(@"[AppDataCleaner] Directory does not exist: %@", path);
        return NO;
    }

    // Check for any regular file (ignore dotpaths) up to a shallow depth.
    NSString *command = [NSString stringWithFormat:@"find '%@' -maxdepth 3 -type f -not -path '*/\\.*' -print | head -n 1", path];
    NSString *result = [self runCommandAndGetOutput:command];
    if (result.length > 0 && ![result isEqualToString:@"error"]) {
        NSLog(@"[AppDataCleaner] Found at least one file in directory: %@", path);
        return YES;
    }

    // Backup: check for any non-system subdirectory (ignore .com.apple*).
    command = [NSString stringWithFormat:@"find '%@' -mindepth 1 -maxdepth 2 -type d -not -path '*/\\.*' -print | grep -v '\\.?com\\.apple' | head -n 1", path];
    result = [self runCommandAndGetOutput:command];
    if (result.length > 0 && ![result isEqualToString:@"error"]) {
        NSLog(@"[AppDataCleaner] Found subdirectories in: %@", path);
        return YES;
    }

    return NO;
}

// Helper method to check if the app has any references in system databases
- (BOOL)hasSystemDatabaseReferencesForBundleID:(NSString *)bundleID {
    NSArray *parts = [bundleID componentsSeparatedByString:@"."];
    NSString *appName = parts.lastObject;
    NSString *company = parts.count > 1 ? parts[1] : @"";
    
    // Check for entry in launch services database
    NSArray *dbPaths = @[
        @"/var/mobile/Library/MobileInstallation/LastLaunchServicesMap.plist",
        @"/var/mobile/Library/MobileInstallation/LastLaunchServicesMap.plist"
    ];
    
    for (NSString *dbPath in dbPaths) {
        if ([_fileManager fileExistsAtPath:dbPath]) {
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:dbPath];
            if (plist[@"System"] && [plist[@"System"] objectForKey:bundleID]) {
                NSLog(@"[AppDataCleaner] Found reference in LaunchServices database: %@", bundleID);
                return YES;
            }
            
            if (plist[@"User"] && [plist[@"User"] objectForKey:bundleID]) {
                NSLog(@"[AppDataCleaner] Found reference in LaunchServices database: %@", bundleID);
                return YES;
            }
        }
    }
    
    // Check for entries in IconState.plist
    NSArray *iconStatePaths = @[
        @"/var/mobile/Library/SpringBoard/IconState.plist",
        @"/var/mobile/Library/SpringBoard/IconState.plist"
    ];
    
    for (NSString *iconPath in iconStatePaths) {
        if ([_fileManager fileExistsAtPath:iconPath]) {
            NSString *command = [NSString stringWithFormat:@"cat '%@' | grep -q '%@' && echo 'found' || echo 'not found'", iconPath, bundleID];
            NSString *result = [self runCommandAndGetOutput:command];
            if ([result containsString:@"found"]) {
                NSLog(@"[AppDataCleaner] Found reference in IconState.plist: %@", bundleID);
                return YES;
            }
        }
    }
    
    // Check for app in notification settings
    NSArray *notifPaths = @[
        @"/var/mobile/Library/Preferences/com.apple.notifyd.plist",
        @"/var/mobile/Library/Preferences/com.apple.notifyd.plist"
    ];
    
    for (NSString *notifPath in notifPaths) {
        if ([_fileManager fileExistsAtPath:notifPath]) {
            NSString *command = [NSString stringWithFormat:@"cat '%@' | grep -q '%@' && echo 'found' || echo 'not found'", notifPath, bundleID];
            NSString *result = [self runCommandAndGetOutput:command];
            if ([result containsString:@"found"]) {
                NSLog(@"[AppDataCleaner] Found reference in notification settings: %@", bundleID);
                return YES;
            }
        }
    }
    
    // Check for any references in SQLite databases
    NSArray *sqlitePaths = @[
        @"/var/mobile/Library/SpringBoard/ApplicationHistory.sqlite",
        @"/var/mobile/Library/Assistant/SiriAnalytics.db",
        @"/var/mobile/Library/SpringBoard/ApplicationHistory.sqlite",
        @"/var/mobile/Library/Assistant/SiriAnalytics.db"
    ];
    
    for (NSString *sqlitePath in sqlitePaths) {
        if ([_fileManager fileExistsAtPath:sqlitePath]) {
            // Check for bundle ID
            NSString *command = [NSString stringWithFormat:@"sqlite3 '%@' \"SELECT count(*) FROM sqlite_master WHERE type='table' AND sql LIKE '%%%@%%';\" 2>/dev/null || echo '0'", sqlitePath, bundleID];
            NSString *result = [self runCommandAndGetOutput:command];
            if (![result isEqualToString:@"0"] && ![result isEqualToString:@"error"]) {
                NSLog(@"[AppDataCleaner] Found reference in database: %@", sqlitePath);
                return YES;
            }
            
            // Also check for app name or company if bundle ID not found
            if (appName.length > 3) {
                command = [NSString stringWithFormat:@"sqlite3 '%@' \"SELECT count(*) FROM sqlite_master WHERE type='table' AND sql LIKE '%%%@%%';\" 2>/dev/null || echo '0'", sqlitePath, appName];
                result = [self runCommandAndGetOutput:command];
                if (![result isEqualToString:@"0"] && ![result isEqualToString:@"error"]) {
                    NSLog(@"[AppDataCleaner] Found reference to app name in database: %@", sqlitePath);
                    return YES;
                }
            }
            
            if (company.length > 3) {
                command = [NSString stringWithFormat:@"sqlite3 '%@' \"SELECT count(*) FROM sqlite_master WHERE type='table' AND sql LIKE '%%%@%%';\" 2>/dev/null || echo '0'", sqlitePath, company];
                result = [self runCommandAndGetOutput:command];
                if (![result isEqualToString:@"0"] && ![result isEqualToString:@"error"]) {
                    NSLog(@"[AppDataCleaner] Found reference to company name in database: %@", sqlitePath);
                    return YES;
                }
            }
        }
    }
    
    // If we didn't find anything in system databases, return false
    return NO;
}

// NEW: Method to check if there are keychain items for a bundle ID
@end
