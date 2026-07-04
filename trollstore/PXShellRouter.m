// PXShellRouter.m — Legacy shell command router for TrollStore builds.

#import "PXShellRouter.h"
#import "PXFileOps.h"
#import "PXRootHelper.h"

#import <fnmatch.h>
#import <errno.h>
#import <stdlib.h>
#import <Security/Security.h>
#import <sqlite3.h>

NSString *const PXShellRouterErrorDomain = @"com.hydra.projectx.shellrouter";

static NSString *PXTrim(NSString *s) {
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static NSError *PXRouterError(PXShellRouterError code, NSString *desc) {
    return [NSError errorWithDomain:PXShellRouterErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: desc ?: @"Shell router error"}];
}

static BOOL PXIsEPERMOrEACCES(NSError *error) {
    NSNumber *n = error.userInfo[PXFileOpsErrnoUserInfoKey];
    int e = n.intValue;
    return e == EPERM || e == EACCES;
}

static BOOL PXPathNeedsRoot(NSString *path) {
    return [path hasPrefix:@"/var/root/"] ||
           [path hasPrefix:@"/private/var/root/"] ||
           [path hasPrefix:@"/var/mobile/Library/SpringBoard/"] ||
           [path hasPrefix:@"/private/var/mobile/Library/SpringBoard/"] ||
           [path hasPrefix:@"/var/mobile/Library/UsageLog/"] ||
           [path hasPrefix:@"/private/var/mobile/Library/UsageLog/"];
}

static BOOL PXRunRoot(NSArray<NSString *> *args, NSError **error) {
    int exitCode = 0;
    NSString *stdErr = nil;
    BOOL ok = [[PXRootHelper sharedHelper] runAsRoot:args
                                           exitCode:&exitCode
                                             stdOut:nil
                                             stdErr:&stdErr
                                              error:error];
    if (!ok && error && *error == nil) {
        NSString *desc = [NSString stringWithFormat:@"Root helper failed (%d): %@", exitCode, stdErr ?: @""];
        *error = PXRouterError(PXShellRouterErrorHandlerFailed, desc);
    }
    return ok;
}

static BOOL PXRemovePath(NSString *path, NSError **error) {
    if (PXPathNeedsRoot(path)) {
        return PXRunRoot(@[@"rm", path], error);
    }
    NSError *err = nil;
    if ([PXFileOps removePath:path error:&err]) return YES;
    if (PXIsEPERMOrEACCES(err)) return PXRunRoot(@[@"rm", path], error);
    if (error) *error = err;
    return NO;
}

static BOOL PXChmodPath(NSString *path, NSString *modeString, BOOL recursive, NSError **error) {
    if (PXPathNeedsRoot(path)) {
        NSMutableArray *args = [NSMutableArray arrayWithObjects:@"chmod", modeString, path, nil];
        if (recursive) [args addObject:@"-R"];
        return PXRunRoot(args, error);
    }
    mode_t mode = (mode_t)strtoul(modeString.UTF8String, NULL, 8);
    NSError *err = nil;
    if ([PXFileOps chmodPath:path mode:mode recursive:recursive error:&err]) return YES;
    if (PXIsEPERMOrEACCES(err)) {
        NSMutableArray *args = [NSMutableArray arrayWithObjects:@"chmod", modeString, path, nil];
        if (recursive) [args addObject:@"-R"];
        return PXRunRoot(args, error);
    }
    if (error) *error = err;
    return NO;
}

static BOOL PXChflagsPath(NSString *path, BOOL recursive, NSError **error) {
    if (PXPathNeedsRoot(path)) {
        NSMutableArray *args = [NSMutableArray arrayWithObjects:@"chflags", @"clear", path, nil];
        if (recursive) [args addObject:@"-R"];
        return PXRunRoot(args, error);
    }
    NSError *err = nil;
    if ([PXFileOps clearImmutableFlagAtPath:path recursive:recursive error:&err]) return YES;
    if (PXIsEPERMOrEACCES(err)) {
        NSMutableArray *args = [NSMutableArray arrayWithObjects:@"chflags", @"clear", path, nil];
        if (recursive) [args addObject:@"-R"];
        return PXRunRoot(args, error);
    }
    if (error) *error = err;
    return NO;
}

@interface PXShellRouter ()
@property (atomic, copy, readwrite, nullable) NSError *lastError;
@end

@implementation PXShellRouter

+ (instancetype)sharedRouter {
    static PXShellRouter *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ shared = [[PXShellRouter alloc] init]; });
    return shared;
}

+ (NSArray<NSDictionary<NSString *,id> *> *)parseCompositeCommand:(NSString *)command {
    NSMutableArray *segments = [NSMutableArray array];
    NSMutableString *current = [NSMutableString string];
    unichar quote = 0;
    for (NSUInteger i = 0; i < command.length; i++) {
        unichar c = [command characterAtIndex:i];
        if (quote) {
            [current appendFormat:@"%C", c];
            if (c == quote) quote = 0;
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
            [current appendFormat:@"%C", c];
            continue;
        }
        BOOL split = NO;
        NSString *op = @";";
        if (c == ';') {
            split = YES;
        } else if (c == '&' && i + 1 < command.length && [command characterAtIndex:i + 1] == '&') {
            split = YES;
            op = @"&&";
            i++;
        }
        if (split) {
            NSString *s = PXTrim(current);
            if (s.length) [segments addObject:@{@"command": s, @"op": op}];
            [current setString:@""];
        } else {
            [current appendFormat:@"%C", c];
        }
    }
    NSString *s = PXTrim(current);
    if (s.length) [segments addObject:@{@"command": s, @"op": @"end"}];
    return segments;
}

+ (NSArray<NSString *> *)tokenizeArgv:(NSString *)command {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    NSMutableString *cur = [NSMutableString string];
    unichar quote = 0;
    BOOL escaped = NO;
    for (NSUInteger i = 0; i < command.length; i++) {
        unichar c = [command characterAtIndex:i];
        if (escaped) {
            [cur appendFormat:@"%C", c];
            escaped = NO;
            continue;
        }
        if (c == '\\') {
            escaped = YES;
            continue;
        }
        if (quote) {
            if (c == quote) quote = 0;
            else [cur appendFormat:@"%C", c];
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
            continue;
        }
        if ([[NSCharacterSet whitespaceAndNewlineCharacterSet] characterIsMember:c]) {
            if (cur.length) {
                [out addObject:cur.copy];
                [cur setString:@""];
            }
            continue;
        }
        [cur appendFormat:@"%C", c];
    }
    if (quote || escaped) return nil;
    if (cur.length) [out addObject:cur.copy];
    return out;
}

- (void)runShellCommandIgnoringError:(NSString *)command {
    NSError *err = nil;
    if (![self runShellCommand:command error:&err] && err) {
        NSLog(@"[PXShellRouter] %@", err.localizedDescription);
    }
}

- (BOOL)runShellCommand:(NSString *)command error:(NSError **)outError {
    if (![command isKindOfClass:[NSString class]] || command.length == 0) return YES;
    BOOL okAll = YES;
    for (NSDictionary *seg in [PXShellRouter parseCompositeCommand:command]) {
        NSString *raw = seg[@"command"];
        BOOL bestEffort = NO;
        NSString *cmd = PXTrim(raw);
        NSArray *suffixes = @[@"2>/dev/null || true", @"2>/dev/null||true", @">/dev/null 2>&1 || true"];
        for (NSString *suffix in suffixes) {
            if ([cmd hasSuffix:suffix]) {
                cmd = PXTrim([cmd substringToIndex:cmd.length - suffix.length]);
                bestEffort = YES;
                break;
            }
        }

        NSError *err = nil;
        BOOL ok = [self runSingleCommand:cmd error:&err];
        if (!ok) {
            self.lastError = err;
            if (bestEffort) {
                NSLog(@"[PXShellRouter] best-effort command failed: %@ (%@)", cmd, err.localizedDescription);
                continue;
            }
            okAll = NO;
            if (outError) *outError = err;
            break;
        }
    }
    return okAll;
}

- (BOOL)runSingleCommand:(NSString *)cmd error:(NSError **)error {
    if ([cmd hasPrefix:@"grep "]) return [self handleGrepRedirect:cmd error:error];
    if ([cmd containsString:@"|"] || [cmd containsString:@">"]) {
        if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedCommand, [NSString stringWithFormat:@"Unsupported shell construct: %@", cmd]);
        return NO;
    }
    NSArray<NSString *> *argv = [PXShellRouter tokenizeArgv:cmd];
    if (!argv) {
        if (error) *error = PXRouterError(PXShellRouterErrorParseFailed, [NSString stringWithFormat:@"Failed to parse command: %@", cmd]);
        return NO;
    }
    if (!argv.count) return YES;
    NSString *op = argv[0];
    if ([op isEqualToString:@"rm"]) return [self handleRm:argv error:error];
    if ([op isEqualToString:@"mkdir"]) return [self handleMkdir:argv error:error];
    if ([op isEqualToString:@"chmod"]) return [self handleChmod:argv error:error];
    if ([op isEqualToString:@"chflags"]) return [self handleChflags:argv error:error];
    if ([op isEqualToString:@"find"]) return [self handleFind:argv error:error];
    if ([op isEqualToString:@"mv"]) return [self handleMv:argv error:error];
    if ([op isEqualToString:@"cp"]) return [self handleCp:argv error:error];
    if ([op isEqualToString:@"touch"]) return [self handleTouch:argv error:error];
    if ([op isEqualToString:@"chown"]) return [self handleChown:argv error:error];
    if ([op isEqualToString:@"launchctl"]) return [self handleLaunchctl:argv error:error];
    if ([op isEqualToString:@"security"]) return [self handleSecurity:argv error:error];
    if ([op isEqualToString:@"plutil"]) return [self handlePlutil:argv error:error];
    if ([op isEqualToString:@"sqlite3"]) return [self handleSqlite:argv error:error];
    if ([op isEqualToString:@"sync"]) { [PXFileOps syncFilesystem]; return YES; }
    if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedCommand, [NSString stringWithFormat:@"Unsupported command: %@", op]);
    return NO;
}

- (BOOL)handleRm:(NSArray<NSString *> *)argv error:(NSError **)error {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for (NSUInteger i = 1; i < argv.count; i++) {
        NSString *a = argv[i];
        if ([a hasPrefix:@"-"]) continue;
        [paths addObject:a];
    }
    for (NSString *path in paths) {
        if ([path hasSuffix:@"/*"]) {
            NSString *dir = [path substringToIndex:path.length - 2];
            if (![PXFileOps removeContentsOfDirectory:dir keepNames:nil error:error]) return NO;
        } else if ([path.lastPathComponent containsString:@"*"]) {
            if (PXPathNeedsRoot(path)) {
                return PXRunRoot(@[@"rmglob", path.stringByDeletingLastPathComponent, path.lastPathComponent], error);
            }
            NSString *dir = path.stringByDeletingLastPathComponent;
            NSString *pattern = path.lastPathComponent;
            if (![PXFileOps removeMatchingGlob:pattern inDirectory:dir error:error]) return NO;
        } else if (!PXRemovePath(path, error)) {
            return NO;
        }
    }
    return YES;
}

- (BOOL)handleMkdir:(NSArray<NSString *> *)argv error:(NSError **)error {
    for (NSUInteger i = 1; i < argv.count; i++) {
        NSString *p = argv[i];
        if ([p isEqualToString:@"-p"]) continue;
        if (![PXFileOps createDirectory:p error:error]) return NO;
    }
    return YES;
}

- (BOOL)handleChmod:(NSArray<NSString *> *)argv error:(NSError **)error {
    BOOL recursive = NO;
    NSString *mode = nil;
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for (NSUInteger i = 1; i < argv.count; i++) {
        NSString *a = argv[i];
        if ([a isEqualToString:@"-R"]) { recursive = YES; continue; }
        if (!mode) mode = a;
        else [paths addObject:a];
    }
    if (!mode || !paths.count) {
        if (error) *error = PXRouterError(PXShellRouterErrorInvalidArgs, @"chmod missing mode/path");
        return NO;
    }
    for (NSString *p in paths) if (!PXChmodPath(p, mode, recursive, error)) return NO;
    return YES;
}

- (BOOL)handleChflags:(NSArray<NSString *> *)argv error:(NSError **)error {
    BOOL recursive = NO;
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for (NSUInteger i = 1; i < argv.count; i++) {
        NSString *a = argv[i];
        if ([a isEqualToString:@"-R"]) { recursive = YES; continue; }
        if ([a hasPrefix:@"-"]) continue;
        if ([a containsString:@"nouchg"] || [a containsString:@"noschg"] || [a containsString:@"nohidden"]) continue;
        [paths addObject:a];
    }
    for (NSString *p in paths) if (!PXChflagsPath(p, recursive, error)) return NO;
    return YES;
}

- (BOOL)handleFind:(NSArray<NSString *> *)argv error:(NSError **)error {
    if (argv.count < 2) return YES;
    NSString *root = argv[1];
    if ([argv containsObject:@"-empty"] && [argv containsObject:@"-delete"]) {
        return [PXFileOps removeEmptyDirectoriesUnder:root error:error];
    }
    if ([argv containsObject:@"-type"] && [argv containsObject:@"f"]) {
        NSString *namePattern = nil;
        NSUInteger idx = [argv indexOfObject:@"-name"];
        if (idx != NSNotFound && idx + 1 < argv.count) namePattern = argv[idx + 1];
        return [PXFileOps removePathsUnderRoot:root matchingPredicate:^BOOL(NSString *path, BOOL isDirectory) {
            if (isDirectory) return NO;
            if (!namePattern) return YES;
            return fnmatch(namePattern.UTF8String, path.lastPathComponent.UTF8String, 0) == 0;
        } error:error];
    }
    if ([argv containsObject:@"-maxdepth"] && [argv containsObject:@"1"]) {
        NSMutableSet<NSString *> *keep = [NSMutableSet set];
        for (NSUInteger i = 0; i + 1 < argv.count; i++) {
            if ([argv[i] isEqualToString:@"-not"] && [argv[i + 1] isEqualToString:@"-name"] && i + 2 < argv.count) {
                [keep addObject:argv[i + 2]];
            }
        }
        if (keep.count) return [PXFileOps removeContentsOfDirectory:root keepNames:keep.allObjects error:error];
    }
    if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedOption, [NSString stringWithFormat:@"Unsupported find pattern: %@", [argv componentsJoinedByString:@" "]]);
    return NO;
}

- (BOOL)handleMv:(NSArray<NSString *> *)argv error:(NSError **)error {
    if (argv.count < 3) { if (error) *error = PXRouterError(PXShellRouterErrorInvalidArgs, @"mv missing args"); return NO; }
    NSString *src = argv[1];
    NSString *dst = argv[2];
    if (PXPathNeedsRoot(src) || PXPathNeedsRoot(dst)) return PXRunRoot(@[@"mv", src, dst], error);
    return [PXFileOps movePath:src toPath:dst error:error];
}

- (BOOL)handleCp:(NSArray<NSString *> *)argv error:(NSError **)error {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for (NSUInteger i = 1; i < argv.count; i++) if (![argv[i] hasPrefix:@"-"]) [paths addObject:argv[i]];
    if (paths.count < 2) { if (error) *error = PXRouterError(PXShellRouterErrorInvalidArgs, @"cp missing args"); return NO; }
    return [PXFileOps copyPath:paths[0] toPath:paths[1] error:error];
}

- (BOOL)handleTouch:(NSArray<NSString *> *)argv error:(NSError **)error {
    for (NSUInteger i = 1; i < argv.count; i++) if (![PXFileOps touchPath:argv[i] createIfMissing:YES error:error]) return NO;
    return YES;
}

- (BOOL)handleChown:(NSArray<NSString *> *)argv error:(NSError **)error {
    BOOL recursive = NO;
    NSString *owner = nil;
    NSString *path = nil;
    for (NSUInteger i = 1; i < argv.count; i++) {
        if ([argv[i] isEqualToString:@"-R"]) { recursive = YES; continue; }
        if (!owner) owner = argv[i]; else { path = argv[i]; break; }
    }
    if (!owner || !path) { if (error) *error = PXRouterError(PXShellRouterErrorInvalidArgs, @"chown missing args"); return NO; }
    uid_t uid = 501;
    gid_t gid = 501;
    if (![owner isEqualToString:@"mobile:mobile"] && ![owner isEqualToString:@"501:501"]) {
        if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedOption, [NSString stringWithFormat:@"Unsupported chown owner: %@", owner]);
        return NO;
    }
    NSError *err = nil;
    if ([PXFileOps chownPath:path uid:uid gid:gid recursive:recursive error:&err]) return YES;
    if (PXIsEPERMOrEACCES(err) || PXPathNeedsRoot(path)) {
        return PXRunRoot(@[@"chown", @"501", @"501", path], error);
    }
    if (error) *error = err;
    return NO;
}

- (BOOL)handleLaunchctl:(NSArray<NSString *> *)argv error:(NSError **)error {
    // Historical call sites use launchctl kill/stop as best-effort process
    // nudges. TrollStore cannot control launchd services; treat as success so
    // clean flows do not fail solely because launchd control is unavailable.
    NSLog(@"[PXShellRouter] launchctl command ignored under TrollStore: %@", [argv componentsJoinedByString:@" "]);
    return YES;
}

- (BOOL)handleSecurity:(NSArray<NSString *> *)argv error:(NSError **)error {
    if (argv.count < 2) return YES;
    NSString *sub = argv[1];
    BOOL internet = [sub isEqualToString:@"delete-internet-password"];
    BOOL generic = [sub isEqualToString:@"delete-generic-password"];
    if (!internet && !generic) {
        if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedOption, [NSString stringWithFormat:@"Unsupported security command: %@", sub]);
        return NO;
    }
    NSString *label = nil;
    for (NSUInteger i = 2; i + 1 < argv.count; i++) {
        if ([argv[i] isEqualToString:@"-l"]) { label = argv[i + 1]; break; }
    }
    if (!label.length) return YES;
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = internet ? (__bridge id)kSecClassInternetPassword : (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrLabel] = label;
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status == errSecSuccess || status == errSecItemNotFound) return YES;
    if (error) *error = PXRouterError(PXShellRouterErrorHandlerFailed, [NSString stringWithFormat:@"SecItemDelete failed for label %@: %d", label, (int)status]);
    return NO;
}

- (BOOL)handlePlutil:(NSArray<NSString *> *)argv error:(NSError **)error {
    if (argv.count < 4 || ![argv[1] isEqualToString:@"-convert"]) {
        if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedOption, @"Unsupported plutil pattern");
        return NO;
    }
    NSString *formatName = argv[2];
    NSString *path = argv.lastObject;
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:error];
    if (!data) return NO;
    NSPropertyListFormat inFormat = NSPropertyListBinaryFormat_v1_0;
    id obj = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:&inFormat error:error];
    if (!obj) return NO;
    NSPropertyListFormat outFormat = [formatName isEqualToString:@"xml1"] ? NSPropertyListXMLFormat_v1_0 : NSPropertyListBinaryFormat_v1_0;
    NSData *out = [NSPropertyListSerialization dataWithPropertyList:obj format:outFormat options:0 error:error];
    if (!out) return NO;
    return [out writeToFile:path options:NSDataWritingAtomic error:error];
}

- (BOOL)handleGrepRedirect:(NSString *)cmd error:(NSError **)error {
    NSRange gt = [cmd rangeOfString:@">"];
    if (gt.location == NSNotFound) {
        if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedOption, @"grep without redirect unsupported");
        return NO;
    }
    NSString *left = PXTrim([cmd substringToIndex:gt.location]);
    NSString *dst = PXTrim([cmd substringFromIndex:gt.location + 1]);
    NSArray<NSString *> *argv = [PXShellRouter tokenizeArgv:left];
    NSArray<NSString *> *dstArgv = [PXShellRouter tokenizeArgv:dst];
    if (argv.count < 4 || dstArgv.count != 1 || ![argv[0] isEqualToString:@"grep"] || ![argv[1] isEqualToString:@"-v"]) {
        if (error) *error = PXRouterError(PXShellRouterErrorUnsupportedOption, [NSString stringWithFormat:@"Unsupported grep pattern: %@", cmd]);
        return NO;
    }
    NSString *pattern = argv[2];
    NSString *src = argv[3];
    NSString *content = [NSString stringWithContentsOfFile:src encoding:NSUTF8StringEncoding error:error];
    if (!content) return NO;
    NSMutableArray<NSString *> *kept = [NSMutableArray array];
    for (NSString *line in [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        if ([line rangeOfString:pattern].location == NSNotFound) [kept addObject:line];
    }
    NSString *out = [kept componentsJoinedByString:@"\n"];
    return [out writeToFile:dstArgv[0] atomically:YES encoding:NSUTF8StringEncoding error:error];
}

- (BOOL)handleSqlite:(NSArray<NSString *> *)argv error:(NSError **)error {
    if (argv.count < 3) return YES;
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(argv[1].UTF8String, &db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK || !db) {
        if (error) *error = PXRouterError(PXShellRouterErrorHandlerFailed, [NSString stringWithFormat:@"sqlite3_open failed for %@", argv[1]]);
        if (db) sqlite3_close(db);
        return NO;
    }
    char *errmsg = NULL;
    rc = sqlite3_exec(db, argv[2].UTF8String, NULL, NULL, &errmsg);
    sqlite3_close(db);
    if (rc != SQLITE_OK) {
        NSString *msg = errmsg ? [NSString stringWithUTF8String:errmsg] : @"sqlite3_exec failed";
        if (errmsg) sqlite3_free(errmsg);
        if (error) *error = PXRouterError(PXShellRouterErrorHandlerFailed, msg);
        return NO;
    }
    return YES;
}

@end
