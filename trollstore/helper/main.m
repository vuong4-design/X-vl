// weaponx_root_helper — minimal root-privileged helper for TrollStore.
//
// Bundled in the main app and declared in TSRootBinaries; invoked via TSUtil
// spawnRoot: (see PXRootHelper). Runs as uid 0 and performs ONLY the small set
// of operations that genuinely require root. No /bin/sh dependency: uses
// removefile(3), lchown(2), fchmodat(2), lchflags(2), rename(2) directly.
//
// Usage (argv):
//   weaponx_root_helper rm      <absolute-path>
//   weaponx_root_helper chown   <uid> <gid> <absolute-path>          (recursive)
//   weaponx_root_helper chmod   <octal-mode> <absolute-path> [-R]
//   weaponx_root_helper chflags clear <absolute-path> [-R]
//   weaponx_root_helper mv      <src-absolute-path> <dst-absolute-path>
//
// Exit codes:
//   0  success
//   2  invalid arguments
//   3  operation failed (see stderr)
//
// SECURITY: every path argument is validated against an allowlist of prefixes
// so a compromised caller cannot ask the root helper to touch arbitrary paths.

#import <Foundation/Foundation.h>
#import <removefile.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>
#import <dirent.h>
#import <fcntl.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>

// Allowlisted path prefixes. Keep narrow; each new prefix needs justification.
static const char *kAllowedPrefixes[] = {
    // Root-owned plist & caches.
    "/var/root/Library/Preferences/",
    "/var/root/Library/Caches/",
    "/private/var/root/Library/Preferences/",
    "/private/var/root/Library/Caches/",

    // Mobile-owned system paths (chown after restore or rm root-owned leftovers).
    "/var/mobile/Library/",
    "/private/var/mobile/Library/",

    // SpringBoard + iconstate + push store (anti-forensic clean).
    "/var/mobile/Library/SpringBoard/",
    "/private/var/mobile/Library/SpringBoard/",

    // WebKit / Accounts / UsageLog / Caches / Preferences / Cookies.
    "/var/mobile/Library/WebKit/",
    "/var/mobile/Library/Accounts/",
    "/var/mobile/Library/UsageLog/",
    "/var/mobile/Library/Caches/",
    "/var/mobile/Library/Preferences/",
    "/var/mobile/Library/Cookies/",

    // Shared app group containers (keychain bridge & shared scrub).
    "/var/mobile/Containers/Shared/AppGroup/",
    "/private/var/mobile/Containers/Shared/AppGroup/",

    // App data containers (restore staging dest).
    "/var/mobile/Containers/Data/Application/",
    "/private/var/mobile/Containers/Data/Application/",

    // Bundle containers (read mostly; for chmod adjustments before move).
    "/var/containers/Bundle/Application/",
    "/private/var/containers/Bundle/Application/",

    // tmp staging area used by restore/backup pipelines.
    "/var/tmp/weaponx/",
    "/private/var/tmp/weaponx/",
};
static const size_t kAllowedPrefixCount = sizeof(kAllowedPrefixes) / sizeof(kAllowedPrefixes[0]);

static void perr(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void perr(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fputs(s.UTF8String, stderr);
    fputc('\n', stderr);
}

static BOOL pathIsAllowed(NSString *path) {
    if (path.length == 0) return NO;
    if (![path isAbsolutePath]) return NO;
    if ([path containsString:@"/../"] || [path hasSuffix:@"/.."]) return NO;
    if ([path containsString:@"//"]) return NO;

    const char *cpath = path.UTF8String;
    for (size_t i = 0; i < kAllowedPrefixCount; i++) {
        if (strncmp(cpath, kAllowedPrefixes[i], strlen(kAllowedPrefixes[i])) == 0) {
            return YES;
        }
    }
    return NO;
}

#pragma mark - ops

static int op_rm(NSString *path) {
    if (!pathIsAllowed(path)) { perr(@"rm: path not allowed: %@", path); return 2; }
    if (removefile(path.fileSystemRepresentation, NULL, REMOVEFILE_RECURSIVE) != 0) {
        if (errno == ENOENT) return 0;
        perr(@"rm '%@' failed: %s", path, strerror(errno));
        return 3;
    }
    return 0;
}

static int chown_recursive(NSString *path, uid_t uid, gid_t gid) {
    if (lchown(path.fileSystemRepresentation, uid, gid) != 0 && errno != ENOENT) {
        perr(@"chown '%@' failed: %s", path, strerror(errno));
        return 3;
    }
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) return 0;
    DIR *d = opendir(path.fileSystemRepresentation);
    if (!d) return 0;
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        NSString *c = [path stringByAppendingPathComponent:@(e->d_name)];
        int r = chown_recursive(c, uid, gid);
        if (r != 0) { rc = r; break; }
    }
    closedir(d);
    return rc;
}

static int op_chown(NSString *uidStr, NSString *gidStr, NSString *path) {
    if (!pathIsAllowed(path)) { perr(@"chown: path not allowed: %@", path); return 2; }
    uid_t uid = (uid_t)strtoul(uidStr.UTF8String, NULL, 10);
    gid_t gid = (gid_t)strtoul(gidStr.UTF8String, NULL, 10);
    return chown_recursive(path, uid, gid);
}

static int chmod_recursive(NSString *path, mode_t mode, BOOL recursive) {
    if (fchmodat(AT_FDCWD, path.fileSystemRepresentation, mode, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOTSUP || errno == EINVAL) {
            if (chmod(path.fileSystemRepresentation, mode) != 0 && errno != ENOENT) {
                perr(@"chmod '%@' failed: %s", path, strerror(errno));
                return 3;
            }
        } else if (errno != ENOENT) {
            perr(@"chmod '%@' failed: %s", path, strerror(errno));
            return 3;
        }
    }
    if (!recursive) return 0;
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) return 0;
    DIR *d = opendir(path.fileSystemRepresentation);
    if (!d) return 0;
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        NSString *c = [path stringByAppendingPathComponent:@(e->d_name)];
        int r = chmod_recursive(c, mode, YES);
        if (r != 0) { rc = r; break; }
    }
    closedir(d);
    return rc;
}

static int op_chmod(NSString *modeStr, NSString *path, BOOL recursive) {
    if (!pathIsAllowed(path)) { perr(@"chmod: path not allowed: %@", path); return 2; }
    mode_t mode = (mode_t)strtoul(modeStr.UTF8String, NULL, 8);
    if (mode == 0 && ![modeStr isEqualToString:@"0"]) {
        perr(@"chmod: invalid mode '%@'", modeStr); return 2;
    }
    return chmod_recursive(path, mode, recursive);
}

static int chflags_recursive(NSString *path, BOOL recursive) {
    if (lchflags(path.fileSystemRepresentation, 0) != 0 && errno != ENOENT && errno != ENOTSUP) {
        perr(@"chflags '%@' failed: %s", path, strerror(errno));
        return 3;
    }
    if (!recursive) return 0;
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) return 0;
    DIR *d = opendir(path.fileSystemRepresentation);
    if (!d) return 0;
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        NSString *c = [path stringByAppendingPathComponent:@(e->d_name)];
        int r = chflags_recursive(c, YES);
        if (r != 0) { rc = r; break; }
    }
    closedir(d);
    return rc;
}

static int op_chflags(NSString *sub, NSString *path, BOOL recursive) {
    if (![sub isEqualToString:@"clear"]) { perr(@"chflags: only 'clear' supported"); return 2; }
    if (!pathIsAllowed(path)) { perr(@"chflags: path not allowed: %@", path); return 2; }
    return chflags_recursive(path, recursive);
}

static int op_mv(NSString *src, NSString *dst) {
    if (!pathIsAllowed(src)) { perr(@"mv: src not allowed: %@", src); return 2; }
    if (!pathIsAllowed(dst)) { perr(@"mv: dst not allowed: %@", dst); return 2; }
    removefile(dst.fileSystemRepresentation, NULL, REMOVEFILE_RECURSIVE);
    if (rename(src.fileSystemRepresentation, dst.fileSystemRepresentation) != 0) {
        perr(@"mv '%@' -> '%@' failed: %s", src, dst, strerror(errno));
        return 3;
    }
    return 0;
}

#pragma mark - main

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) { perr(@"usage: weaponx_root_helper <op> ..."); return 2; }
        NSString *op = @(argv[1]);

        if ([op isEqualToString:@"rm"]) {
            if (argc != 3) { perr(@"rm: expects <path>"); return 2; }
            return op_rm(@(argv[2]));
        }
        if ([op isEqualToString:@"chown"]) {
            if (argc != 5) { perr(@"chown: expects <uid> <gid> <path>"); return 2; }
            return op_chown(@(argv[2]), @(argv[3]), @(argv[4]));
        }
        if ([op isEqualToString:@"chmod"]) {
            if (argc != 4 && argc != 5) { perr(@"chmod: expects <mode> <path> [-R]"); return 2; }
            BOOL r = (argc == 5 && strcmp(argv[4], "-R") == 0);
            return op_chmod(@(argv[2]), @(argv[3]), r);
        }
        if ([op isEqualToString:@"chflags"]) {
            if (argc != 4 && argc != 5) { perr(@"chflags: expects clear <path> [-R]"); return 2; }
            BOOL r = (argc == 5 && strcmp(argv[4], "-R") == 0);
            return op_chflags(@(argv[2]), @(argv[3]), r);
        }
        if ([op isEqualToString:@"mv"]) {
            if (argc != 4) { perr(@"mv: expects <src> <dst>"); return 2; }
            return op_mv(@(argv[2]), @(argv[3]));
        }

        perr(@"unknown op: %@", op);
        return 2;
    }
}
