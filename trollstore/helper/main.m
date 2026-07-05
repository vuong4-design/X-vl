// weaponx_root_helper — minimal root-privileged helper for TrollStore.
//
// Bundled in the main app and declared in TSRootBinaries; invoked via TSUtil
// spawnRoot: (see PXRootHelper). Runs as uid 0 and performs ONLY the small set
// of operations that genuinely require root. No /bin/sh dependency: uses
// removefile(3), lchown(2), fchmodat(2), lchflags(2), rename(2) directly.
//
// Usage (argv):
//   weaponx_root_helper rm      <absolute-path>
//   weaponx_root_helper rmglob  <absolute-dir> <fnmatch-pattern>
//   weaponx_root_helper chown   <uid> <gid> <absolute-path>          (recursive)
//   weaponx_root_helper chmod   <octal-mode> <absolute-path> [-R]
//   weaponx_root_helper chflags clear <absolute-path> [-R]
//   weaponx_root_helper mv      <src-absolute-path> <dst-absolute-path>
//   weaponx_root_helper mkdir   <absolute-path>
//   weaponx_root_helper cpfile  <src-absolute-path> <dst-absolute-path>
//   weaponx_root_helper replacefile <src-absolute-path> <dst-absolute-path>
//   weaponx_root_helper ldidprobe
//   weaponx_root_helper ldidsign <binary-absolute-path> [entitlements-plist]
//   weaponx_root_helper dyldlaunch <executable> <dylib> <home> <bundleID> [logPath]
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
#import <fnmatch.h>
#import <spawn.h>
#import <sys/wait.h>

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);
extern char **environ;

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

    // TrollStore app bundle resources copied into target launches.
    "/Applications/ProjectXTroll.app/",
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

static void appendLogLine(NSString *path, NSString *fmt, ...) NS_FORMAT_FUNCTION(2,3);
static void appendLogLine(NSString *path, NSString *fmt, ...) {
    if (!path.length) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return;
    NSString *line = [s stringByAppendingString:@"\n"];
    write(fd, line.UTF8String, strlen(line.UTF8String));
    fsync(fd);
    close(fd);
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

static int op_rmglob(NSString *dir, NSString *pattern) {
    NSString *dirForAllow = [dir hasSuffix:@"/"] ? dir : [dir stringByAppendingString:@"/"];
    if (!pathIsAllowed(dirForAllow)) { perr(@"rmglob: dir not allowed: %@", dir); return 2; }
    if (pattern.length == 0 || [pattern containsString:@"/"]) { perr(@"rmglob: invalid pattern: %@", pattern); return 2; }

    DIR *d = opendir(dir.fileSystemRepresentation);
    if (!d) {
        if (errno == ENOENT) return 0;
        perr(@"rmglob opendir '%@' failed: %s", dir, strerror(errno));
        return 3;
    }

    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (fnmatch(pattern.fileSystemRepresentation, e->d_name, FNM_PERIOD) != 0) continue;
        NSString *child = [dir stringByAppendingPathComponent:@(e->d_name)];
        rc = op_rm(child);
        if (rc != 0) break;
    }
    closedir(d);
    return rc;
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

static int op_mkdir(NSString *path) {
    if (!pathIsAllowed(path)) { perr(@"mkdir: path not allowed: %@", path); return 2; }
    NSError *err = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0755} error:&err]) {
        perr(@"mkdir '%@' failed: %@", path, err.localizedDescription ?: @"unknown error");
        return 3;
    }
    return 0;
}

static int op_cpfile(NSString *src, NSString *dst) {
    if (!pathIsAllowed(src)) { perr(@"cpfile: src not allowed: %@", src); return 2; }
    if (!pathIsAllowed(dst)) { perr(@"cpfile: dst not allowed: %@", dst); return 2; }
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *parent = [dst stringByDeletingLastPathComponent];
    NSError *err = nil;
    if (parent.length && ![fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0755} error:&err]) {
        perr(@"cpfile mkdir parent '%@' failed: %@", parent, err.localizedDescription ?: @"unknown error");
        return 3;
    }
    int inFd = open(src.fileSystemRepresentation, O_RDONLY);
    if (inFd < 0) {
        perr(@"cpfile open src '%@' failed: %s", src, strerror(errno));
        return 3;
    }
    unlink(dst.fileSystemRepresentation);
    int outFd = open(dst.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (outFd < 0) {
        int saved = errno;
        close(inFd);
        perr(@"cpfile open dst '%@' failed: %s", dst, strerror(saved));
        return 3;
    }
    char buf[1024 * 1024];
    ssize_t n = 0;
    while ((n = read(inFd, buf, sizeof(buf))) > 0) {
        char *p = buf;
        ssize_t remaining = n;
        while (remaining > 0) {
            ssize_t w = write(outFd, p, (size_t)remaining);
            if (w < 0) {
                int saved = errno;
                close(inFd);
                close(outFd);
                unlink(dst.fileSystemRepresentation);
                perr(@"cpfile write dst '%@' failed: %s", dst, strerror(saved));
                return 3;
            }
            remaining -= w;
            p += w;
        }
    }
    if (n < 0) {
        int saved = errno;
        close(inFd);
        close(outFd);
        unlink(dst.fileSystemRepresentation);
        perr(@"cpfile read src '%@' failed: %s", src, strerror(saved));
        return 3;
    }
    fchmod(outFd, 0755);
    fsync(outFd);
    close(inFd);
    close(outFd);
    return 0;
}

static int copy_regular_file(NSString *src, NSString *dst, mode_t mode) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *parent = [dst stringByDeletingLastPathComponent];
    NSError *err = nil;
    if (parent.length && ![fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0755} error:&err]) {
        perr(@"copy mkdir parent '%@' failed: %@", parent, err.localizedDescription ?: @"unknown error");
        return 3;
    }
    int inFd = open(src.fileSystemRepresentation, O_RDONLY);
    if (inFd < 0) {
        perr(@"copy open src '%@' failed: %s", src, strerror(errno));
        return 3;
    }
    unlink(dst.fileSystemRepresentation);
    int outFd = open(dst.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (outFd < 0) {
        int saved = errno;
        close(inFd);
        perr(@"copy open dst '%@' failed: %s", dst, strerror(saved));
        return 3;
    }
    char buf[1024 * 1024];
    ssize_t n = 0;
    while ((n = read(inFd, buf, sizeof(buf))) > 0) {
        char *p = buf;
        ssize_t remaining = n;
        while (remaining > 0) {
            ssize_t w = write(outFd, p, (size_t)remaining);
            if (w < 0) {
                int saved = errno;
                close(inFd);
                close(outFd);
                unlink(dst.fileSystemRepresentation);
                perr(@"copy write dst '%@' failed: %s", dst, strerror(saved));
                return 3;
            }
            remaining -= w;
            p += w;
        }
    }
    if (n < 0) {
        int saved = errno;
        close(inFd);
        close(outFd);
        unlink(dst.fileSystemRepresentation);
        perr(@"copy read src '%@' failed: %s", src, strerror(saved));
        return 3;
    }
    fchmod(outFd, mode);
    fsync(outFd);
    close(inFd);
    close(outFd);
    return 0;
}

static BOOL files_equal(NSString *a, NSString *b, NSString **reason) {
    int fdA = open(a.fileSystemRepresentation, O_RDONLY);
    if (fdA < 0) {
        if (reason) *reason = [NSString stringWithFormat:@"open source failed: %s", strerror(errno)];
        return NO;
    }
    int fdB = open(b.fileSystemRepresentation, O_RDONLY);
    if (fdB < 0) {
        if (reason) *reason = [NSString stringWithFormat:@"open destination failed: %s", strerror(errno)];
        close(fdA);
        return NO;
    }
    struct stat stA;
    struct stat stB;
    if (fstat(fdA, &stA) != 0 || fstat(fdB, &stB) != 0) {
        if (reason) *reason = [NSString stringWithFormat:@"fstat failed: %s", strerror(errno)];
        close(fdA);
        close(fdB);
        return NO;
    }
    if (stA.st_size != stB.st_size) {
        if (reason) *reason = [NSString stringWithFormat:@"size mismatch src=%lld dst=%lld", (long long)stA.st_size, (long long)stB.st_size];
        close(fdA);
        close(fdB);
        return NO;
    }
    char bufA[1024 * 1024];
    char bufB[1024 * 1024];
    off_t offset = 0;
    for (;;) {
        ssize_t nA = read(fdA, bufA, sizeof(bufA));
        ssize_t nB = read(fdB, bufB, sizeof(bufB));
        if (nA < 0 || nB < 0) {
            if (reason) *reason = [NSString stringWithFormat:@"read compare failed at %lld: %s", (long long)offset, strerror(errno)];
            close(fdA);
            close(fdB);
            return NO;
        }
        if (nA != nB) {
            if (reason) *reason = [NSString stringWithFormat:@"read length mismatch at %lld", (long long)offset];
            close(fdA);
            close(fdB);
            return NO;
        }
        if (nA == 0) break;
        if (memcmp(bufA, bufB, (size_t)nA) != 0) {
            if (reason) *reason = [NSString stringWithFormat:@"byte mismatch near offset %lld", (long long)offset];
            close(fdA);
            close(fdB);
            return NO;
        }
        offset += nA;
    }
    close(fdA);
    close(fdB);
    return YES;
}

static int op_replacefile(NSString *src, NSString *dst) {
    if (!pathIsAllowed(src)) { perr(@"replacefile: src not allowed: %@", src); return 2; }
    if (!pathIsAllowed(dst)) { perr(@"replacefile: dst not allowed: %@", dst); return 2; }
    struct stat srcSt;
    if (stat(src.fileSystemRepresentation, &srcSt) != 0) {
        perr(@"replacefile stat src '%@' failed: %s", src, strerror(errno));
        return 3;
    }
    mode_t mode = srcSt.st_mode & 07777;
    if (!mode) mode = 0755;
    NSString *parent = [dst stringByDeletingLastPathComponent];
    NSString *tmp = [parent stringByAppendingPathComponent:[NSString stringWithFormat:@".%@.projectx.%d.tmp", dst.lastPathComponent, getpid()]];
    unlink(tmp.fileSystemRepresentation);
    int rc = copy_regular_file(src, tmp, mode);
    if (rc != 0) return rc;
    if (rename(tmp.fileSystemRepresentation, dst.fileSystemRepresentation) != 0) {
        int saved = errno;
        unlink(tmp.fileSystemRepresentation);
        perr(@"replacefile rename '%@' -> '%@' failed: %s", tmp, dst, strerror(saved));
        return 3;
    }
    int dirFd = open(parent.fileSystemRepresentation, O_RDONLY);
    if (dirFd >= 0) {
        fsync(dirFd);
        close(dirFd);
    }
    NSString *reason = nil;
    if (!files_equal(src, dst, &reason)) {
        perr(@"replacefile verification failed: %@", reason ?: @"unknown mismatch");
        return 3;
    }
    printf("replaced=%s\nverified=YES\n", dst.UTF8String);
    return 0;
}

static NSString *find_ldid(void) {
    NSArray<NSString *> *candidates = @[
        @"/usr/bin/ldid",
        @"/var/jb/usr/bin/ldid",
        @"/private/preboot/jb/usr/bin/ldid",
        @"/bin/ldid"
    ];
    for (NSString *path in candidates) {
        if (access(path.fileSystemRepresentation, X_OK) == 0) return path;
    }
    return nil;
}

static int op_ldidprobe(void) {
    NSString *ldid = find_ldid();
    if (!ldid.length) {
        perr(@"ldid not found");
        return 3;
    }
    printf("%s\n", ldid.UTF8String);
    return 0;
}

static int op_ldidsign(NSString *binaryPath, NSString *entitlementsPath) {
    if (!pathIsAllowed(binaryPath)) { perr(@"ldidsign: binary path not allowed: %@", binaryPath); return 2; }
    if (entitlementsPath.length && !pathIsAllowed(entitlementsPath)) { perr(@"ldidsign: entitlements path not allowed: %@", entitlementsPath); return 2; }
    NSString *ldid = find_ldid();
    if (!ldid.length) {
        perr(@"ldidsign: ldid not found");
        return 3;
    }
    if (access(binaryPath.fileSystemRepresentation, W_OK) != 0) {
        perr(@"ldidsign: binary not writable: %@ (%s)", binaryPath, strerror(errno));
        return 3;
    }
    if (entitlementsPath.length && access(entitlementsPath.fileSystemRepresentation, R_OK) != 0) {
        perr(@"ldidsign: entitlements not readable: %@ (%s)", entitlementsPath, strerror(errno));
        return 3;
    }

    pid_t pid = 0;
    NSString *signArg = entitlementsPath.length ? [@"-S" stringByAppendingString:entitlementsPath] : @"-S";
    const char *argv[] = { ldid.fileSystemRepresentation, signArg.fileSystemRepresentation, binaryPath.fileSystemRepresentation, NULL };
    int rc = posix_spawn(&pid, ldid.fileSystemRepresentation, NULL, NULL, (char *const *)argv, (char *const *)environ);
    if (rc != 0) {
        perr(@"ldidsign: posix_spawn failed: %s", strerror(rc));
        return 3;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        perr(@"ldidsign: waitpid failed: %s", strerror(errno));
        return 3;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        perr(@"ldidsign: ldid failed status=%d", status);
        return 3;
    }
    printf("signed=%s\nldid=%s\nentitlements=%s\n", binaryPath.UTF8String, ldid.UTF8String, entitlementsPath.length ? entitlementsPath.UTF8String : "");
    return 0;
}

static int op_dyldlaunch(NSString *executable, NSString *dylib, NSString *home, NSString *bundleID, NSString *logPath) {
    if (!pathIsAllowed(executable)) { perr(@"dyldlaunch: executable not allowed: %@", executable); return 2; }
    if (!pathIsAllowed(dylib)) { perr(@"dyldlaunch: dylib not allowed: %@", dylib); return 2; }
    NSString *homeForAllow = [home hasSuffix:@"/"] ? home : [home stringByAppendingString:@"/"];
    if (!pathIsAllowed(homeForAllow)) { perr(@"dyldlaunch: home not allowed: %@", home); return 2; }
    if (logPath.length && !pathIsAllowed(logPath)) { perr(@"dyldlaunch: log path not allowed: %@", logPath); return 2; }
    if (bundleID.length == 0 || [bundleID containsString:@"/"]) { perr(@"dyldlaunch: invalid bundleID: %@", bundleID); return 2; }
    if (access(executable.fileSystemRepresentation, X_OK) != 0) { perr(@"dyldlaunch: executable not executable: %@ (%s)", executable, strerror(errno)); return 3; }
    if (access(dylib.fileSystemRepresentation, R_OK) != 0) { perr(@"dyldlaunch: dylib not readable: %@ (%s)", dylib, strerror(errno)); return 3; }

    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];
    mkdir(tmpDir.fileSystemRepresentation, 0700);

    const char *argv[] = { executable.fileSystemRepresentation, NULL };
    NSString *dyld = [@"DYLD_INSERT_LIBRARIES=" stringByAppendingString:dylib];
    NSString *homeEnv = [@"HOME=" stringByAppendingString:home];
    NSString *cfHome = [@"CFFIXED_USER_HOME=" stringByAppendingString:home];
    NSString *tmpEnv = [@"TMPDIR=" stringByAppendingString:[tmpDir stringByAppendingString:@"/"]];
    NSString *bidEnv = [@"PROJECTX_TARGET_BUNDLE_ID=" stringByAppendingString:bundleID];
    NSString *flagEnv = @"PROJECTX_DYLD_LAUNCH=1";
    NSString *printLibs = @"DYLD_PRINT_LIBRARIES=1";
    NSString *printInit = @"DYLD_PRINT_INITIALIZERS=1";
    NSString *printFile = logPath.length ? [@"DYLD_PRINT_TO_FILE=" stringByAppendingString:logPath] : @"DYLD_PRINT_TO_FILE=/tmp/projectx-dyldlaunch.log";
    const char *envp[] = {
        dyld.UTF8String,
        homeEnv.UTF8String,
        cfHome.UTF8String,
        tmpEnv.UTF8String,
        bidEnv.UTF8String,
        flagEnv.UTF8String,
        printLibs.UTF8String,
        printInit.UTF8String,
        printFile.UTF8String,
        NULL
    };

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    int logFd = -1;
    if (logPath.length) {
        unlink(logPath.fileSystemRepresentation);
        logFd = open(logPath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (logFd >= 0) {
            dprintf(logFd, "ProjectX dyldlaunch\nexecutable=%s\ndylib=%s\nhome=%s\nbundleID=%s\nDYLD_INSERT_LIBRARIES=%s\nDYLD_PRINT_TO_FILE=%s\n", executable.UTF8String, dylib.UTF8String, home.UTF8String, bundleID.UTF8String, dylib.UTF8String, logPath.UTF8String);
            fsync(logFd);
            posix_spawn_file_actions_adddup2(&actions, logFd, STDOUT_FILENO);
            posix_spawn_file_actions_adddup2(&actions, logFd, STDERR_FILENO);
            posix_spawn_file_actions_addclose(&actions, logFd);
        }
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 501);
    posix_spawnattr_set_persona_gid_np(&attr, 501);

    pid_t pid = 0;
    int rc = posix_spawn(&pid, executable.fileSystemRepresentation, &actions, &attr, (char *const *)argv, (char *const *)envp);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        appendLogLine(logPath, @"posix_spawn_failed rc=%d errno=%d message=%s", rc, errno, strerror(rc));
        if (logFd >= 0) close(logFd);
        perr(@"dyldlaunch: posix_spawn failed executable=%@ rc=%d (%s)", executable, rc, strerror(rc));
        return 3;
    }
    if (logFd >= 0) close(logFd);
    printf("pid=%d\n", pid);
    fflush(stdout);
    appendLogLine(logPath, @"spawn_success pid=%d", pid);
    usleep(1000 * 1000);
    int status = 0;
    pid_t waitResult = waitpid(pid, &status, WNOHANG);
    if (waitResult == 0) {
        printf("child_alive_after_1s=YES\n");
        appendLogLine(logPath, @"child_alive_after_1s=YES");
    } else if (waitResult == pid) {
        if (WIFEXITED(status)) {
            printf("child_exited_after_1s=YES exit=%d\n", WEXITSTATUS(status));
            appendLogLine(logPath, @"child_exited_after_1s=YES exit=%d", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("child_signaled_after_1s=YES signal=%d\n", WTERMSIG(status));
            appendLogLine(logPath, @"child_signaled_after_1s=YES signal=%d", WTERMSIG(status));
        } else {
            printf("child_status_after_1s=%d\n", status);
            appendLogLine(logPath, @"child_status_after_1s=%d", status);
        }
    } else {
        printf("waitpid_after_1s_failed=%s\n", strerror(errno));
        appendLogLine(logPath, @"waitpid_after_1s_failed=%s", strerror(errno));
    }
    fflush(stdout);
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
        if ([op isEqualToString:@"rmglob"]) {
            if (argc != 4) { perr(@"rmglob: expects <dir> <pattern>"); return 2; }
            return op_rmglob(@(argv[2]), @(argv[3]));
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
        if ([op isEqualToString:@"mkdir"]) {
            if (argc != 3) { perr(@"mkdir: expects <path>"); return 2; }
            return op_mkdir(@(argv[2]));
        }
        if ([op isEqualToString:@"cpfile"]) {
            if (argc != 4) { perr(@"cpfile: expects <src> <dst>"); return 2; }
            return op_cpfile(@(argv[2]), @(argv[3]));
        }
        if ([op isEqualToString:@"replacefile"]) {
            if (argc != 4) { perr(@"replacefile: expects <src> <dst>"); return 2; }
            return op_replacefile(@(argv[2]), @(argv[3]));
        }
        if ([op isEqualToString:@"ldidprobe"]) {
            if (argc != 2) { perr(@"ldidprobe: expects no args"); return 2; }
            return op_ldidprobe();
        }
        if ([op isEqualToString:@"ldidsign"]) {
            if (argc != 3 && argc != 4) { perr(@"ldidsign: expects <binary-path> [entitlements-plist]"); return 2; }
            NSString *entitlementsPath = argc == 4 ? @(argv[3]) : nil;
            return op_ldidsign(@(argv[2]), entitlementsPath);
        }
        if ([op isEqualToString:@"dyldlaunch"]) {
            if (argc != 6 && argc != 7) { perr(@"dyldlaunch: expects <executable> <dylib> <home> <bundleID> [logPath]"); return 2; }
            NSString *logPath = argc == 7 ? @(argv[6]) : nil;
            return op_dyldlaunch(@(argv[2]), @(argv[3]), @(argv[4]), @(argv[5]), logPath);
        }

        perr(@"unknown op: %@", op);
        return 2;
    }
}
