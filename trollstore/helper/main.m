// weaponx_root_helper — minimal root-privileged helper for TrollStore.
//
// This binary is declared in the main app's TSRootBinaries and is invoked via
// TSUtil spawnRoot: (see PXRootHelper). It runs as uid 0 and performs ONLY the
// small set of operations that genuinely require root: removing root-owned
// files under /var/root and chowning system-scoped paths back to mobile.
//
// It is deliberately tiny and does its own in-process work (no /bin/sh): it
// uses removefile(3) and lchown(2)/chown(2) directly so it has no dependency
// on shell or jailbreak binaries.
//
// Usage (argv):
//   weaponx_root_helper rm    <absolute-path>
//   weaponx_root_helper chown <uid> <gid> <absolute-path>   (recursive)
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
#import <unistd.h>
#import <dirent.h>
#import <string.h>

// Allowlisted path prefixes the helper is permitted to operate on. Anything
// outside these is rejected even though we run as root.
static const char *kAllowedPrefixes[] = {
    "/var/root/Library/Preferences/",
    "/var/mobile/Library/Safari",
    "/var/mobile/Library/",
    "/private/var/root/Library/Preferences/",
    "/private/var/mobile/Library/",
};

static BOOL PathIsAllowed(const char *path) {
    if (path == NULL || path[0] != '/') return NO;
    // Reject parent-directory traversal outright.
    if (strstr(path, "/../") != NULL) return NO;
    size_t n = sizeof(kAllowedPrefixes) / sizeof(kAllowedPrefixes[0]);
    for (size_t i = 0; i < n; i++) {
        if (strncmp(path, kAllowedPrefixes[i], strlen(kAllowedPrefixes[i])) == 0) {
            return YES;
        }
    }
    return NO;
}

static int DoRemove(const char *path) {
    if (!PathIsAllowed(path)) {
        fprintf(stderr, "weaponx_root_helper: path not allowed: %s\n", path);
        return 3;
    }
    removefile_state_t state = removefile_state_alloc();
    int rc = removefile(path, state, REMOVEFILE_RECURSIVE);
    removefile_state_free(state);
    if (rc != 0) {
        fprintf(stderr, "weaponx_root_helper: removefile failed for %s: %s\n",
                path, strerror(errno));
        return 3;
    }
    return 0;
}

static int ChownRecursive(const char *path, uid_t uid, gid_t gid) {
    if (lchown(path, uid, gid) != 0 && errno != ENOENT) {
        fprintf(stderr, "weaponx_root_helper: lchown failed for %s: %s\n",
                path, strerror(errno));
        return 3;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        return 0; // vanished; tolerate
    }
    if (!S_ISDIR(st.st_mode)) {
        return 0;
    }
    DIR *d = opendir(path);
    if (d == NULL) {
        return 0; // not fatal
    }
    int result = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        int rc = ChownRecursive(child, uid, gid);
        if (rc != 0) {
            result = rc;
        }
    }
    closedir(d);
    return result;
}

static int DoChown(const char *uidStr, const char *gidStr, const char *path) {
    if (!PathIsAllowed(path)) {
        fprintf(stderr, "weaponx_root_helper: path not allowed: %s\n", path);
        return 3;
    }
    uid_t uid = (uid_t)strtoul(uidStr, NULL, 10);
    gid_t gid = (gid_t)strtoul(gidStr, NULL, 10);
    return ChownRecursive(path, uid, gid);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            fprintf(stderr, "usage: weaponx_root_helper <rm|chown> ...\n");
            return 2;
        }
        const char *op = argv[1];
        if (strcmp(op, "rm") == 0) {
            if (argc != 3) {
                fprintf(stderr, "usage: weaponx_root_helper rm <path>\n");
                return 2;
            }
            return DoRemove(argv[2]);
        } else if (strcmp(op, "chown") == 0) {
            if (argc != 5) {
                fprintf(stderr, "usage: weaponx_root_helper chown <uid> <gid> <path>\n");
                return 2;
            }
            return DoChown(argv[2], argv[3], argv[4]);
        }
        fprintf(stderr, "weaponx_root_helper: unknown op: %s\n", op);
        return 2;
    }
}
