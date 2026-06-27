// PXFileOps.m — In-process replacements for shelled-out file operations.
// See PXFileOps.h for the contract.

#import "PXFileOps.h"
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>
#import <fcntl.h>
#import <fnmatch.h>
#import <dirent.h>
#import <errno.h>
#import <string.h>

NSString *const PXFileOpsErrorDomain = @"com.hydra.projectx.fileops";
NSString *const PXFileOpsErrnoUserInfoKey = @"PXFileOpsErrno";

static NSError *PXMakeError(PXFileOpsError code, NSString *desc) {
    return [NSError errorWithDomain:PXFileOpsErrorDomain
                              code:code
                          userInfo:@{NSLocalizedDescriptionKey: desc}];
}

// Variant that carries errno so the router can decide to fall back to
// PXRootHelper on EPERM/EACCES.
static NSError *PXMakeErrnoError(PXFileOpsError code, NSString *desc, int err) {
    return [NSError errorWithDomain:PXFileOpsErrorDomain
                              code:code
                          userInfo:@{
        NSLocalizedDescriptionKey: desc,
        PXFileOpsErrnoUserInfoKey: @(err),
    }];
}

static BOOL PXIsNonEmpty(NSString *path) {
    return (path != nil && path.length > 0);
}

@implementation PXFileOps

+ (BOOL)removePath:(NSString *)path error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(path)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"removePath: nil/empty path");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        // rm -rf semantics: absent path is success.
        return YES;
    }

    NSError *rmErr = nil;
    if (![fm removeItemAtPath:path error:&rmErr]) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"Failed to remove '%@': %@", path,
                rmErr.localizedDescription ?: @"unknown error"];
            *error = PXMakeError(PXFileOpsErrorRemoveFailed, desc);
        }
        return NO;
    }
    return YES;
}

+ (BOOL)removeContentsOfDirectory:(NSString *)dirPath
                       keepNames:(nullable NSArray<NSString *> *)keepNames
                           error:(NSError * _Nullable * _Nullable)error {
    return [self removeContentsOfDirectory:dirPath
                                keepNames:keepNames
                                recursive:NO
                                    error:error];
}

+ (BOOL)removeContentsOfDirectory:(NSString *)dirPath
                       keepNames:(nullable NSArray<NSString *> *)keepNames
                       recursive:(BOOL)recursive
                           error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(dirPath)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"removeContentsOfDirectory: nil/empty path");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dirPath]) {
        return YES; // nothing to clear
    }

    NSError *listErr = nil;
    NSArray<NSString *> *children = [fm contentsOfDirectoryAtPath:dirPath error:&listErr];
    if (!children) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"Failed to list '%@': %@", dirPath,
                listErr.localizedDescription ?: @"unknown error"];
            *error = PXMakeError(PXFileOpsErrorRemoveFailed, desc);
        }
        return NO;
    }

    NSSet<NSString *> *keep = keepNames ? [NSSet setWithArray:keepNames] : [NSSet set];
    for (NSString *name in children) {
        if ([keep containsObject:name]) {
            // When recursive and this kept entry is a directory, descend to
            // re-apply the keep filter at every level.
            if (recursive) {
                NSString *child = [dirPath stringByAppendingPathComponent:name];
                BOOL isDir = NO;
                if ([fm fileExistsAtPath:child isDirectory:&isDir] && isDir) {
                    if (![self removeContentsOfDirectory:child
                                              keepNames:keepNames
                                              recursive:YES
                                                  error:error]) {
                        return NO;
                    }
                }
            }
            continue;
        }
        NSString *child = [dirPath stringByAppendingPathComponent:name];
        NSError *rmErr = nil;
        if (![fm removeItemAtPath:child error:&rmErr]) {
            if (error) {
                NSString *desc = [NSString stringWithFormat:
                    @"Failed to remove '%@': %@", child,
                    rmErr.localizedDescription ?: @"unknown error"];
                *error = PXMakeError(PXFileOpsErrorRemoveFailed, desc);
            }
            return NO;
        }
    }
    return YES;
}

+ (BOOL)createDirectory:(NSString *)path error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(path)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"createDirectory: nil/empty path");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *mkErr = nil;
    if (![fm createDirectoryAtPath:path
       withIntermediateDirectories:YES
                        attributes:nil
                             error:&mkErr]) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"Failed to create directory '%@': %@", path,
                mkErr.localizedDescription ?: @"unknown error"];
            *error = PXMakeError(PXFileOpsErrorCreateFailed, desc);
        }
        return NO;
    }
    return YES;
}

+ (BOOL)movePath:(NSString *)src
          toPath:(NSString *)dst
           error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(src) || !PXIsNonEmpty(dst)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"movePath: nil/empty src or dst");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:dst]) {
        NSError *rmErr = nil;
        if (![fm removeItemAtPath:dst error:&rmErr]) {
            if (error) {
                NSString *desc = [NSString stringWithFormat:
                    @"Failed to clear destination '%@': %@", dst,
                    rmErr.localizedDescription ?: @"unknown error"];
                *error = PXMakeError(PXFileOpsErrorMoveFailed, desc);
            }
            return NO;
        }
    }

    NSError *mvErr = nil;
    if (![fm moveItemAtPath:src toPath:dst error:&mvErr]) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"Failed to move '%@' -> '%@': %@", src, dst,
                mvErr.localizedDescription ?: @"unknown error"];
            *error = PXMakeError(PXFileOpsErrorMoveFailed, desc);
        }
        return NO;
    }
    return YES;
}

+ (BOOL)copyPath:(NSString *)src
          toPath:(NSString *)dst
           error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(src) || !PXIsNonEmpty(dst)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"copyPath: nil/empty src or dst");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:dst]) {
        NSError *rmErr = nil;
        if (![fm removeItemAtPath:dst error:&rmErr]) {
            if (error) {
                NSString *desc = [NSString stringWithFormat:
                    @"Failed to clear destination '%@': %@", dst,
                    rmErr.localizedDescription ?: @"unknown error"];
                *error = PXMakeError(PXFileOpsErrorCopyFailed, desc);
            }
            return NO;
        }
    }

    NSError *cpErr = nil;
    if (![fm copyItemAtPath:src toPath:dst error:&cpErr]) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"Failed to copy '%@' -> '%@': %@", src, dst,
                cpErr.localizedDescription ?: @"unknown error"];
            *error = PXMakeError(PXFileOpsErrorCopyFailed, desc);
        }
        return NO;
    }
    return YES;
}

+ (BOOL)chmodPath:(NSString *)path
             mode:(mode_t)mode
        recursive:(BOOL)recursive
            error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(path)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"chmodPath: nil/empty path");
        return NO;
    }

    // fchmodat with AT_SYMLINK_NOFOLLOW never follows a symlink: if the path
    // itself is a symlink we change the link's mode, not the target's.
    if (fchmodat(AT_FDCWD, path.fileSystemRepresentation, mode, AT_SYMLINK_NOFOLLOW) != 0) {
        // Some filesystems return ENOTSUP for AT_SYMLINK_NOFOLLOW on non-link
        // entries; retry without the flag only when the entry is NOT a symlink.
        struct stat st;
        if (errno == ENOTSUP &&
            lstat(path.fileSystemRepresentation, &st) == 0 &&
            !S_ISLNK(st.st_mode)) {
            if (chmod(path.fileSystemRepresentation, mode) != 0) {
                if (error) {
                    NSString *desc = [NSString stringWithFormat:
                        @"chmod failed for '%@': %s", path, strerror(errno)];
                    *error = PXMakeErrnoError(PXFileOpsErrorChmodFailed, desc, errno);
                }
                return NO;
            }
        } else {
            if (error) {
                NSString *desc = [NSString stringWithFormat:
                    @"chmod failed for '%@': %s", path, strerror(errno)];
                *error = PXMakeErrnoError(PXFileOpsErrorChmodFailed, desc, errno);
            }
            return NO;
        }
    }

    if (!recursive) {
        return YES;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:path isDirectory:&isDir] && isDir) {
        // Do not follow symlinks while descending.
        NSDirectoryEnumerator *en =
            [fm enumeratorAtURL:[NSURL fileURLWithPath:path]
     includingPropertiesForKeys:@[NSURLIsSymbolicLinkKey]
                        options:0
                   errorHandler:nil];
        for (NSURL *url in en) {
            NSNumber *isLink = nil;
            [url getResourceValue:&isLink forKey:NSURLIsSymbolicLinkKey error:NULL];
            const char *cpath = url.path.fileSystemRepresentation;
            if (fchmodat(AT_FDCWD, cpath, mode, AT_SYMLINK_NOFOLLOW) != 0) {
                struct stat st;
                if (errno == ENOTSUP &&
                    lstat(cpath, &st) == 0 && !S_ISLNK(st.st_mode)) {
                    if (chmod(cpath, mode) != 0) {
                        if (error) {
                            NSString *desc = [NSString stringWithFormat:
                                @"chmod failed for '%@': %s", url.path, strerror(errno)];
                            *error = PXMakeErrnoError(PXFileOpsErrorChmodFailed, desc, errno);
                        }
                        return NO;
                    }
                } else {
                    if (error) {
                        NSString *desc = [NSString stringWithFormat:
                            @"chmod failed for '%@': %s", url.path, strerror(errno)];
                        *error = PXMakeErrnoError(PXFileOpsErrorChmodFailed, desc, errno);
                    }
                    return NO;
                }
            }
        }
    }
    return YES;
}

+ (BOOL)clearImmutableFlagAtPath:(NSString *)path
                       recursive:(BOOL)recursive
                           error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(path)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"clearImmutableFlag: nil/empty path");
        return NO;
    }

    // lchflags(flags=0) clears uchg/uimmutable without following a symlink.
    // Tolerate ENOENT (path already gone == success).
    if (lchflags(path.fileSystemRepresentation, 0) != 0 && errno != ENOENT) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"chflags failed for '%@': %s", path, strerror(errno)];
            *error = PXMakeErrnoError(PXFileOpsErrorChflagsFailed, desc, errno);
        }
        return NO;
    }

    if (!recursive) {
        return YES;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:path isDirectory:&isDir] && isDir) {
        // Do not follow symlinks while descending.
        NSDirectoryEnumerator *en =
            [fm enumeratorAtURL:[NSURL fileURLWithPath:path]
     includingPropertiesForKeys:@[NSURLIsSymbolicLinkKey]
                        options:0
                   errorHandler:nil];
        for (NSURL *url in en) {
            const char *cpath = url.path.fileSystemRepresentation;
            if (lchflags(cpath, 0) != 0 && errno != ENOENT) {
                if (error) {
                    NSString *desc = [NSString stringWithFormat:
                        @"chflags failed for '%@': %s", url.path, strerror(errno)];
                    *error = PXMakeErrnoError(PXFileOpsErrorChflagsFailed, desc, errno);
                }
                return NO;
            }
        }
    }
    return YES;
}

+ (BOOL)removeMatchingGlob:(NSString *)pattern
               inDirectory:(NSString *)dirPath
                     error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(pattern) || !PXIsNonEmpty(dirPath)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"removeMatchingGlob: nil/empty pattern or dir");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dirPath]) {
        return YES; // nothing to match
    }

    NSError *listErr = nil;
    NSArray<NSString *> *children = [fm contentsOfDirectoryAtPath:dirPath error:&listErr];
    if (!children) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"Failed to list '%@': %@", dirPath,
                listErr.localizedDescription ?: @"unknown error"];
            *error = PXMakeError(PXFileOpsErrorGlobFailed, desc);
        }
        return NO;
    }

    const char *cpattern = pattern.fileSystemRepresentation;
    for (NSString *name in children) {
        // fnmatch against the entry name only: the glob never escapes dirPath.
        if (fnmatch(cpattern, name.fileSystemRepresentation, FNM_PERIOD) == 0) {
            NSString *child = [dirPath stringByAppendingPathComponent:name];
            NSError *rmErr = nil;
            if (![fm removeItemAtPath:child error:&rmErr]) {
                if (error) {
                    NSString *desc = [NSString stringWithFormat:
                        @"Failed to remove '%@': %@", child,
                        rmErr.localizedDescription ?: @"unknown error"];
                    *error = PXMakeError(PXFileOpsErrorGlobFailed, desc);
                }
                return NO;
            }
        }
    }
    return YES;
}

+ (BOOL)removePathsUnderRoot:(NSString *)root
          matchingPredicate:(BOOL (^)(NSString *path, BOOL isDirectory))predicate
                       error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(root) || predicate == nil) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"removePathsUnderRoot: nil/empty root or predicate");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:root]) {
        return YES;
    }

    // Collect matches first (depth-first, deepest last) so removing children
    // does not perturb the live enumeration.
    NSDirectoryEnumerator *en =
        [fm enumeratorAtURL:[NSURL fileURLWithPath:root]
 includingPropertiesForKeys:@[NSURLIsDirectoryKey]
                    options:0
               errorHandler:nil];
    NSMutableArray<NSString *> *matches = [NSMutableArray array];
    for (NSURL *url in en) {
        NSNumber *isDirNum = nil;
        [url getResourceValue:&isDirNum forKey:NSURLIsDirectoryKey error:NULL];
        BOOL isDir = isDirNum.boolValue;
        if (predicate(url.path, isDir)) {
            [matches addObject:url.path];
        }
    }

    // Remove deepest paths first so a matched directory's matched children are
    // gone before we remove the directory itself.
    [matches sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        return [@(b.length) compare:@(a.length)];
    }];

    for (NSString *path in matches) {
        if (![fm fileExistsAtPath:path]) {
            continue; // already removed as part of a parent
        }
        NSError *rmErr = nil;
        if (![fm removeItemAtPath:path error:&rmErr]) {
            if (error) {
                NSString *desc = [NSString stringWithFormat:
                    @"Failed to remove '%@': %@", path,
                    rmErr.localizedDescription ?: @"unknown error"];
                *error = PXMakeError(PXFileOpsErrorRemoveFailed, desc);
            }
            return NO;
        }
    }
    return YES;
}

+ (BOOL)removeEmptyDirectoriesUnder:(NSString *)root
                              error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(root)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"removeEmptyDirectoriesUnder: nil/empty root");
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:root]) {
        return YES;
    }

    // Gather all directories, deepest first, then rmdir those that are empty.
    // rmdir only succeeds on empty dirs, so removing depth-first naturally
    // collapses newly-emptied parents.
    NSDirectoryEnumerator *en =
        [fm enumeratorAtURL:[NSURL fileURLWithPath:root]
 includingPropertiesForKeys:@[NSURLIsDirectoryKey]
                    options:0
               errorHandler:nil];
    NSMutableArray<NSString *> *dirs = [NSMutableArray array];
    for (NSURL *url in en) {
        NSNumber *isDirNum = nil;
        [url getResourceValue:&isDirNum forKey:NSURLIsDirectoryKey error:NULL];
        if (isDirNum.boolValue) {
            [dirs addObject:url.path];
        }
    }
    [dirs sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        return [@(b.length) compare:@(a.length)];
    }];

    for (NSString *dir in dirs) {
        // rmdir fails with ENOTEMPTY for non-empty dirs: that is fine, skip.
        if (rmdir(dir.fileSystemRepresentation) != 0 &&
            errno != ENOTEMPTY && errno != ENOENT && errno != EEXIST) {
            if (error) {
                NSString *desc = [NSString stringWithFormat:
                    @"rmdir failed for '%@': %s", dir, strerror(errno)];
                *error = PXMakeErrnoError(PXFileOpsErrorRemoveFailed, desc, errno);
            }
            return NO;
        }
    }
    return YES;
}

+ (BOOL)touchPath:(NSString *)path
  createIfMissing:(BOOL)createIfMissing
            error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(path)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"touchPath: nil/empty path");
        return NO;
    }

    const char *cpath = path.fileSystemRepresentation;

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        if (!createIfMissing) {
            // touch on a missing file without create: nothing to do, success.
            return YES;
        }
        int fd = open(cpath, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            if (error) {
                NSString *desc = [NSString stringWithFormat:
                    @"touch (create) failed for '%@': %s", path, strerror(errno)];
                *error = PXMakeErrnoError(PXFileOpsErrorTouchFailed, desc, errno);
            }
            return NO;
        }
        close(fd);
        return YES;
    }

    // Bump atime+mtime to now. utimes(NULL) sets both to current time.
    if (utimes(cpath, NULL) != 0) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"touch (utimes) failed for '%@': %s", path, strerror(errno)];
            *error = PXMakeErrnoError(PXFileOpsErrorTouchFailed, desc, errno);
        }
        return NO;
    }
    return YES;
}

+ (BOOL)chownPath:(NSString *)path
              uid:(uid_t)uid
              gid:(gid_t)gid
        recursive:(BOOL)recursive
            error:(NSError * _Nullable * _Nullable)error {
    if (!PXIsNonEmpty(path)) {
        if (error) *error = PXMakeError(PXFileOpsErrorInvalidArgs, @"chownPath: nil/empty path");
        return NO;
    }

    // lchown never follows a symlink. errno is surfaced so the router can fall
    // back to PXRootHelper on EPERM/EACCES.
    if (lchown(path.fileSystemRepresentation, uid, gid) != 0) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"chown failed for '%@': %s", path, strerror(errno)];
            *error = PXMakeErrnoError(PXFileOpsErrorChownFailed, desc, errno);
        }
        return NO;
    }

    if (!recursive) {
        return YES;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:path isDirectory:&isDir] && isDir) {
        NSDirectoryEnumerator *en =
            [fm enumeratorAtURL:[NSURL fileURLWithPath:path]
     includingPropertiesForKeys:nil
                        options:0
                   errorHandler:nil];
        for (NSURL *url in en) {
            if (lchown(url.path.fileSystemRepresentation, uid, gid) != 0) {
                if (error) {
                    NSString *desc = [NSString stringWithFormat:
                        @"chown failed for '%@': %s", url.path, strerror(errno)];
                    *error = PXMakeErrnoError(PXFileOpsErrorChownFailed, desc, errno);
                }
                return NO;
            }
        }
    }
    return YES;
}

+ (void)syncFilesystem {
    sync();
}

@end
