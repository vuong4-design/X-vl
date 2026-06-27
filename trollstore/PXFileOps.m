// PXFileOps.m — In-process replacements for shelled-out file operations.
// See PXFileOps.h for the contract.

#import "PXFileOps.h"
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>

NSString *const PXFileOpsErrorDomain = @"com.hydra.projectx.fileops";

static NSError *PXMakeError(PXFileOpsError code, NSString *desc) {
    return [NSError errorWithDomain:PXFileOpsErrorDomain
                              code:code
                          userInfo:@{NSLocalizedDescriptionKey: desc}];
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

    if (chmod(path.fileSystemRepresentation, mode) != 0) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"chmod failed for '%@': %s", path, strerror(errno)];
            *error = PXMakeError(PXFileOpsErrorChmodFailed, desc);
        }
        return NO;
    }

    if (!recursive) {
        return YES;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:path isDirectory:&isDir] && isDir) {
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:path];
        for (NSString *rel in en) {
            NSString *child = [path stringByAppendingPathComponent:rel];
            if (chmod(child.fileSystemRepresentation, mode) != 0) {
                if (error) {
                    NSString *desc = [NSString stringWithFormat:
                        @"chmod failed for '%@': %s", child, strerror(errno)];
                    *error = PXMakeError(PXFileOpsErrorChmodFailed, desc);
                }
                return NO;
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

    // chflags with flags=0 clears uchg/uimmutable. Tolerate ENOENT.
    if (chflags(path.fileSystemRepresentation, 0) != 0 && errno != ENOENT) {
        if (error) {
            NSString *desc = [NSString stringWithFormat:
                @"chflags failed for '%@': %s", path, strerror(errno)];
            *error = PXMakeError(PXFileOpsErrorChflagsFailed, desc);
        }
        return NO;
    }

    if (!recursive) {
        return YES;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:path isDirectory:&isDir] && isDir) {
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:path];
        for (NSString *rel in en) {
            NSString *child = [path stringByAppendingPathComponent:rel];
            if (chflags(child.fileSystemRepresentation, 0) != 0 && errno != ENOENT) {
                if (error) {
                    NSString *desc = [NSString stringWithFormat:
                        @"chflags failed for '%@': %s", child, strerror(errno)];
                    *error = PXMakeError(PXFileOpsErrorChflagsFailed, desc);
                }
                return NO;
            }
        }
    }
    return YES;
}

@end
