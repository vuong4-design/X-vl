// PXFileOps.h — In-process replacements for the shelled-out file operations
// that previously ran via /bin/sh (rm/mkdir/mv/cp/chmod/chflags/find).
//
// Every method operates on mobile-owned paths under no-sandbox and returns a
// real NSError on failure. There is NO silent failure: callers can distinguish
// "did nothing" from "succeeded". Operations that genuinely require uid 0 must
// NOT use this class — route them through PXRootHelper instead.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const PXFileOpsErrorDomain;

typedef NS_ENUM(NSInteger, PXFileOpsError) {
    PXFileOpsErrorInvalidArgs   = 1, // nil/empty path argument
    PXFileOpsErrorRemoveFailed  = 2, // removeItemAtPath: failed
    PXFileOpsErrorCreateFailed  = 3, // createDirectoryAtPath: failed
    PXFileOpsErrorMoveFailed    = 4, // moveItemAtPath: failed
    PXFileOpsErrorCopyFailed    = 5, // copyItemAtPath: failed
    PXFileOpsErrorChmodFailed   = 6, // chmod(2) failed
    PXFileOpsErrorChflagsFailed = 7, // chflags(2) failed
};

@interface PXFileOps : NSObject

// Removes the item at `path` (file or directory tree). Succeeds (YES) if the
// path does not exist. Replaces `rm -rf '<path>'`.
+ (BOOL)removePath:(NSString *)path error:(NSError * _Nullable * _Nullable)error;

// Removes every child of `dirPath` whose name is NOT in `keepNames`. Replaces
// `find <dir> -not -name X -exec rm -rf {} +` and `rm -rf '<dir>'/*`.
+ (BOOL)removeContentsOfDirectory:(NSString *)dirPath
                       keepNames:(nullable NSArray<NSString *> *)keepNames
                           error:(NSError * _Nullable * _Nullable)error;

// Creates a directory (with intermediates). Replaces `mkdir -p '<path>'`.
+ (BOOL)createDirectory:(NSString *)path error:(NSError * _Nullable * _Nullable)error;

// Moves `src` -> `dst`, removing an existing item at `dst` first. Replaces
// `mv '<src>' '<dst>'`.
+ (BOOL)movePath:(NSString *)src
          toPath:(NSString *)dst
           error:(NSError * _Nullable * _Nullable)error;

// Copies `src` -> `dst`, removing an existing item at `dst` first. Replaces
// `cp '<src>' '<dst>'`.
+ (BOOL)copyPath:(NSString *)src
          toPath:(NSString *)dst
           error:(NSError * _Nullable * _Nullable)error;

// Applies POSIX permission bits. Replaces `chmod <mode> '<path>'`.
+ (BOOL)chmodPath:(NSString *)path
             mode:(mode_t)mode
        recursive:(BOOL)recursive
            error:(NSError * _Nullable * _Nullable)error;

// Clears the uchg (user-immutable) flag. Replaces `chflags -R nouchg '<path>'`.
+ (BOOL)clearImmutableFlagAtPath:(NSString *)path
                       recursive:(BOOL)recursive
                           error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
