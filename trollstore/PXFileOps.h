// PXFileOps.h — In-process replacements for the shelled-out file operations
// that previously ran via /bin/sh (rm/mkdir/mv/cp/chmod/chflags/find/touch/
// chown/sync/glob).
//
// Every method operates on mobile-owned paths under no-sandbox and returns a
// real NSError on failure. There is NO silent failure: callers can distinguish
// "did nothing" from "succeeded". Operations that genuinely require uid 0 must
// NOT use this class — route them through PXRootHelper instead. The chown
// helper here surfaces errno in NSError.userInfo so the router can decide to
// fall back to PXRootHelper on EPERM/EACCES.

#import <Foundation/Foundation.h>
#import <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const PXFileOpsErrorDomain;
extern NSString *const PXFileOpsErrnoUserInfoKey;

typedef NS_ENUM(NSInteger, PXFileOpsError) {
    PXFileOpsErrorInvalidArgs   = 1,
    PXFileOpsErrorRemoveFailed  = 2,
    PXFileOpsErrorCreateFailed  = 3,
    PXFileOpsErrorMoveFailed    = 4,
    PXFileOpsErrorCopyFailed    = 5,
    PXFileOpsErrorChmodFailed   = 6,
    PXFileOpsErrorChflagsFailed = 7,
    PXFileOpsErrorTouchFailed   = 8,
    PXFileOpsErrorChownFailed   = 9,
    PXFileOpsErrorGlobFailed    = 10,
};

@interface PXFileOps : NSObject

// rm -rf '<path>' (absent path == success).
+ (BOOL)removePath:(NSString *)path error:(NSError * _Nullable * _Nullable)error;

// Remove children of dirPath whose name is NOT in keepNames. When recursive==YES
// descend into subdirectories and re-apply the filter at every level.
+ (BOOL)removeContentsOfDirectory:(NSString *)dirPath
                        keepNames:(nullable NSArray<NSString *> *)keepNames
                        recursive:(BOOL)recursive
                            error:(NSError * _Nullable * _Nullable)error;

// Convenience: top-level only.
+ (BOOL)removeContentsOfDirectory:(NSString *)dirPath
                        keepNames:(nullable NSArray<NSString *> *)keepNames
                            error:(NSError * _Nullable * _Nullable)error;

// Remove entries under dirPath whose name matches fnmatch(3) pattern. Non-recursive.
+ (BOOL)removeMatchingGlob:(NSString *)pattern
               inDirectory:(NSString *)dirPath
                     error:(NSError * _Nullable * _Nullable)error;

// Walk root, remove entries where predicate returns YES.
+ (BOOL)removePathsUnderRoot:(NSString *)root
          matchingPredicate:(BOOL (^)(NSString *path, BOOL isDirectory))predicate
                       error:(NSError * _Nullable * _Nullable)error;

// find <root> -depth -type d -empty -delete (root itself untouched).
+ (BOOL)removeEmptyDirectoriesUnder:(NSString *)root
                              error:(NSError * _Nullable * _Nullable)error;

// mkdir -p '<path>'.
+ (BOOL)createDirectory:(NSString *)path error:(NSError * _Nullable * _Nullable)error;

// mv '<src>' '<dst>' (removes existing dst first).
+ (BOOL)movePath:(NSString *)src
          toPath:(NSString *)dst
           error:(NSError * _Nullable * _Nullable)error;

// cp '<src>' '<dst>' (removes existing dst first).
+ (BOOL)copyPath:(NSString *)src
          toPath:(NSString *)dst
           error:(NSError * _Nullable * _Nullable)error;

// touch '<path>' — updates atime/mtime; creates empty file if createIfMissing.
+ (BOOL)touchPath:(NSString *)path
  createIfMissing:(BOOL)createIfMissing
            error:(NSError * _Nullable * _Nullable)error;

// chmod [-R] MODE '<path>' — uses fchmodat(AT_SYMLINK_NOFOLLOW); never follows symlinks.
+ (BOOL)chmodPath:(NSString *)path
             mode:(mode_t)mode
        recursive:(BOOL)recursive
            error:(NSError * _Nullable * _Nullable)error;

// chflags [-R] nouchg,noschg '<path>' — uses lchflags(2); never follows symlinks.
+ (BOOL)clearImmutableFlagAtPath:(NSString *)path
                       recursive:(BOOL)recursive
                           error:(NSError * _Nullable * _Nullable)error;

// chown [-R] UID:GID '<path>' — lchown(2); errno surfaced for router fallback.
+ (BOOL)chownPath:(NSString *)path
              uid:(uid_t)uid
              gid:(gid_t)gid
        recursive:(BOOL)recursive
            error:(NSError * _Nullable * _Nullable)error;

// sync(2).
+ (void)syncFilesystem;

@end

NS_ASSUME_NONNULL_END
