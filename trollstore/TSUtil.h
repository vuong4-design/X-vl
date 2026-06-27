// TSUtil.h — Minimal stub declaration for standalone compilation.
//
// This is a MINIMAL stub exposing only the spawnRoot: entry point that
// PXRootHelper depends on. At build time, link against the real TrollStore
// TSUtil implementation (from the TrollStore source tree) which provides the
// full persona-mgmt based root spawning. Do NOT ship this stub as the actual
// implementation — it only exists so the trollstore/ module compiles
// independently of the TrollStore source.
//
// Real source: https://github.com/opa334/TrollStore (Shared/TSUtil.{h,m})

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TSUtil : NSObject

// Spawns the binary at `path` with `args` as root (uid 0) via TrollStore's
// persona-mgmt mechanism. Returns the child's exit code (0 on success).
//
// - path:   absolute path to a binary declared in the app's TSRootBinaries.
// - args:   argument vector (argv[1...]); argv[0] is set to `path` internally.
// - stdOut: if non-NULL, receives the child's captured stdout as an NSString.
// - stdErr: if non-NULL, receives the child's captured stderr as an NSString.
//
// NOTE: Only functional on iOS <= 17.0 (practically < 17.6). From iOS 17.6
// onward the underlying persona-mgmt path is mitigated and this returns a
// non-zero failure code. Callers MUST treat a non-zero return as a hard error
// and surface it (no silent fallback).
+ (int)spawnRoot:(NSString *)path
            args:(nullable NSArray<NSString *> *)args
          stdOut:(NSString * _Nullable * _Nullable)stdOut
          stdErr:(NSString * _Nullable * _Nullable)stdErr;

@end

NS_ASSUME_NONNULL_END
