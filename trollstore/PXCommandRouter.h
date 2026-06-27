// PXCommandRouter.h — Translates the legacy /bin/sh command strings used by
// AppDataCleaner into in-process PXFileOps primitives, falling back to
// PXRootHelper for genuinely uid-0 paths.
//
// This is the single chokepoint that replaces `runCommandWithPrivileges:`'s
// shell-out. It parses a (possibly composite) shell string, dispatches each
// simple command to a handler, and applies the anti-forensic semantics the
// vendor cleaners depend on:
//
//   * `A; B; C`      -> sequential, a failure in A does NOT stop B/C.
//   * `A && B`       -> sequential, a failure in A DOES stop B.
//   * `... 2>/dev/null || true` -> best-effort: log the NSError via PXLog and
//     continue. This is NOT silently ignored — every best-effort failure is
//     logged with errno so anti-forensic visibility is preserved.
//   * No trailing `|| true` -> fail-fast: the error is surfaced to the caller.
//
// Path scope decides in-process vs root:
//   * sandbox / Containers / tmp        -> in-process PXFileOps.
//   * /var/root, SpringBoard, system .. -> PXRootHelper.
//   * EPERM/EACCES in-process           -> retry via PXRootHelper.
// Four known uid-0 paths are marked forceRoot to skip the in-process attempt.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const PXCommandRouterErrorDomain;

typedef NS_ENUM(NSInteger, PXCommandRouterError) {
    PXCommandRouterErrorInvalidArgs   = 1, // nil/empty command
    PXCommandRouterErrorParseFailed   = 2, // could not tokenize/argv-split
    PXCommandRouterErrorUnsupported   = 3, // argv[0] has no handler
    PXCommandRouterErrorExecFailed    = 4, // a primitive returned an error
};

@interface PXCommandRouter : NSObject

+ (instancetype)sharedRouter;

// Executes a (possibly composite) shell command string by translating it into
// in-process primitives. Returns YES if every non-best-effort segment
// succeeded. Best-effort segments (`|| true`) never cause a NO return but are
// logged on failure. On a fail-fast segment error, `error` is populated and
// execution stops at that segment.
- (BOOL)executeShellCommand:(NSString *)command
                      error:(NSError * _Nullable * _Nullable)error;

// Lower-level: execute a single already-split argv (no composite handling).
// Exposed for unit testing the handler table.
- (BOOL)executeArgv:(NSArray<NSString *> *)argv
         bestEffort:(BOOL)bestEffort
              error:(NSError * _Nullable * _Nullable)error;

// Tokenize a composite shell string into segments with their chaining operator.
// Exposed for unit testing the parser. Each element is a dictionary:
//   @{ @"argv": NSArray<NSString*>, @"bestEffort": @(BOOL), @"stopOnError": @(BOOL) }
+ (NSArray<NSDictionary *> *)parseCompositeCommand:(NSString *)command;

// Split a single command string into argv, honoring '...' and "..." quoting.
// Exposed for unit testing.
+ (nullable NSArray<NSString *> *)splitArguments:(NSString *)command;

@end

NS_ASSUME_NONNULL_END
