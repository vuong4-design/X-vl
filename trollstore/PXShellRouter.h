// PXShellRouter.h — Translates legacy /bin/sh command strings into in-process
// PXFileOps calls (and PXRootHelper for system-scoped paths needing uid 0).
//
// The router exists so the >100 historical runCommandWithPrivileges: call
// sites in AppDataCleaner.m / AppDataBackupManager.m do not need to be touched
// one-by-one. They keep passing shell strings; the router parses, dispatches,
// and reports errors faithfully. `2>/dev/null || true` suffixes become
// best-effort + logged warning, NOT silent skip.
//
// PR-R1 scope: tokenizer, argv splitter, composite handling, handlers for
//   rm / mkdir / chmod / chflags / find (covers ~70% of call sites).
// PR-R2 / PR-R3 add the remaining handlers (mv, cp, touch, chown, launchctl,
// security, plutil, grep, sqlite3, sync) without touching the dispatch core.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const PXShellRouterErrorDomain;

typedef NS_ENUM(NSInteger, PXShellRouterError) {
    PXShellRouterErrorInvalidArgs        = 1,
    PXShellRouterErrorParseFailed        = 2,
    PXShellRouterErrorUnsupportedCommand = 3, // argv[0] not in handler table
    PXShellRouterErrorUnsupportedOption  = 4, // known command, unknown flag combo
    PXShellRouterErrorHandlerFailed      = 5, // handler ran and returned NSError
};

@interface PXShellRouter : NSObject

+ (instancetype)sharedRouter;

// Execute a legacy shell command string. Returns YES if every non-best-effort
// sub-command completed without a fatal error. Best-effort segments (those
// originally trailing `2>/dev/null || true`) never cause a NO return; their
// failures are logged via NSLog and surfaced through `lastError`.
- (BOOL)runShellCommand:(NSString *)command
                  error:(NSError * _Nullable * _Nullable)outError;

// Convenience matching the legacy void-returning signature.
- (void)runShellCommandIgnoringError:(NSString *)command;

// Diagnostic: the most recent error captured (incl. best-effort).
@property (atomic, copy, readonly, nullable) NSError *lastError;

// Test hooks.
+ (NSArray<NSDictionary<NSString *, id> *> *)parseCompositeCommand:(NSString *)command;
+ (nullable NSArray<NSString *> *)tokenizeArgv:(NSString *)command;

@end

NS_ASSUME_NONNULL_END
