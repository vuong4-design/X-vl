// PXProcessKiller.h
// Small helper to kill processes without spawning a shell.

#import <Foundation/Foundation.h>
#include <signal.h>

// Best-effort kill using killall by exact process name.
// Returns YES if the command executed (not whether a process was actually killed).
BOOL PXKillallByName(NSString *processName, int signalNumber);

// Convenience helpers
BOOL PXKillallTermThenKill(NSString *processName, NSTimeInterval graceSeconds);
BOOL PXKillallTermThenKillMany(NSArray<NSString *> *processNames, NSTimeInterval graceSeconds);

// Returns YES if at least one process with the exact name is currently running.
BOOL PXProcessIsRunning(NSString *processName);

// Polls until none of the named processes are running, or until the timeout
// elapses. Returns YES if all processes are gone, NO on timeout.
BOOL PXWaitForProcessesToExit(NSArray<NSString *> *processNames, NSTimeInterval timeoutSeconds);
