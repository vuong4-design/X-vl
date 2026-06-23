// PXProcessKiller.m

#import "PXProcessKiller.h"

#import <spawn.h>
#import <sys/wait.h>
#import <signal.h>
#import <dispatch/dispatch.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/param.h>

extern char **environ;

static NSString *PXKillallPath(void) {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSArray<NSString *> *candidates = @[
            @"/usr/bin/killall",
            @"/bin/killall",
            @"/var/jb/usr/bin/killall",
            @"/private/preboot/jb/usr/bin/killall",
            @"/private/var/jb/usr/bin/killall"
        ];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *p in candidates) {
            if ([fm fileExistsAtPath:p]) {
                cached = p;
                break;
            }
        }
    });
    return cached;
}

static int PXSpawnAndWaitSilenced(NSString *binPath, NSArray<NSString *> *args, int timeoutSec) {
    if (!binPath.length || args.count == 0) return -1;
    if (timeoutSec <= 0) timeoutSec = 10;

    // Build argv
    NSUInteger argc = args.count + 2;
    char **argv = (char **)calloc(argc, sizeof(char *));
    if (!argv) return -1;
    argv[0] = (char *)[binPath UTF8String];
    for (NSUInteger i = 0; i < args.count; i++) {
        argv[i + 1] = (char *)[[args objectAtIndex:i] UTF8String];
    }
    argv[argc - 1] = NULL;

    // Silence stdout/stderr
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    int devNull = open("/dev/null", O_WRONLY);
    if (devNull >= 0) {
        posix_spawn_file_actions_adddup2(&actions, devNull, STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, devNull, STDERR_FILENO);
        posix_spawn_file_actions_addclose(&actions, devNull);
    }

    pid_t pid = 0;
    int spawnStatus = posix_spawn(&pid, [binPath UTF8String], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (devNull >= 0) close(devNull);
    free(argv);

    if (spawnStatus != 0 || pid <= 0) {
        return spawnStatus != 0 ? spawnStatus : -1;
    }

    int status = 0;
    int iterations = 0;
    int maxIterations = timeoutSec * 10; // 100ms
    while (iterations < maxIterations) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return -1;
        }
        if (r == -1) {
            return -1;
        }
        usleep(100000);
        iterations++;
    }

    // timeout
    kill(pid, SIGKILL);
    (void)waitpid(pid, &status, 0);
    return -1;
}

BOOL PXKillallByName(NSString *processName, int signalNumber) {
    if (![processName isKindOfClass:[NSString class]] || processName.length == 0) return NO;
    NSString *bin = PXKillallPath();
    if (!bin.length) return NO;

    NSString *sigArg = nil;
    if (signalNumber == SIGKILL || signalNumber == 9) {
        sigArg = @"-9";
    } else if (signalNumber == SIGTERM || signalNumber == 15) {
        sigArg = @"-TERM";
    } else if (signalNumber == SIGHUP || signalNumber == 1) {
        sigArg = @"-HUP";
    } else if (signalNumber == SIGINT || signalNumber == 2) {
        sigArg = @"-INT";
    } else {
        // best-effort numeric
        sigArg = [NSString stringWithFormat:@"-%d", signalNumber];
    }

    // killall <sig> <name>
    (void)PXSpawnAndWaitSilenced(bin, @[sigArg, processName], 10);
    return YES;
}

BOOL PXKillallTermThenKill(NSString *processName, NSTimeInterval graceSeconds) {
    BOOL ok1 = PXKillallByName(processName, SIGTERM);
    if (graceSeconds > 0) {
        [NSThread sleepForTimeInterval:graceSeconds];
    }
    BOOL ok2 = PXKillallByName(processName, SIGKILL);
    return ok1 || ok2;
}

BOOL PXKillallTermThenKillMany(NSArray<NSString *> *processNames, NSTimeInterval graceSeconds) {
    if (![processNames isKindOfClass:[NSArray class]] || processNames.count == 0) return NO;
    BOOL any = NO;
    for (id n in processNames) {
        if (![n isKindOfClass:[NSString class]] || ![(NSString *)n length]) continue;
        any |= PXKillallByName((NSString *)n, SIGTERM);
    }
    if (graceSeconds > 0) {
        [NSThread sleepForTimeInterval:graceSeconds];
    }
    for (id n in processNames) {
        if (![n isKindOfClass:[NSString class]] || ![(NSString *)n length]) continue;
        any |= PXKillallByName((NSString *)n, SIGKILL);
    }
    return any;
}

BOOL PXProcessIsRunning(NSString *processName) {
    if (![processName isKindOfClass:[NSString class]] || processName.length == 0) return NO;

    const char *target = [processName UTF8String];
    if (!target) return NO;

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };

    // Query required buffer size first. The process table can change between
    // the sizing call and the fetch, so retry a few times on ENOMEM.
    for (int attempt = 0; attempt < 4; attempt++) {
        size_t size = 0;
        if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) {
            return NO;
        }
        if (size == 0) {
            return NO;
        }

        // Add headroom in case the table grew since sizing.
        size_t allocSize = size + (size / 8) + sizeof(struct kinfo_proc);
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(allocSize);
        if (!procs) {
            return NO;
        }

        size_t fetched = allocSize;
        int rc = sysctl(mib, 4, procs, &fetched, NULL, 0);
        if (rc != 0) {
            free(procs);
            if (errno == ENOMEM) {
                // Table grew; retry with a fresh size.
                continue;
            }
            return NO;
        }

        NSUInteger count = fetched / sizeof(struct kinfo_proc);
        BOOL found = NO;
        for (NSUInteger i = 0; i < count; i++) {
            const char *comm = procs[i].kp_proc.p_comm;
            // p_comm is truncated to MAXCOMLEN (16) chars including NUL, so
            // compare against the same truncation of the target name.
            if (strncmp(comm, target, MAXCOMLEN) == 0) {
                found = YES;
                break;
            }
        }
        free(procs);
        return found;
    }

    return NO;
}

BOOL PXWaitForProcessesToExit(NSArray<NSString *> *processNames, NSTimeInterval timeoutSeconds) {
    if (![processNames isKindOfClass:[NSArray class]] || processNames.count == 0) return YES;
    if (timeoutSeconds <= 0) timeoutSeconds = 0.5;

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeoutSeconds];
    for (;;) {
        BOOL anyAlive = NO;
        for (id n in processNames) {
            if (![n isKindOfClass:[NSString class]] || ![(NSString *)n length]) continue;
            if (PXProcessIsRunning((NSString *)n)) {
                anyAlive = YES;
                break;
            }
        }
        if (!anyAlive) {
            return YES;
        }
        if ([[NSDate date] compare:deadline] != NSOrderedAscending) {
            return NO;
        }
        usleep(50000); // 50ms between polls
    }
}
