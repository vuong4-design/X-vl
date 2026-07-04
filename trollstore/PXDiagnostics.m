// PXDiagnostics.m — TrollStore debug logging and self-tests.

#import "PXDiagnostics.h"
#import "PXRootHelper.h"
#import "PXShellRouter.h"

#import <UIKit/UIKit.h>
#import <sys/stat.h>

static NSString *PXDiagDirectory(void) {
    return @"/var/mobile/Library/ProjectXTroll";
}

static NSString *PXDiagString(id obj) {
    if (!obj) return @"(nil)";
    if ([obj isKindOfClass:[NSString class]]) return obj;
    return [obj description];
}

@implementation PXDiagnostics

+ (NSString *)logPath {
    return [PXDiagDirectory() stringByAppendingPathComponent:@"diagnostic.log"];
}

+ (void)ensureDirectory {
    NSError *err = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:PXDiagDirectory()
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:&err];
}

+ (void)clearLog {
    [self ensureDirectory];
    [[@"" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:[self logPath] atomically:YES];
}

+ (void)log:(NSString *)format, ... {
    if (!format.length) return;
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    [self ensureDirectory];
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [fmt stringFromDate:[NSDate date]], message ?: @""];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];

    NSString *path = [self logPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [data writeToFile:path atomically:YES];
        return;
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    [fh seekToEndOfFile];
    [fh writeData:data];
    [fh closeFile];
}

+ (NSString *)readLogTailWithMaxBytes:(NSUInteger)maxBytes {
    NSData *data = [NSData dataWithContentsOfFile:[self logPath]];
    if (!data.length) return @"(diagnostic log is empty)";
    if (maxBytes > 0 && data.length > maxBytes) {
        data = [data subdataWithRange:NSMakeRange(data.length - maxBytes, maxBytes)];
    }
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return s ?: @"(failed to decode diagnostic log)";
}

+ (NSDictionary<NSString *,id> *)environmentSnapshot {
    [self log:@"[env] starting environment snapshot"];
    NSBundle *bundle = [NSBundle mainBundle];
    NSProcessInfo *pi = [NSProcessInfo processInfo];
    NSString *tmpDir = @"/var/tmp/weaponx";
    NSString *tmpFile = [tmpDir stringByAppendingPathComponent:@"diagnostic_write_test.txt"];
    NSString *libFile = [PXDiagDirectory() stringByAppendingPathComponent:@"diagnostic_write_test.txt"];
    NSError *tmpErr = nil;
    NSError *libErr = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    [self ensureDirectory];
    BOOL tmpWrite = [@"ok" writeToFile:tmpFile atomically:YES encoding:NSUTF8StringEncoding error:&tmpErr];
    BOOL libWrite = [@"ok" writeToFile:libFile atomically:YES encoding:NSUTF8StringEncoding error:&libErr];
    NSDictionary *info = @{
        @"bundleIdentifier": bundle.bundleIdentifier ?: @"",
        @"bundlePath": bundle.bundlePath ?: @"",
        @"executable": bundle.infoDictionary[@"CFBundleExecutable"] ?: @"",
        @"home": NSHomeDirectory() ?: @"",
        @"osVersion": pi.operatingSystemVersionString ?: @"",
        @"logPath": [self logPath],
        @"writeVarTmp": tmpWrite ? @"YES" : PXDiagString(tmpErr.localizedDescription),
        @"writeProjectXTrollLibrary": libWrite ? @"YES" : PXDiagString(libErr.localizedDescription),
    };
    [self log:@"[env] %@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)rootHelperSelfTest {
    [self log:@"[root] starting root helper self-test"];
    PXRootHelper *helper = [PXRootHelper sharedHelper];
    NSString *path = [helper helperBinaryPath];
    BOOL exists = path.length && [[NSFileManager defaultManager] fileExistsAtPath:path];
    BOOL executable = path.length && [[NSFileManager defaultManager] isExecutableFileAtPath:path];
    BOOL available = [helper isRootSpawnAvailable];
    int exitCode = -999;
    NSString *stdOut = nil;
    NSString *stdErr = nil;
    NSError *err = nil;
    BOOL ok = [helper runAsRoot:@[@"rm", @"/var/tmp/weaponx/roothelper_nonexistent"]
                          exitCode:&exitCode
                            stdOut:&stdOut
                            stdErr:&stdErr
                             error:&err];
    NSDictionary *info = @{
        @"helperPath": path ?: @"(nil)",
        @"exists": exists ? @"YES" : @"NO",
        @"executable": executable ? @"YES" : @"NO",
        @"available": available ? @"YES" : @"NO",
        @"runOK": ok ? @"YES" : @"NO",
        @"exitCode": @(exitCode),
        @"stdout": stdOut ?: @"",
        @"stderr": stdErr ?: @"",
        @"error": err.localizedDescription ?: @"",
    };
    [self log:@"[root] %@", info];
    return info;
}

+ (NSDictionary<NSString *,id> *)routerFixtureSelfTest {
    [self log:@"[router-test] starting router fixture self-test"];
    NSArray<NSString *> *commands = @[
        @"mkdir -p '/var/tmp/weaponx/router-test/a'",
        @"touch '/var/tmp/weaponx/router-test/a/file.txt'",
        @"chmod -R 0777 '/var/tmp/weaponx/router-test'",
        @"chflags -R nouchg,noschg,nohidden '/var/tmp/weaponx/router-test'",
        @"rm -rf '/var/tmp/weaponx/router-test/a/file.txt'",
        @"find '/var/tmp/weaponx/router-test' -depth -type d -empty -delete",
        @"sync"
    ];
    NSMutableArray *results = [NSMutableArray array];
    for (NSString *cmd in commands) {
        NSError *err = nil;
        BOOL ok = [[PXShellRouter sharedRouter] runShellCommand:cmd error:&err];
        NSDictionary *row = @{
            @"command": cmd,
            @"ok": ok ? @"YES" : @"NO",
            @"error": err.localizedDescription ?: @"",
        };
        [results addObject:row];
        [self log:@"[router-test] %@", row];
    }
    return @{@"results": results};
}

@end
