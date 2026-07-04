#import "AppEntitlementsReader.h"

#import "AppDataCleaner.h"
#ifdef PROJECTX_TROLLSTORE
#import "PXEntitlements.h"
#else
#import "CommandRunner.h"
#endif

#import <objc/message.h>

static NSString * const PXEntitlementsErrorDomain = @"com.hydra.projectx.entitlements";

@implementation AppEntitlementsReader

#ifndef PROJECTX_TROLLSTORE
static NSString *PXShellQuote(NSString *s) {
    NSString *escaped = [s stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"];
    return [NSString stringWithFormat:@"'%@'", escaped];
}
#endif

- (NSDictionary *)fullEntitlementsForBundleID:(NSString *)bundleID
                                        error:(NSError **)error {
    NSString *binaryPath = [self mainExecutablePathForBundleID:bundleID error:error];
    if (!binaryPath) {
        return nil;
    }

#ifdef PROJECTX_TROLLSTORE
    NSError *entErr = nil;
    NSDictionary *ents = [PXEntitlements entitlementsForBinaryAtPath:binaryPath error:&entErr];
    if (!ents) {
        if (error) {
            *error = entErr ?: [NSError errorWithDomain:PXEntitlementsErrorDomain
                                                   code:2
                                               userInfo:@{NSLocalizedDescriptionKey: @"Failed to read entitlements"}];
        }
        return nil;
    }

    return ents;
#else
    CommandRunner *runner = [CommandRunner shared];
    NSString *ldidPath = [runner firstExistingPath:@[
        @"/usr/bin/ldid",
        @"/var/jb/usr/bin/ldid",
        @"/private/preboot/jb/usr/bin/ldid",
        @"/bin/ldid"
    ]];

    if (!ldidPath) {
        if (error) {
            *error = [NSError errorWithDomain:PXEntitlementsErrorDomain
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"ldid not found"}];
        }
        return nil;
    }

    NSString *cmd = [NSString stringWithFormat:@"%@ -e %@", PXShellQuote(ldidPath), PXShellQuote(binaryPath)];
    CommandResult *res = [runner runAndCapture:cmd];
    if (res.exitCode != 0) {
        if (error) {
            NSString *msg = res.stderrString.length ? res.stderrString : @"ldid failed";
            *error = [NSError errorWithDomain:PXEntitlementsErrorDomain
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: msg}];
        }
        return nil;
    }

    NSData *plistData = [res.stdoutString dataUsingEncoding:NSUTF8StringEncoding];
    if (!plistData.length) {
        if (error) {
            *error = [NSError errorWithDomain:PXEntitlementsErrorDomain
                                         code:3
                                     userInfo:@{NSLocalizedDescriptionKey: @"Empty entitlements output"}];
        }
        return nil;
    }

    NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0;
    NSError *plistError = nil;
    id obj = [NSPropertyListSerialization propertyListWithData:plistData
                                                       options:NSPropertyListImmutable
                                                        format:&format
                                                         error:&plistError];
    if (!obj || ![obj isKindOfClass:[NSDictionary class]]) {
        if (error) {
            *error = plistError ?: [NSError errorWithDomain:PXEntitlementsErrorDomain
                                                       code:4
                                                   userInfo:@{NSLocalizedDescriptionKey: @"Failed to parse entitlements plist"}];
        }
        return nil;
    }

    return (NSDictionary *)obj;
#endif
}

- (NSArray<NSString *> *)applicationGroupsForBundleID:(NSString *)bundleID
                                                error:(NSError **)error {
    NSDictionary *entitlements = [self fullEntitlementsForBundleID:bundleID error:error];
    if (!entitlements) {
        return @[];
    }

    id groups = entitlements[@"com.apple.security.application-groups"];
    if (![groups isKindOfClass:[NSArray class]]) {
        return @[];
    }

    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (id g in (NSArray *)groups) {
        if ([g isKindOfClass:[NSString class]] && [(NSString *)g length] > 0) {
            [out addObject:g];
        }
    }
    return out;
}

- (NSArray<NSString *> *)keychainAccessGroupsForBundleID:(NSString *)bundleID
                                                    error:(NSError **)error {
    NSDictionary *entitlements = [self fullEntitlementsForBundleID:bundleID error:error];
    if (!entitlements) {
        return @[];
    }

    NSMutableOrderedSet<NSString *> *out = [NSMutableOrderedSet orderedSet];

    // Explicit keychain-access-groups
    id groups = entitlements[@"keychain-access-groups"];
    if ([groups isKindOfClass:[NSArray class]]) {
        for (id g in (NSArray *)groups) {
            if ([g isKindOfClass:[NSString class]] && [(NSString *)g length] > 0) {
                [out addObject:(NSString *)g];
            }
        }
    }

    // Also include the app's default keychain group (application-identifier) if present.
    // Many apps store keychain items under this group even when it is not listed in keychain-access-groups.
    id appIdent = entitlements[@"application-identifier"];
    if ([appIdent isKindOfClass:[NSString class]] && [(NSString *)appIdent length] > 0) {
        [out addObject:(NSString *)appIdent];
    }

    return out.array;
}

- (NSString *)mainExecutablePathForBundleID:(NSString *)bundleID
                                     error:(NSError **)error {
    // Preferred: resolve via LSApplicationProxy (more reliable than filesystem UUID scans).
    Class LSApplicationProxyClass = NSClassFromString(@"LSApplicationProxy");
    SEL proxySel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    if (LSApplicationProxyClass && [LSApplicationProxyClass respondsToSelector:proxySel]) {
        @try {
            id proxy = ((id (*)(id, SEL, id))objc_msgSend)(LSApplicationProxyClass, proxySel, bundleID);
            if (proxy) {
                NSString *bundlePath = nil;

                id bundleURL = nil;
                @try { bundleURL = [proxy valueForKey:@"bundleURL"]; } @catch (__unused NSException *e) {}
                if ([bundleURL isKindOfClass:[NSURL class]]) {
                    bundlePath = [(NSURL *)bundleURL path];
                } else if ([bundleURL isKindOfClass:[NSString class]]) {
                    bundlePath = (NSString *)bundleURL;
                }

                if (!bundlePath.length) {
                    id bundleContainerURL = nil;
                    @try { bundleContainerURL = [proxy valueForKey:@"bundleContainerURL"]; } @catch (__unused NSException *e) {}
                    if ([bundleContainerURL isKindOfClass:[NSURL class]]) {
                        bundlePath = [(NSURL *)bundleContainerURL path];
                    } else if ([bundleContainerURL isKindOfClass:[NSString class]]) {
                        bundlePath = (NSString *)bundleContainerURL;
                    }
                }

                if (bundlePath.length) {
                    // If we got the container directory, find the .app inside.
                    NSFileManager *fm = [NSFileManager defaultManager];
                    BOOL isDir = NO;
                    if ([fm fileExistsAtPath:bundlePath isDirectory:&isDir] && isDir) {
                        NSString *appPath = bundlePath;
                        if (![appPath hasSuffix:@".app"]) {
                            NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:bundlePath error:nil];
                            for (NSString *item in items) {
                                if ([item hasSuffix:@".app"]) {
                                    appPath = [bundlePath stringByAppendingPathComponent:item];
                                    break;
                                }
                            }
                        }

                        NSString *exeName = nil;
                        @try { exeName = [proxy valueForKey:@"bundleExecutable"]; } @catch (__unused NSException *e) {}
                        if (!exeName.length) {
                            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[appPath stringByAppendingPathComponent:@"Info.plist"]];
                            if ([info isKindOfClass:[NSDictionary class]]) {
                                exeName = info[@"CFBundleExecutable"]; 
                            }
                        }

                        if (exeName.length) {
                            NSString *binaryPath = [appPath stringByAppendingPathComponent:exeName];
                            if ([fm fileExistsAtPath:binaryPath]) {
                                return binaryPath;
                            }
                        }
                    }
                }
            }
        } @catch (__unused NSException *e) {
            // Fall back to filesystem method below
        }
    }

    AppDataCleaner *cleaner = [AppDataCleaner sharedManager];
    NSString *bundleUUID = [cleaner findBundleContainerUUIDForBundleID:bundleID];
    if (!bundleUUID.length) {
        if (error) {
            *error = [NSError errorWithDomain:PXEntitlementsErrorDomain
                                         code:10
                                     userInfo:@{NSLocalizedDescriptionKey: @"Bundle container UUID not found"}];
        }
        return nil;
    }

    NSArray<NSString *> *bundleBaseDirs = @[
        @"/var/containers/Bundle/Application",
        @"/var/mobile/Containers/Bundle/Application",
        @"/containers/Bundle/Application"
    ];

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *base in bundleBaseDirs) {
        NSString *uuidPath = [base stringByAppendingPathComponent:bundleUUID];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:uuidPath isDirectory:&isDir] || !isDir) {
            continue;
        }

        NSError *listErr = nil;
        NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:uuidPath error:&listErr];
        if (!items.count) {
            continue;
        }

        for (NSString *item in items) {
            if (![item hasSuffix:@".app"]) {
                continue;
            }
            NSString *appPath = [uuidPath stringByAppendingPathComponent:item];
            NSString *infoPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
            if (![info isKindOfClass:[NSDictionary class]]) {
                continue;
            }
            NSString *foundBundleID = info[@"CFBundleIdentifier"];
            if (![foundBundleID isKindOfClass:[NSString class]] || ![foundBundleID isEqualToString:bundleID]) {
                continue;
            }
            NSString *exe = info[@"CFBundleExecutable"];
            if (![exe isKindOfClass:[NSString class]] || !exe.length) {
                if (error) {
                    *error = [NSError errorWithDomain:PXEntitlementsErrorDomain
                                                 code:11
                                             userInfo:@{NSLocalizedDescriptionKey: @"CFBundleExecutable missing"}];
                }
                return nil;
            }
            NSString *binaryPath = [appPath stringByAppendingPathComponent:exe];
            if ([fm fileExistsAtPath:binaryPath]) {
                return binaryPath;
            }
        }
    }

    if (error) {
        *error = [NSError errorWithDomain:PXEntitlementsErrorDomain
                                     code:12
                                 userInfo:@{NSLocalizedDescriptionKey: @"Main executable not found in bundle container"}];
    }
    return nil;
}

@end
