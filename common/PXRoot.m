#import "PXRoot.h"
#import <mach-o/dyld.h>
#import <dlfcn.h>

// Roothide's jbroot()/rootfs() are provided by libroothide. We resolve the
// symbol dynamically with dlsym so there is zero link-time dependency on
// libroothide: the same binary links and runs identically on rootful,
// rootless, and roothide systems. Under an SDK build the symbol is loaded;
// otherwise dlsym returns NULL and we fall through to path-based detection.
typedef char *(*px_jbroot_fn)(const char *);

static NSString *gJBRoot = nil;

// Derive the jbroot from the running Mach-O image path. Under roothide an
// injected dylib lives at "<jbroot>/usr/lib/..." or "<jbroot>/Library/...";
// walking up from a known marker recovers the randomized root.
static NSString *PXJBRootFromImagePaths(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *image = [NSString stringWithUTF8String:raw];

        // Roothide randomized root marker: /var/.jbroot-XXXXXXXX/
        NSRange marker = [image rangeOfString:@"/.jbroot-"];
        if (marker.location != NSNotFound) {
            // Cut after the jbroot component (……/.jbroot-XXXXXXXX).
            NSRange tail = [image rangeOfString:@"/"
                                        options:0
                                          range:NSMakeRange(NSMaxRange(marker),
                                                            image.length - NSMaxRange(marker))];
            NSUInteger end = (tail.location != NSNotFound) ? tail.location : image.length;
            return [image substringToIndex:end];
        }
    }
    return nil;
}

// Glob /var for a .jbroot-* directory (used by standalone binaries like the
// daemon, whose own image path may sit outside the jbroot).
static NSString *PXJBRootFromVarGlob(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *entries = [fm contentsOfDirectoryAtPath:@"/var" error:nil];
    for (NSString *entry in entries) {
        if ([entry hasPrefix:@".jbroot-"]) {
            return [@"/var" stringByAppendingPathComponent:entry];
        }
    }
    return nil;
}

NSString *PXJBRoot(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // 1) Roothide official API when present (SDK build). Resolved via
        //    dlsym so there is no link-time dependency on libroothide.
        px_jbroot_fn jbroot_fn = (px_jbroot_fn)dlsym(RTLD_DEFAULT, "jbroot");
        if (jbroot_fn != NULL) {
            char *resolved = jbroot_fn("/");
            if (resolved) {
                NSString *r = [NSString stringWithUTF8String:resolved];
                // NOTE: roothide's jbroot() return-value ownership is not yet
                // verified against the SDK headers. We intentionally do NOT
                // free() here: a one-time few-byte leak (guarded by
                // dispatch_once) is harmless, whereas free()ing non-heap
                // storage would crash at every startup. Revisit once the
                // contract is confirmed when wiring the SDK in CI.
                // jbroot("/") yields "<root>/"; trim the trailing slash.
                if (r.length > 1 && [r hasSuffix:@"/"]) {
                    r = [r substringToIndex:r.length - 1];
                }
                if (r.length > 0 && ![r isEqualToString:@"/"]) {
                    gJBRoot = r;
                    return;
                }
            }
        }

        // 2) Explicit environment override.
        const char *env = getenv("JBROOT");
        if (env && strlen(env) > 0) {
            gJBRoot = [NSString stringWithUTF8String:env];
            return;
        }

        // 3) Roothide randomized root via running image path.
        NSString *fromImage = PXJBRootFromImagePaths();
        if (fromImage) { gJBRoot = fromImage; return; }

        // 4) Roothide randomized root via /var glob (daemon case).
        NSString *fromGlob = PXJBRootFromVarGlob();
        if (fromGlob) { gJBRoot = fromGlob; return; }

        // 5) Rootless fixed prefix.
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
            gJBRoot = @"/var/jb";
            return;
        }

        // 6) Rootful fallback.
        gJBRoot = @"";
    });
    return gJBRoot;
}

NSString *PXJBPath(NSString *relativePath) {
    if (relativePath.length == 0) return PXJBRoot();
    NSString *root = PXJBRoot();
    if (root.length == 0) return relativePath; // rootful: unchanged
    if (![relativePath hasPrefix:@"/"]) {
        relativePath = [@"/" stringByAppendingString:relativePath];
    }
    return [root stringByAppendingString:relativePath];
}

NSString *PXRootPath(NSString *absolutePath) {
    if (absolutePath.length == 0) return absolutePath;
    NSString *root = PXJBRoot();
    if (root.length == 0) return absolutePath; // rootful: unchanged

    // Already rooted — avoid double-prefixing.
    if ([absolutePath hasPrefix:root]) return absolutePath;

    // Only relocate the install/runtime trees that move under the jbroot.
    static NSArray<NSString *> *relocatable = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        relocatable = @[ @"/Library", @"/Applications", @"/usr", @"/var/mobile" ];
    });
    for (NSString *prefix in relocatable) {
        if ([absolutePath hasPrefix:prefix]) {
            return [root stringByAppendingString:absolutePath];
        }
    }
    return absolutePath;
}
