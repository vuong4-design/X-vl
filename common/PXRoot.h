#ifndef PXROOT_H
#define PXROOT_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * PXRoot - Centralized jailbreak-root (jbroot) path resolver.
 *
 * Supports three environments from a single codebase:
 *   - Rootful   : jbroot is "" (paths are absolute as-is)
 *   - Rootless  : jbroot is "/var/jb"
 *   - Roothide  : jbroot is a per-device randomized "/var/.jbroot-XXXXXXXX"
 *
 * Resolution is performed once and cached. All install/runtime paths in
 * Tier 1 (daemon/guardian) and beyond should route through these helpers
 * instead of hardcoding absolute literals.
 */

/// Returns the jbroot prefix for the current environment.
/// Rootful -> @"" ; Rootless -> @"/var/jb" ; Roothide -> @"/var/.jbroot-XXXXXXXX".
/// The result is cached after the first call.
extern NSString *PXJBRoot(void);

/// Joins a jbroot-relative path (e.g. @"/Library/WeaponX") onto the resolved
/// jbroot. Pass a leading-slash path; under rootful this returns it unchanged.
extern NSString *PXJBPath(NSString *relativePath);

/// Translates an absolute system path into its jbroot-relative location.
/// Paths under /Library, /Applications, /usr, and /var/mobile are relocated
/// beneath the jbroot when one is present. Other paths are returned unchanged.
extern NSString *PXRootPath(NSString *absolutePath);

NS_ASSUME_NONNULL_END

#endif /* PXROOT_H */
