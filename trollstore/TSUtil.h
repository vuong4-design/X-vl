// TSUtil.h — Minimal subset used by ProjectX TrollStore migration.
//
// Original TSUtil.{h,m} from opa334/TrollStore contains app-management,
// entitlement dumping, persistence-helper, exploit detection, etc. We only
// need spawnRoot for PXRootHelper. Everything else has been stripped to
// remove dependencies on CoreServices private headers, libroot, Security,
// MobileContainerManager, UIKit, and CoreTelephony.
//
// If the project later needs other TSUtil functionality, restore the relevant
// pieces from the upstream repo and add the corresponding framework links.

#import <Foundation/Foundation.h>

// Spawns `path` as uid 0 using the persona-mgmt entitlement on iOS <= 17.5.
// `args` is argv WITHOUT path (the function prepends it). Pass stdOut/stdErr
// as NULL to ignore. Returns the child's exit status (or a negative error).
//
// Implementation lives in TSUtil.m. PXRootHelper wraps this with availability
// detection and NSError reporting.
extern int spawnRoot(NSString *path, NSArray *args, NSString **stdOut, NSString **stdErr);
