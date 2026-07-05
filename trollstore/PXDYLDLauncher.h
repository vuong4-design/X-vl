// PXDYLDLauncher.h - experimental DYLD_INSERT_LIBRARIES launcher backend.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const PXDYLDLauncherErrorDomain;

@interface PXDYLDLauncher : NSObject

+ (NSDictionary<NSString *, id> *)launchBundleID:(NSString *)bundleID timeout:(NSTimeInterval)timeout;

@end

NS_ASSUME_NONNULL_END
