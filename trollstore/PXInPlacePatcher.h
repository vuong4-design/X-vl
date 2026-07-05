// PXInPlacePatcher.h - safe in-place injection preparation and restore.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const PXInPlacePatcherErrorDomain;

@interface PXInPlacePatcher : NSObject

+ (NSDictionary<NSString *, id> *)prepareBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)patchPreparedCopyBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)restoreBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)statusForBundleID:(NSString *)bundleID;

@end

NS_ASSUME_NONNULL_END
