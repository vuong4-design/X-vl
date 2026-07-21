// PXInPlacePatcher.h - safe in-place injection preparation and restore.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const PXInPlacePatcherErrorDomain;

@interface PXInPlacePatcher : NSObject

+ (NSDictionary<NSString *, id> *)prepareBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)scanFrameworkCarriersBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)deepScanBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)patchPlanForBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)patchFrameworkCarrierBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)patchFrameworkCarrierBundleID:(NSString *)bundleID candidateIndex:(NSUInteger)candidateIndex;
+ (NSDictionary<NSString *, id> *)installWeakLoadCarrierBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)patchPreparedCopyBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)exportPatchedTIPABundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)installPatchedCopyBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)installPatchedCopyWithoutLaunchBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)restoreBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)statusForBundleID:(NSString *)bundleID;

@end

NS_ASSUME_NONNULL_END
