// PXDiagnostics.h — TrollStore debug logging and self-tests.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PXDiagnostics : NSObject

+ (NSString *)logPath;
+ (void)clearLog;
+ (void)log:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
+ (NSString *)readLogTailWithMaxBytes:(NSUInteger)maxBytes;

+ (NSDictionary<NSString *, id> *)environmentSnapshot;
+ (NSDictionary<NSString *, id> *)entitlementsSnapshot;
+ (NSDictionary<NSString *, id> *)rootHelperSelfTest;
+ (NSDictionary<NSString *, id> *)routerFixtureSelfTest;
+ (NSDictionary<NSString *, id> *)injectionSnapshotForBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)enableObjCHooksSnapshotForBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)injectionMarkerStatusForBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)dyldLaunchBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)prepareInPlaceBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)scanFrameworkCarriersBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)patchFrameworkCarrierBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)patchPreparedInPlaceCopyBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)exportPatchedTIPABundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)installPatchedInPlaceCopyBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)installPatchedInPlaceCopyWithoutLaunchBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)restoreInPlaceBundleID:(NSString *)bundleID;
+ (NSDictionary<NSString *, id> *)inPlaceStatusBundleID:(NSString *)bundleID;

@end

NS_ASSUME_NONNULL_END
