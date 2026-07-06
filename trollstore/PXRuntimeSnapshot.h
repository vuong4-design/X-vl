// PXRuntimeSnapshot.h - runtime config snapshot for injected ProjectXInject.dylib.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const PXRuntimeSnapshotErrorDomain;

@interface PXRuntimeSnapshot : NSObject

+ (NSString *)baseDirectory;
+ (NSString *)snapshotPathForBundleID:(NSString *)bundleID;
+ (NSString *)loadedMarkerPathForBundleID:(NSString *)bundleID;
+ (NSString *)bundledInjectDylibPath;

+ (nullable NSDictionary<NSString *, id> *)exportSnapshotForBundleID:(NSString *)bundleID
                                                               error:(NSError **)error;
+ (nullable NSDictionary<NSString *, id> *)exportSnapshotForBundleID:(NSString *)bundleID
                                                     enableObjCHooks:(BOOL)enableObjCHooks
                                                               error:(NSError **)error;
+ (NSDictionary<NSString *, id> *)statusForBundleID:(NSString *)bundleID;

@end

NS_ASSUME_NONNULL_END
