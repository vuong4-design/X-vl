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

@end

NS_ASSUME_NONNULL_END
