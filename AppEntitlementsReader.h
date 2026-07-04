#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AppEntitlementsReader : NSObject

// Returns application group identifiers from the target app's entitlements.
- (NSArray<NSString *> *)applicationGroupsForBundleID:(NSString *)bundleID
                                                error:(NSError **)error;

// Returns keychain access groups from the target app's entitlements.
- (NSArray<NSString *> *)keychainAccessGroupsForBundleID:(NSString *)bundleID
                                                   error:(NSError **)error;

// Returns the full entitlements dictionary for the target app.
- (NSDictionary *_Nullable)fullEntitlementsForBundleID:(NSString *)bundleID
                                                 error:(NSError **)error;

// Resolves the main executable path for the app bundle identifier.
- (NSString *)mainExecutablePathForBundleID:(NSString *)bundleID
                                     error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
