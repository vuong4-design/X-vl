#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Cụm 0 — Shared validated config snapshot.
//
// Single source of truth for the active profile's device_ids.plist.
// Hooks read a frozen, validated snapshot through this module instead of
// parsing device_ids.plist themselves and inventing their own fallbacks.
//
// Group validity flags gate per-domain spoofing. A group is valid only when
// all of its P0-required keys are present and well-typed. When a group is
// invalid, member hooks must fall through to %orig (no partial spoof, no
// hardcoded constants).
typedef struct {
    BOOL identity;
    BOOL iosVersion;
    BOOL screen;
    BOOL hardware;
    BOOL wifi;
    BOOL carrier;
} PXSnapshotGroups;

@interface PXConfigSnapshot : NSObject

// Immutable validated device_ids for the resolved profile (empty dict if none).
@property (nonatomic, copy, readonly) NSDictionary<NSString *, id> *deviceIds;

// Resolved profile id used to build this snapshot (nil if resolution failed).
@property (nonatomic, copy, readonly, nullable) NSString *profileId;

// In-memory generation counter. Increments only after a successful atomic swap.
// Never read from disk; used by hooks to invalidate their own caches.
@property (nonatomic, readonly) uint64_t generation;

// Per-group validity for the currently-live snapshot.
@property (nonatomic, readonly) PXSnapshotGroups groups;

// Singleton holding the live snapshot.
+ (instancetype)shared;

// Resolve current profile -> load device_ids.plist -> validate -> atomic swap.
// Returns YES if a new valid core snapshot was installed (generation bumped).
// On failure, keeps the previous snapshot and returns NO.
- (BOOL)reload;

// Typed, nil-safe accessors (nil / nil when key absent or wrong type).
- (nullable NSString *)stringForKey:(NSString *)key;
- (nullable NSNumber *)numberForKey:(NSString *)key;

// Convenience group checks (read the live `groups`).
- (BOOL)isIdentityValid;
- (BOOL)isIOSVersionValid;
- (BOOL)isScreenValid;
- (BOOL)isHardwareValid;
- (BOOL)isWiFiValid;
- (BOOL)isCarrierValid;

@end

NS_ASSUME_NONNULL_END
