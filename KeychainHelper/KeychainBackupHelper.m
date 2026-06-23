#import "KeychainBackupHelper.h"
#import <Security/Security.h>

NSString * const PXKeychainBackupErrorDomain = @"com.hydra.projectx.keychain";

@implementation PXKeychainBackupResult
- (instancetype)init {
    self = [super init];
    if (self) {
        _warnings = @[];
        _errors = @[];
    }
    return self;
}
@end

#pragma mark - Private Helpers

/// Convert keychain item class to SecItemClass CFTypeRef.
static CFTypeRef PXSecItemClassFromType(PXKeychainItemClass itemClass) {
    switch (itemClass) {
        case PXKeychainItemClassGenericPassword:
            return kSecClassGenericPassword;
        case PXKeychainItemClassInternetPassword:
            return kSecClassInternetPassword;
        case PXKeychainItemClassCertificate:
            return kSecClassCertificate;
        case PXKeychainItemClassKey:
            return kSecClassKey;
        case PXKeychainItemClassIdentity:
            return kSecClassIdentity;
        default:
            return NULL;
    }
}

/// Get human-readable name for a keychain class.
static NSString *PXKeychainClassName(CFTypeRef secClass) {
    if (secClass == kSecClassGenericPassword) return @"GenericPassword";
    if (secClass == kSecClassInternetPassword) return @"InternetPassword";
    if (secClass == kSecClassCertificate) return @"Certificate";
    if (secClass == kSecClassKey) return @"Key";
    if (secClass == kSecClassIdentity) return @"Identity";
    return @"Unknown";
}

/// Get OSStatus error description.
static NSString *PXSecurityErrorDescription(OSStatus status) {
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    NSString *desc = message ? (__bridge_transfer NSString *)message : [NSString stringWithFormat:@"OSStatus %d", (int)status];
    return desc;
}

// Optional query knobs to avoid UI prompts and to surface errors.
static void PXAddAuthUIFlags(NSMutableDictionary *query) {
    if (!query) return;
    // iOS 9+: control whether SecItem may prompt.
    // Using FAIL ensures we get a clear error instead of UI/blocks.
    if (@available(iOS 9.0, *)) {
        query[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
    }
}

/// List of all keychain classes to iterate.
static NSArray<NSNumber *> *PXAllKeychainClasses(void) {
    return @[
        @(PXKeychainItemClassGenericPassword),
        @(PXKeychainItemClassInternetPassword),
        @(PXKeychainItemClassCertificate),
        @(PXKeychainItemClassKey),
        @(PXKeychainItemClassIdentity),
    ];
}

/// Attributes that should NOT be included when adding items back (system-managed).
static NSSet<NSString *> *PXExcludedRestoreAttributes(void) {
    static NSSet *excluded = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        excluded = [NSSet setWithObjects:
            (__bridge NSString *)kSecAttrAccessControl,
            (__bridge NSString *)kSecAttrCreationDate,
            (__bridge NSString *)kSecAttrModificationDate,
            (__bridge NSString *)kSecAttrPersistentReference,
            (__bridge NSString *)kSecValuePersistentRef,
            @"tomb",   // Internal attribute
            @"UUID",   // Internal
            @"sha1",   // Internal
            nil
        ];
    });
    return excluded;
}

/// Serialize a single keychain item dictionary into a plist-safe export dictionary.
/// NSData -> base64, NSDate -> timestamp, NSNumber/NSString kept as-is.
/// Non-serializable values (e.g. SecAccessControlRef) are skipped.
static NSDictionary *PXSerializeKeychainItem(NSDictionary *item, CFTypeRef secClass) {
    NSMutableDictionary *exportItem = [NSMutableDictionary dictionary];
    exportItem[@"_class"] = PXKeychainClassName(secClass);
    exportItem[@"_secClass"] = (__bridge id)secClass;

    for (NSString *key in item) {
        id value = item[key];

        if ([value isKindOfClass:[NSData class]]) {
            exportItem[key] = @{
                @"_type": @"data",
                @"_base64": [(NSData *)value base64EncodedStringWithOptions:0]
            };
        } else if ([value isKindOfClass:[NSDate class]]) {
            exportItem[key] = @{
                @"_type": @"date",
                @"_timestamp": @([(NSDate *)value timeIntervalSince1970])
            };
        } else if ([value isKindOfClass:[NSNumber class]] ||
                   [value isKindOfClass:[NSString class]]) {
            exportItem[key] = value;
        }
        // Skip non-serializable types (e.g. SecAccessControlRef).
    }

    return exportItem;
}

#pragma mark - Implementation

@implementation KeychainBackupHelper

#pragma mark - Backup

+ (PXKeychainBackupResult *)backupKeychainToFile:(NSString *)filePath
                                    accessGroups:(NSArray<NSString *> *)groups
                                     itemClasses:(PXKeychainItemClass)itemClasses
                                           error:(NSError **)error {
    if (!filePath.length) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorInvalidArguments
                                     userInfo:@{NSLocalizedDescriptionKey: @"Backup file path is required"}];
        }
        return nil;
    }
    
    if (!groups.count) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorNoAccessGroups
                                     userInfo:@{NSLocalizedDescriptionKey: @"At least one access group is required"}];
        }
        return nil;
    }
    
    PXKeychainBackupResult *result = [[PXKeychainBackupResult alloc] init];
    NSMutableArray<NSString *> *warnings = [NSMutableArray array];
    NSMutableArray<NSString *> *errors = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *allItems = [NSMutableArray array];

    // B4: Unified query loop over (group x class). Each pair is queried exactly
    // once, removing the previous dependency on groups.firstObject and the
    // duplicated second pass.
    for (NSString *group in groups) {
        if (![group isKindOfClass:[NSString class]] || group.length == 0) continue;

        for (NSNumber *classNum in PXAllKeychainClasses()) {
            PXKeychainItemClass classType = [classNum unsignedIntegerValue];
            if (!(itemClasses & classType)) continue;

            CFTypeRef secClass = PXSecItemClassFromType(classType);
            if (!secClass) continue;

            NSMutableDictionary *query = [@{
                (__bridge id)kSecClass: (__bridge id)secClass,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecReturnData: @YES,
                (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
                (__bridge id)kSecAttrAccessGroup: group,
            } mutableCopy];
            PXAddAuthUIFlags(query);

            CFTypeRef cfResult = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &cfResult);

            if (status == errSecItemNotFound) {
                // No items of this class/group - not an error.
                continue;
            }

            if (status != errSecSuccess) {
                NSString *msg = [NSString stringWithFormat:@"Failed to query %@ in group %@: %@",
                                PXKeychainClassName(secClass), group, PXSecurityErrorDescription(status)];
                [warnings addObject:msg];
                continue;
            }

            NSArray *items = (__bridge_transfer NSArray *)cfResult;
            if (![items isKindOfClass:[NSArray class]]) {
                items = @[items];
            }

            for (NSDictionary *item in items) {
                result.itemsProcessed++;
                NSDictionary *exportItem = PXSerializeKeychainItem(item, secClass);
                [allItems addObject:exportItem];
                result.itemsSucceeded++;
            }
        }
    }
    
    // Create backup dictionary.
    NSDictionary *backup = @{
        @"version": @1,
        @"created": @([[NSDate date] timeIntervalSince1970]),
        @"accessGroups": groups,
        @"items": allItems,
    };
    
    // Write to file.
    NSError *writeError = nil;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:backup
                                                                   format:NSPropertyListXMLFormat_v1_0
                                                                  options:0
                                                                    error:&writeError];
    if (!plistData) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorFileIO
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to serialize backup",
                                               NSUnderlyingErrorKey: writeError ?: [NSNull null]}];
        }
        return nil;
    }
    
    BOOL written = [plistData writeToFile:filePath options:NSDataWritingAtomic error:&writeError];
    if (!written) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorFileIO
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to write backup file",
                                               NSUnderlyingErrorKey: writeError ?: [NSNull null]}];
        }
        return nil;
    }
    
    result.warnings = warnings;
    result.errors = errors;
    return result;
}

#pragma mark - Restore

+ (PXKeychainBackupResult *)restoreKeychainFromFile:(NSString *)filePath
                                           overwrite:(BOOL)overwrite
                                               error:(NSError **)error {
    if (!filePath.length) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorInvalidArguments
                                     userInfo:@{NSLocalizedDescriptionKey: @"Backup file path is required"}];
        }
        return nil;
    }
    
    // Read backup file.
    NSData *plistData = [NSData dataWithContentsOfFile:filePath];
    if (!plistData.length) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorFileIO
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to read backup file or file is empty"}];
        }
        return nil;
    }
    
    NSError *parseError = nil;
    NSDictionary *backup = [NSPropertyListSerialization propertyListWithData:plistData
                                                                     options:NSPropertyListImmutable
                                                                      format:NULL
                                                                       error:&parseError];
    if (!backup || ![backup isKindOfClass:[NSDictionary class]]) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorInvalidBackupFile
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid backup file format",
                                               NSUnderlyingErrorKey: parseError ?: [NSNull null]}];
        }
        return nil;
    }
    
    NSArray *items = backup[@"items"];
    if (![items isKindOfClass:[NSArray class]]) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorInvalidBackupFile
                                     userInfo:@{NSLocalizedDescriptionKey: @"Backup file contains no items"}];
        }
        return nil;
    }
    
    PXKeychainBackupResult *result = [[PXKeychainBackupResult alloc] init];
    NSMutableArray<NSString *> *warnings = [NSMutableArray array];
    NSMutableArray<NSString *> *errors = [NSMutableArray array];
    NSSet<NSString *> *excluded = PXExcludedRestoreAttributes();

    // B2: If overwrite, wipe ALL classes in each target group up-front (not just
    // the classes present in the backup file). This makes restore a true
    // whole-group replacement and prevents stale items of a class that the
    // backup happens not to contain from surviving.
    if (overwrite) {
        NSArray<NSString *> *groups = [backup[@"accessGroups"] isKindOfClass:[NSArray class]] ? backup[@"accessGroups"] : @[];

        for (NSString *group in groups) {
            if (![group isKindOfClass:[NSString class]] || group.length == 0) continue;
            for (NSNumber *classNum in PXAllKeychainClasses()) {
                PXKeychainItemClass classType = [classNum unsignedIntegerValue];
                CFTypeRef secClass = PXSecItemClassFromType(classType);
                if (!secClass) continue;
                NSMutableDictionary *q = [NSMutableDictionary dictionary];
                q[(__bridge id)kSecClass] = (__bridge id)secClass;
                q[(__bridge id)kSecAttrAccessGroup] = group;
                // Include synchronizable items too (B1: SynchronizableAny retained per decision).
                q[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kSecAttrSynchronizableAny;
                OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
                if (st != errSecSuccess && st != errSecItemNotFound) {
                    [warnings addObject:[NSString stringWithFormat:@"Pre-wipe failed for %@/%@: %@",
                                         group,
                                         PXKeychainClassName(secClass),
                                         PXSecurityErrorDescription(st)]];
                }
            }
        }
    }
    
    NSString *accessControlKey = (__bridge NSString *)kSecAttrAccessControl;

    for (NSDictionary *item in items) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        result.itemsProcessed++;
        
        // Get the security class.
        id secClassValue = item[@"_secClass"];
        if (!secClassValue) {
            [warnings addObject:@"Item missing _secClass"];
            result.itemsFailed++;
            continue;
        }

        // B3 (Plan A): items created via SecAccessControlRef (biometric/passcode)
        // expose kSecAttrAccessControl, which is a non-serializable object and was
        // dropped at backup time. Such items are restored best-effort with the
        // default protection class; warn so the user knows the original
        // protection class (e.g. biometric/passcode gating) is not preserved.
        if (item[accessControlKey] != nil) {
            NSString *acct = item[(__bridge id)kSecAttrAccount];
            NSString *svc = item[(__bridge id)kSecAttrService];
            [warnings addObject:[NSString stringWithFormat:@"Item (acct=%@ svc=%@) used an access-control object; original protection class not preserved on restore",
                                 acct ?: @"", svc ?: @""]];
        }
        
        // Build the add query.
        NSMutableDictionary *addQuery = [NSMutableDictionary dictionary];
        addQuery[(__bridge id)kSecClass] = secClassValue;
        
        for (NSString *key in item) {
            if ([key hasPrefix:@"_"]) continue; // Skip metadata keys
            if ([excluded containsObject:key]) continue;
            
            id value = item[key];
            
            // Decode special types.
            if ([value isKindOfClass:[NSDictionary class]]) {
                NSDictionary *wrapped = (NSDictionary *)value;
                NSString *type = wrapped[@"_type"];
                
                if ([type isEqualToString:@"data"]) {
                    NSString *base64 = wrapped[@"_base64"];
                    if (base64) {
                        value = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
                    }
                } else if ([type isEqualToString:@"date"]) {
                    NSNumber *timestamp = wrapped[@"_timestamp"];
                    if (timestamp) {
                        value = [NSDate dateWithTimeIntervalSince1970:[timestamp doubleValue]];
                    }
                }
            }
            
            if (value) {
                addQuery[key] = value;
            }
        }
        
        // If overwrite mode, we already performed a group-wide pre-wipe.
        
        // Add the item.
        // Ensure we can restore synchronizable items.
        if (addQuery[(__bridge id)kSecAttrSynchronizable]) {
            // Nothing else to do; keep value as-is.
        }
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
        
        if (status == errSecSuccess) {
            result.itemsSucceeded++;
        } else if (status == errSecDuplicateItem && !overwrite) {
            [warnings addObject:[NSString stringWithFormat:@"Item already exists: %@", 
                               addQuery[(__bridge id)kSecAttrAccount] ?: @"unknown"]];
            result.itemsFailed++;
        } else {
            NSString *acct = addQuery[(__bridge id)kSecAttrAccount];
            NSString *svc = addQuery[(__bridge id)kSecAttrService];
            NSString *grp = addQuery[(__bridge id)kSecAttrAccessGroup];
            [errors addObject:[NSString stringWithFormat:@"Failed to add item (acct=%@ svc=%@ group=%@): %@",
                              acct ?: @"",
                              svc ?: @"",
                              grp ?: @"",
                              PXSecurityErrorDescription(status)]];
            result.itemsFailed++;
        }
    }
    
    result.warnings = warnings;
    result.errors = errors;
    return result;
}

#pragma mark - Wipe

+ (PXKeychainBackupResult *)wipeKeychainForAccessGroups:(NSArray<NSString *> *)groups
                                            itemClasses:(PXKeychainItemClass)itemClasses
                                                  error:(NSError **)error {
    if (!groups.count) {
        if (error) {
            *error = [NSError errorWithDomain:PXKeychainBackupErrorDomain
                                         code:PXKeychainBackupErrorNoAccessGroups
                                     userInfo:@{NSLocalizedDescriptionKey: @"At least one access group is required"}];
        }
        return nil;
    }
    
    PXKeychainBackupResult *result = [[PXKeychainBackupResult alloc] init];
    NSMutableArray<NSString *> *warnings = [NSMutableArray array];
    
    for (NSString *group in groups) {
        for (NSNumber *classNum in PXAllKeychainClasses()) {
            PXKeychainItemClass classType = [classNum unsignedIntegerValue];
            if (!(itemClasses & classType)) continue;
            
            CFTypeRef secClass = PXSecItemClassFromType(classType);
            if (!secClass) continue;
            
            NSMutableDictionary *query = [@{
                (__bridge id)kSecClass: (__bridge id)secClass,
                (__bridge id)kSecAttrAccessGroup: group,
            } mutableCopy];
            PXAddAuthUIFlags(query);
            
            // First count items.
            NSMutableDictionary *countQuery = [@{
                (__bridge id)kSecClass: (__bridge id)secClass,
                (__bridge id)kSecAttrAccessGroup: group,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            } mutableCopy];
            PXAddAuthUIFlags(countQuery);
            
            CFTypeRef countResult = NULL;
            OSStatus countStatus = SecItemCopyMatching((__bridge CFDictionaryRef)countQuery, &countResult);
            
            NSUInteger itemCount = 0;
            if (countStatus == errSecSuccess && countResult) {
                NSArray *matches = (__bridge_transfer NSArray *)countResult;
                if ([matches isKindOfClass:[NSArray class]]) {
                    itemCount = matches.count;
                } else {
                    itemCount = 1;
                }
            }
            
            result.itemsProcessed += itemCount;
            
            // Delete all matching items.
            OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
            
            if (status == errSecSuccess || status == errSecItemNotFound) {
                result.itemsSucceeded += itemCount;
            } else {
                [warnings addObject:[NSString stringWithFormat:@"Failed to delete %@ items in group %@: %@",
                                   PXKeychainClassName(secClass), group, PXSecurityErrorDescription(status)]];
                result.itemsFailed += itemCount;
            }
        }
    }
    
    result.warnings = warnings;
    return result;
}

#pragma mark - List

+ (NSArray<NSDictionary *> *)listKeychainItemsForAccessGroups:(NSArray<NSString *> *)groups
                                                   itemClasses:(PXKeychainItemClass)itemClasses {
    NSMutableArray<NSDictionary *> *allItems = [NSMutableArray array];
    
    for (NSString *group in groups) {
        for (NSNumber *classNum in PXAllKeychainClasses()) {
            PXKeychainItemClass classType = [classNum unsignedIntegerValue];
            if (!(itemClasses & classType)) continue;
            
            CFTypeRef secClass = PXSecItemClassFromType(classType);
            if (!secClass) continue;
            
            NSMutableDictionary *query = [@{
                (__bridge id)kSecClass: (__bridge id)secClass,
                (__bridge id)kSecAttrAccessGroup: group,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            } mutableCopy];
            PXAddAuthUIFlags(query);
            
            CFTypeRef cfResult = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &cfResult);
            
            if (status != errSecSuccess) continue;
            
            NSArray *items = (__bridge_transfer NSArray *)cfResult;
            if (![items isKindOfClass:[NSArray class]]) {
                items = @[items];
            }
            
            for (NSDictionary *item in items) {
                NSMutableDictionary *info = [NSMutableDictionary dictionary];
                info[@"class"] = PXKeychainClassName(secClass);
                info[@"accessGroup"] = group;
                
                // Copy safe attributes for display.
                if (item[(__bridge id)kSecAttrAccount]) {
                    info[@"account"] = item[(__bridge id)kSecAttrAccount];
                }
                if (item[(__bridge id)kSecAttrService]) {
                    info[@"service"] = item[(__bridge id)kSecAttrService];
                }
                if (item[(__bridge id)kSecAttrLabel]) {
                    info[@"label"] = item[(__bridge id)kSecAttrLabel];
                }
                if (item[(__bridge id)kSecAttrCreationDate]) {
                    info[@"created"] = item[(__bridge id)kSecAttrCreationDate];
                }
                
                [allItems addObject:info];
            }
        }
    }
    
    return allItems;
}

+ (NSArray<NSDictionary *> *)diagnoseKeychainAccessForGroups:(NSArray<NSString *> *)groups
                                                 itemClasses:(PXKeychainItemClass)itemClasses {
    NSMutableArray<NSDictionary *> *out = [NSMutableArray array];
    for (NSString *group in groups) {
        for (NSNumber *classNum in PXAllKeychainClasses()) {
            PXKeychainItemClass classType = [classNum unsignedIntegerValue];
            if (!(itemClasses & classType)) continue;

            CFTypeRef secClass = PXSecItemClassFromType(classType);
            if (!secClass) continue;

            NSMutableDictionary *query = [@{
                (__bridge id)kSecClass: (__bridge id)secClass,
                (__bridge id)kSecAttrAccessGroup: group,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            } mutableCopy];
            PXAddAuthUIFlags(query);

            CFTypeRef cfResult = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &cfResult);
            NSUInteger count = 0;
            if (status == errSecSuccess && cfResult) {
                id v = (__bridge_transfer id)cfResult;
                if ([v isKindOfClass:[NSArray class]]) {
                    count = [(NSArray *)v count];
                } else {
                    count = 1;
                }
            }

            [out addObject:@{
                @"accessGroup": group ?: @"",
                @"class": PXKeychainClassName(secClass),
                @"status": @((int)status),
                @"statusDesc": PXSecurityErrorDescription(status) ?: @"",
                @"count": @(count),
            }];
        }
    }
    return out;
}

@end
