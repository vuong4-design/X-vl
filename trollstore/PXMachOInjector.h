// PXMachOInjector.h - minimal LC_LOAD_DYLIB insertion for prepared copies.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const PXMachOInjectorErrorDomain;

@interface PXMachOInjector : NSObject

+ (BOOL)insertDylibLoadCommand:(NSString *)dylibLoadPath
               intoMachOAtPath:(NSString *)path
                          error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
