// PXArchive.h - Small TrollStore-safe directory archive used when system tar is unavailable.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const PXArchiveErrorDomain;

BOOL PXArchiveCreateDirectoryArchive(NSString *sourceDir, NSString *archivePath, NSError **error);
BOOL PXArchiveExtractArchiveToDirectory(NSString *archivePath, NSString *destDir, NSError **error);
BOOL PXArchiveCloneDirectoryContents(NSString *sourceDir, NSString *destDir, NSError **error);

NS_ASSUME_NONNULL_END
