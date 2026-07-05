// PXArchive.m - Small TrollStore-safe directory archive used when system tar is unavailable.

#import "PXArchive.h"

#import <sys/stat.h>
#import <sys/time.h>
#import <limits.h>
#import <stdarg.h>
#import <stdint.h>
#import <string.h>
#import <unistd.h>

NSString * const PXArchiveErrorDomain = @"PXArchiveErrorDomain";

static const uint8_t PXArchiveMagic[] = { 'P', 'X', 'A', 'R', '0', '0', '0', '1' };
static const uint8_t PXArchiveTypeEnd = 0;
static const uint8_t PXArchiveTypeDirectory = 1;
static const uint8_t PXArchiveTypeFile = 2;
static const uint8_t PXArchiveTypeSymlink = 3;

static NSError *PXArchiveError(NSInteger code, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    return [NSError errorWithDomain:PXArchiveErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"Archive error"}];
}

static BOOL PXArchiveSetError(NSError **error, NSError *value) {
    if (error) *error = value;
    return NO;
}

static BOOL PXArchiveWrite(NSFileHandle *fh, const void *bytes, NSUInteger length, NSError **error) {
    @try {
        [fh writeData:[NSData dataWithBytes:bytes length:length]];
        return YES;
    } @catch (NSException *ex) {
        return PXArchiveSetError(error, PXArchiveError(1, @"Archive write failed: %@", ex.reason ?: ex.name));
    }
}

static BOOL PXArchiveRead(NSFileHandle *fh, void *bytes, NSUInteger length, NSError **error) {
    @try {
        NSData *data = [fh readDataOfLength:length];
        if (data.length != length) {
            return PXArchiveSetError(error, PXArchiveError(2, @"Archive ended unexpectedly"));
        }
        memcpy(bytes, data.bytes, length);
        return YES;
    } @catch (NSException *ex) {
        return PXArchiveSetError(error, PXArchiveError(3, @"Archive read failed: %@", ex.reason ?: ex.name));
    }
}

static BOOL PXArchiveWriteU8(NSFileHandle *fh, uint8_t value, NSError **error) {
    return PXArchiveWrite(fh, &value, sizeof(value), error);
}

static BOOL PXArchiveReadU8(NSFileHandle *fh, uint8_t *value, NSError **error) {
    return PXArchiveRead(fh, value, sizeof(*value), error);
}

static BOOL PXArchiveWriteU32(NSFileHandle *fh, uint32_t value, NSError **error) {
    uint8_t b[4] = {
        (uint8_t)(value & 0xff),
        (uint8_t)((value >> 8) & 0xff),
        (uint8_t)((value >> 16) & 0xff),
        (uint8_t)((value >> 24) & 0xff)
    };
    return PXArchiveWrite(fh, b, sizeof(b), error);
}

static BOOL PXArchiveReadU32(NSFileHandle *fh, uint32_t *value, NSError **error) {
    uint8_t b[4];
    if (!PXArchiveRead(fh, b, sizeof(b), error)) return NO;
    *value = ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return YES;
}

static BOOL PXArchiveWriteU64(NSFileHandle *fh, uint64_t value, NSError **error) {
    uint8_t b[8];
    for (NSUInteger i = 0; i < sizeof(b); i++) b[i] = (uint8_t)((value >> (i * 8)) & 0xff);
    return PXArchiveWrite(fh, b, sizeof(b), error);
}

static BOOL PXArchiveReadU64(NSFileHandle *fh, uint64_t *value, NSError **error) {
    uint8_t b[8];
    if (!PXArchiveRead(fh, b, sizeof(b), error)) return NO;
    uint64_t v = 0;
    for (NSUInteger i = 0; i < sizeof(b); i++) v |= ((uint64_t)b[i]) << (i * 8);
    *value = v;
    return YES;
}

static BOOL PXArchiveShouldSkipRelativePath(NSString *relPath) {
    NSString *name = relPath.lastPathComponent;
    return [name isEqualToString:@".com.apple.mobile_container_manager.metadata.plist"] ||
           [name isEqualToString:@".com.apple.containermanagerd.metadata.plist"];
}

static BOOL PXArchiveSafeRelativePath(NSString *relPath) {
    if (![relPath isKindOfClass:[NSString class]] || !relPath.length) return NO;
    if ([relPath hasPrefix:@"/"]) return NO;
    NSArray<NSString *> *parts = [relPath pathComponents];
    for (NSString *part in parts) {
        if ([part isEqualToString:@".."] || [part isEqualToString:@"/"]) return NO;
    }
    return YES;
}

static BOOL PXArchiveWriteEntryHeader(NSFileHandle *out,
                                      uint8_t type,
                                      NSString *relPath,
                                      uint64_t dataLen,
                                      uint32_t mode,
                                      uint64_t mtime,
                                      NSError **error) {
    NSData *pathData = [relPath dataUsingEncoding:NSUTF8StringEncoding];
    if (!pathData.length || pathData.length > UINT32_MAX) {
        return PXArchiveSetError(error, PXArchiveError(4, @"Invalid archive path: %@", relPath ?: @""));
    }
    if (!PXArchiveWriteU8(out, type, error)) return NO;
    if (!PXArchiveWriteU32(out, (uint32_t)pathData.length, error)) return NO;
    if (!PXArchiveWriteU64(out, dataLen, error)) return NO;
    if (!PXArchiveWriteU32(out, mode, error)) return NO;
    if (!PXArchiveWriteU64(out, mtime, error)) return NO;
    return PXArchiveWrite(out, pathData.bytes, pathData.length, error);
}

static BOOL PXArchiveCopyFileBytes(NSFileHandle *in, NSFileHandle *out, uint64_t byteCount, NSError **error) {
    uint64_t remaining = byteCount;
    @try {
        while (remaining > 0) {
            NSUInteger chunk = (NSUInteger)MIN((uint64_t)(1024 * 1024), remaining);
            NSData *data = [in readDataOfLength:chunk];
            if (!data.length) {
                return PXArchiveSetError(error, PXArchiveError(5, @"File ended while archiving"));
            }
            [out writeData:data];
            remaining -= data.length;
        }
        return YES;
    } @catch (NSException *ex) {
        return PXArchiveSetError(error, PXArchiveError(6, @"File copy failed: %@", ex.reason ?: ex.name));
    }
}

BOOL PXArchiveCreateDirectoryArchive(NSString *sourceDir, NSString *archivePath, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:sourceDir isDirectory:&isDir] || !isDir) {
        return PXArchiveSetError(error, PXArchiveError(10, @"Source directory not found: %@", sourceDir ?: @""));
    }

    NSString *parent = archivePath.stringByDeletingLastPathComponent;
    if (parent.length) [fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:nil error:nil];
    [fm removeItemAtPath:archivePath error:nil];
    if (![fm createFileAtPath:archivePath contents:nil attributes:nil]) {
        return PXArchiveSetError(error, PXArchiveError(11, @"Failed to create archive: %@", archivePath ?: @""));
    }

    NSFileHandle *out = [NSFileHandle fileHandleForWritingAtPath:archivePath];
    if (!out) return PXArchiveSetError(error, PXArchiveError(12, @"Failed to open archive for writing: %@", archivePath ?: @""));

    if (!PXArchiveWrite(out, PXArchiveMagic, sizeof(PXArchiveMagic), error)) {
        [out closeFile];
        return NO;
    }

    NSDirectoryEnumerator<NSString *> *enumerator = [fm enumeratorAtPath:sourceDir];
    for (NSString *rel in enumerator) {
        if (PXArchiveShouldSkipRelativePath(rel)) {
            [enumerator skipDescendants];
            continue;
        }

        NSString *path = [sourceDir stringByAppendingPathComponent:rel];
        struct stat st;
        if (lstat(path.fileSystemRepresentation, &st) != 0) {
            continue;
        }

        uint32_t mode = (uint32_t)(st.st_mode & 07777);
        uint64_t mtime = (uint64_t)MAX((time_t)0, st.st_mtime);
        if (S_ISDIR(st.st_mode)) {
            if (!PXArchiveWriteEntryHeader(out, PXArchiveTypeDirectory, rel, 0, mode, mtime, error)) {
                [out closeFile];
                return NO;
            }
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            char buf[PATH_MAX];
            ssize_t len = readlink(path.fileSystemRepresentation, buf, sizeof(buf) - 1);
            if (len < 0) continue;
            buf[len] = '\0';
            NSData *targetData = [[NSString stringWithUTF8String:buf] dataUsingEncoding:NSUTF8StringEncoding];
            if (!PXArchiveWriteEntryHeader(out, PXArchiveTypeSymlink, rel, targetData.length, mode, mtime, error) ||
                !PXArchiveWrite(out, targetData.bytes, targetData.length, error)) {
                [out closeFile];
                return NO;
            }
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            if (!PXArchiveWriteEntryHeader(out, PXArchiveTypeFile, rel, (uint64_t)st.st_size, mode, mtime, error)) {
                [out closeFile];
                return NO;
            }
            NSFileHandle *in = [NSFileHandle fileHandleForReadingAtPath:path];
            if (!in) {
                [out closeFile];
                return PXArchiveSetError(error, PXArchiveError(13, @"Failed to open file: %@", path));
            }
            BOOL copied = PXArchiveCopyFileBytes(in, out, (uint64_t)st.st_size, error);
            [in closeFile];
            if (!copied) {
                [out closeFile];
                return NO;
            }
        }
    }

    BOOL ok = PXArchiveWriteU8(out, PXArchiveTypeEnd, error);
    [out closeFile];
    return ok;
}

static BOOL PXArchiveSkipBytes(NSFileHandle *fh, uint64_t byteCount, NSError **error) {
    uint64_t remaining = byteCount;
    @try {
        while (remaining > 0) {
            NSUInteger chunk = (NSUInteger)MIN((uint64_t)(1024 * 1024), remaining);
            NSData *data = [fh readDataOfLength:chunk];
            if (data.length != chunk) return PXArchiveSetError(error, PXArchiveError(20, @"Archive ended while skipping data"));
            remaining -= chunk;
        }
        return YES;
    } @catch (NSException *ex) {
        return PXArchiveSetError(error, PXArchiveError(21, @"Archive skip failed: %@", ex.reason ?: ex.name));
    }
}

static BOOL PXArchiveExtractFile(NSFileHandle *in, NSString *dest, uint64_t byteCount, uint32_t mode, uint64_t mtime, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *parent = dest.stringByDeletingLastPathComponent;
    if (parent.length) [fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:nil error:nil];
    [fm removeItemAtPath:dest error:nil];
    if (![fm createFileAtPath:dest contents:nil attributes:nil]) {
        return PXArchiveSetError(error, PXArchiveError(22, @"Failed to create file: %@", dest));
    }
    NSFileHandle *out = [NSFileHandle fileHandleForWritingAtPath:dest];
    if (!out) return PXArchiveSetError(error, PXArchiveError(23, @"Failed to open file for writing: %@", dest));
    BOOL ok = PXArchiveCopyFileBytes(in, out, byteCount, error);
    [out closeFile];
    chmod(dest.fileSystemRepresentation, mode ? mode : 0644);
    struct timeval tv[2];
    tv[0].tv_sec = (time_t)mtime;
    tv[0].tv_usec = 0;
    tv[1].tv_sec = (time_t)mtime;
    tv[1].tv_usec = 0;
    utimes(dest.fileSystemRepresentation, tv);
    return ok;
}

BOOL PXArchiveExtractArchiveToDirectory(NSString *archivePath, NSString *destDir, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:archivePath]) {
        return PXArchiveSetError(error, PXArchiveError(30, @"Archive not found: %@", archivePath ?: @""));
    }
    [fm createDirectoryAtPath:destDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSFileHandle *in = [NSFileHandle fileHandleForReadingAtPath:archivePath];
    if (!in) return PXArchiveSetError(error, PXArchiveError(31, @"Failed to open archive: %@", archivePath ?: @""));

    uint8_t magic[sizeof(PXArchiveMagic)];
    if (!PXArchiveRead(in, magic, sizeof(magic), error)) {
        [in closeFile];
        return NO;
    }
    if (memcmp(magic, PXArchiveMagic, sizeof(PXArchiveMagic)) != 0) {
        [in closeFile];
        return PXArchiveSetError(error, PXArchiveError(32, @"Unsupported archive format: %@", archivePath ?: @""));
    }

    while (YES) {
        uint8_t type = 0;
        if (!PXArchiveReadU8(in, &type, error)) {
            [in closeFile];
            return NO;
        }
        if (type == PXArchiveTypeEnd) break;

        uint32_t pathLen = 0;
        uint64_t dataLen = 0;
        uint32_t mode = 0;
        uint64_t mtime = 0;
        if (!PXArchiveReadU32(in, &pathLen, error) ||
            !PXArchiveReadU64(in, &dataLen, error) ||
            !PXArchiveReadU32(in, &mode, error) ||
            !PXArchiveReadU64(in, &mtime, error)) {
            [in closeFile];
            return NO;
        }

        NSMutableData *pathData = [NSMutableData dataWithLength:pathLen];
        if (!PXArchiveRead(in, pathData.mutableBytes, pathLen, error)) {
            [in closeFile];
            return NO;
        }
        NSString *rel = [[NSString alloc] initWithData:pathData encoding:NSUTF8StringEncoding];
        if (!PXArchiveSafeRelativePath(rel)) {
            [in closeFile];
            return PXArchiveSetError(error, PXArchiveError(33, @"Unsafe archive path: %@", rel ?: @""));
        }
        NSString *dest = [destDir stringByAppendingPathComponent:rel];

        if (type == PXArchiveTypeDirectory) {
            [fm createDirectoryAtPath:dest withIntermediateDirectories:YES attributes:nil error:nil];
            chmod(dest.fileSystemRepresentation, mode ? mode : 0755);
            if (dataLen && !PXArchiveSkipBytes(in, dataLen, error)) {
                [in closeFile];
                return NO;
            }
        } else if (type == PXArchiveTypeFile) {
            if (!PXArchiveExtractFile(in, dest, dataLen, mode, mtime, error)) {
                [in closeFile];
                return NO;
            }
        } else if (type == PXArchiveTypeSymlink) {
            NSMutableData *targetData = [NSMutableData dataWithLength:(NSUInteger)dataLen];
            if (!PXArchiveRead(in, targetData.mutableBytes, (NSUInteger)dataLen, error)) {
                [in closeFile];
                return NO;
            }
            NSString *target = [[NSString alloc] initWithData:targetData encoding:NSUTF8StringEncoding];
            NSString *parent = dest.stringByDeletingLastPathComponent;
            if (parent.length) [fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:nil error:nil];
            [fm removeItemAtPath:dest error:nil];
            if (target.length) symlink(target.fileSystemRepresentation, dest.fileSystemRepresentation);
        } else {
            [in closeFile];
            return PXArchiveSetError(error, PXArchiveError(34, @"Unknown archive entry type: %u", type));
        }
    }

    [in closeFile];
    return YES;
}

BOOL PXArchiveCloneDirectoryContents(NSString *sourceDir, NSString *destDir, NSError **error) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:sourceDir isDirectory:&isDir] || !isDir) {
        return PXArchiveSetError(error, PXArchiveError(40, @"Source directory not found: %@", sourceDir ?: @""));
    }
    [fm createDirectoryAtPath:destDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"pxclone-%@.pxar", [[NSUUID UUID] UUIDString]]];
    NSError *local = nil;
    BOOL ok = PXArchiveCreateDirectoryArchive(sourceDir, tmp, &local) && PXArchiveExtractArchiveToDirectory(tmp, destDir, &local);
    [fm removeItemAtPath:tmp error:nil];
    if (!ok) return PXArchiveSetError(error, local ?: PXArchiveError(41, @"Clone failed"));
    return YES;
}
