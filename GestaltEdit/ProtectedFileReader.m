#import "ProtectedFileReader.h"
#import "BadQueryBridge.h"

NSDictionary<NSString *, id> *GEReadProtectedFileResult(NSString *path)
{
    if (path.length == 0) {
        return @{ @"error": @"Empty path" };
    }

    NSString *leasePath = path;
    if ([leasePath hasPrefix:@"/private/"]) {
        leasePath = [leasePath substringFromIndex:@"/private".length];
    }

    NSString *leaseError = nil;
    BadQueryLease *lease = [BadQueryLease leaseForPath:leasePath error:&leaseError];
    if (!lease) {
        return @{ @"error": leaseError ?: @"Failed to acquire read lease" };
    }

    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfFile:path
                                          options:NSDataReadingMappedIfSafe
                                            error:&readError];
    [lease invalidate];

    if (!data) {
        return @{ @"error": readError.localizedDescription ?: @"Read failed" };
    }

    return @{ @"data": data };
}
