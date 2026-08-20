#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Reads a protected file using a temporary bad_query sandbox-extension lease.
/// This helper never opens the target for writing and never modifies its contents.
/// Result contains either { @"data": NSData } or { @"error": NSString }.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *GEReadProtectedFileResult(NSString *path);

NS_ASSUME_NONNULL_END
