#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Read-only, in-process probe that creates a fresh VKCGMAvailability instance
/// while temporarily recording GMAvailabilityWrapper current* arguments.
FOUNDATION_EXPORT NSString *GEVIFreshInitProbeReport(void);

NS_ASSUME_NONNULL_END
