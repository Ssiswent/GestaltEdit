#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Read-only in-process probe for the Camera Visual Intelligence availability path.
/// Temporarily intercepts GMAvailabilityWrapper current* calls only to record arguments,
/// immediately restores the original IMPs, then calls query-only availability selectors.
FOUNDATION_EXPORT NSString *GEVIAdvancedProbeReport(void);

NS_ASSUME_NONNULL_END
