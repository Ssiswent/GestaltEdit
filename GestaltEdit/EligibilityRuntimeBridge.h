#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Calls exported read-only libsystem_eligibility APIs via dlsym and returns
/// a plain-text report. No setters, resets, force APIs, or file writes are used.
FOUNDATION_EXPORT NSString *GEEligibilityRuntimeReport(void);

NS_ASSUME_NONNULL_END
