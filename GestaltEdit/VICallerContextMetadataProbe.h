#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Pure read-only in-process metadata diagnostic for VisualIntelligenceCore,
/// VisionKitCore and GenerativeModels. It only loads frameworks, scans their
/// mapped string/reflection sections, and enumerates Objective-C runtime metadata.
FOUNDATION_EXPORT NSString *VICallerContextMetadataGenerateReport(void);

NS_ASSUME_NONNULL_END
