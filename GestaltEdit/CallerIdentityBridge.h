#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Read-only LaunchServices + code-signing diagnostic.
/// Does not call GenerativeExperiences availability XPC, setters, preference writes,
/// MobileGestalt writes, method swizzling, respring or reboot.
FOUNDATION_EXPORT NSString *CallerIdentityGenerateReport(void);

NS_ASSUME_NONNULL_END
