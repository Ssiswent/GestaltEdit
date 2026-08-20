//
//  BadQueryBridge.h
//  GestaltEdit
//
//  Path-based ContainerManager query derived from forcequitOS/bad_query.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface BadQueryLease : NSObject

@property(nonatomic, copy, readonly) NSString *targetPath;
@property(nonatomic, readonly, getter=isActive) BOOL active;

+ (nullable instancetype)leaseForPath:(NSString *)path
                                error:(NSString * _Nullable * _Nullable)error;
- (void)invalidate;

@end

FOUNDATION_EXPORT BOOL BadQueryBridgeAvailable(void);

/// Read-only helper. Acquires a temporary sandbox extension for exactly `path`,
/// reads the file, then immediately releases the extension.
FOUNDATION_EXPORT NSData * _Nullable BadQueryReadDataAtPath(
    NSString *path,
    NSString * _Nullable * _Nullable error);

/// Read-only helper. Acquires a temporary sandbox extension for exactly `path`,
/// lists that directory, then immediately releases the extension.
FOUNDATION_EXPORT NSArray<NSString *> * _Nullable BadQueryListDirectoryAtPath(
    NSString *path,
    NSString * _Nullable * _Nullable error);

NS_ASSUME_NONNULL_END
