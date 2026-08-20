#import "GEVIFreshInitProbe.h"

#import <dlfcn.h>
#import <objc/runtime.h>

static long long (*GEFreshOriginalCurrent1)(id, SEL, id) = NULL;
static long long (*GEFreshOriginalCurrent2)(id, SEL, id, id) = NULL;
static NSMutableArray<NSDictionary *> *GEFreshCapturedCalls;

static NSArray<NSString *> *GEFreshFlatten(id value)
{
    if (!value) return @[];
    if ([value isKindOfClass:[NSString class]]) return @[(NSString *)value];

    NSMutableArray<NSString *> *items = [NSMutableArray array];
    @try {
        if ([value conformsToProtocol:@protocol(NSFastEnumeration)]) {
            for (id item in value) {
                if ([item isKindOfClass:[NSString class]]) {
                    [items addObject:item];
                } else if (item) {
                    [items addObject:[item description] ?: @"<description unavailable>"];
                }
            }
        }
    } @catch (__unused NSException *exception) {
    }

    if (items.count == 0) {
        [items addObject:[value description] ?: @"<description unavailable>"];
    }
    return items;
}

static void GEFreshRecord(SEL selector, id identifiers, id language)
{
    if (!GEFreshCapturedCalls) return;
    NSDictionary *entry = @{
        @"selector": NSStringFromSelector(selector),
        @"identifiers": GEFreshFlatten(identifiers),
        @"identifiersClass": identifiers ? NSStringFromClass([identifiers class]) : @"<nil>",
        @"language": language ? ([language description] ?: @"<description unavailable>") : @"<nil>",
        @"languageClass": language ? NSStringFromClass([language class]) : @"<nil>"
    };
    @synchronized (GEFreshCapturedCalls) {
        [GEFreshCapturedCalls addObject:entry];
    }
}

static long long GEFreshHookCurrent1(id self, SEL _cmd, id identifiers)
{
    GEFreshRecord(_cmd, identifiers, nil);
    return GEFreshOriginalCurrent1 ? GEFreshOriginalCurrent1(self, _cmd, identifiers) : -9999;
}

static long long GEFreshHookCurrent2(id self, SEL _cmd, id identifiers, id language)
{
    GEFreshRecord(_cmd, identifiers, language);
    return GEFreshOriginalCurrent2 ? GEFreshOriginalCurrent2(self, _cmd, identifiers, language) : -9999;
}

static BOOL GEFreshInstallHook(Class cls,
                               SEL selector,
                               const char *expectedEncoding,
                               IMP replacement,
                               IMP *originalOut,
                               NSMutableString *report)
{
    Method method = class_getClassMethod(cls, selector);
    if (!method) {
        [report appendFormat:@"  hook %@: unavailable\n", NSStringFromSelector(selector)];
        return NO;
    }

    const char *encoding = method_getTypeEncoding(method);
    if (!encoding || strcmp(encoding, expectedEncoding) != 0) {
        [report appendFormat:@"  hook %@: ABI mismatch (%s)\n",
         NSStringFromSelector(selector), encoding ?: "<nil>"];
        return NO;
    }

    IMP original = method_getImplementation(method);
    if (!original) return NO;
    *originalOut = original;
    method_setImplementation(method, replacement);
    [report appendFormat:@"  hook %@: installed\n", NSStringFromSelector(selector)];
    return YES;
}

static void GEFreshRestoreHook(Class cls, SEL selector, IMP original, NSMutableString *report)
{
    if (!cls || !original) return;
    Method method = class_getClassMethod(cls, selector);
    if (!method) return;
    method_setImplementation(method, original);
    [report appendFormat:@"  hook %@: restored\n", NSStringFromSelector(selector)];
}

static BOOL GEFreshReadBool(id target, NSString *selectorName, BOOL *value, NSString **error)
{
    SEL selector = NSSelectorFromString(selectorName);
    if (![target respondsToSelector:selector]) {
        if (error) *error = @"selector unavailable";
        return NO;
    }

    NSMethodSignature *signature = [target methodSignatureForSelector:selector];
    if (!signature || signature.numberOfArguments != 2 ||
        !(signature.methodReturnType[0] == 'B' || signature.methodReturnType[0] == 'c')) {
        if (error) *error = @"unexpected signature";
        return NO;
    }

    @try {
        NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
        invocation.target = target;
        invocation.selector = selector;
        [invocation invoke];
        unsigned char raw = 0;
        [invocation getReturnValue:&raw];
        if (value) *value = raw ? YES : NO;
        return YES;
    } @catch (NSException *exception) {
        if (error) *error = exception.reason ?: exception.name;
        return NO;
    }
}

NSString *GEVIFreshInitProbeReport(void)
{
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"--- Fresh VK init / GM argument capture probe ---\n"];
    [report appendString:@"READ-ONLY / EPHEMERAL: temporarily records GMAvailabilityWrapper current* arguments while constructing one fresh VKCGMAvailability object. Original IMPs are restored immediately; return values are never changed; no setter/update method or system write is used.\n"];
    [report appendFormat:@"Process: %@ bundle=%@\n",
     NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];

    void *gmHandle = dlopen("/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels", RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    Class gmClass = NSClassFromString(@"GMAvailabilityWrapper");
    Class vkClass = NSClassFromString(@"VKCGMAvailability");

    [report appendFormat:@"GenerativeModels=%@ VisionKitCore=%@ GM=%@ VK=%@\n",
     gmHandle ? @"OK" : @"FAILED",
     vkHandle ? @"OK" : @"FAILED",
     gmClass ? @"FOUND" : @"MISSING",
     vkClass ? @"FOUND" : @"MISSING"];

    if (!gmClass || !vkClass) {
        if (vkHandle) dlclose(vkHandle);
        if (gmHandle) dlclose(gmHandle);
        return report;
    }

    GEFreshCapturedCalls = [NSMutableArray array];
    SEL current1 = NSSelectorFromString(@"currentWithUseCaseIdentifiers:");
    SEL current2 = NSSelectorFromString(@"currentWithUseCaseIdentifiers:language:");
    IMP original1 = NULL;
    IMP original2 = NULL;

    BOOL hooked1 = GEFreshInstallHook(gmClass, current1, "q24@0:8@16", (IMP)GEFreshHookCurrent1, &original1, report);
    BOOL hooked2 = GEFreshInstallHook(gmClass, current2, "q32@0:8@16@24", (IMP)GEFreshHookCurrent2, &original2, report);
    GEFreshOriginalCurrent1 = (void *)original1;
    GEFreshOriginalCurrent2 = (void *)original2;

    @try {
        id fresh = [((id)vkClass) new];
        [report appendFormat:@"Fresh VKCGMAvailability object: %@\n", fresh ?: @"<nil>"];

        if (fresh) {
            for (NSString *selectorName in @[@"deviceIsEligibleForVI", @"supportsVI", @"enhancedSiriAvailable", @"enhancedSiriEnabled"]) {
                BOOL value = NO;
                NSString *error = nil;
                if (GEFreshReadBool(fresh, selectorName, &value, &error)) {
                    [report appendFormat:@"  fresh.%@ = %@\n", selectorName, value ? @"true" : @"false"];
                } else {
                    [report appendFormat:@"  fresh.%@ = <error: %@>\n", selectorName, error ?: @"unknown"];
                }
            }
        }
    } @catch (NSException *exception) {
        [report appendFormat:@"Fresh VK init exception: %@\n", exception.reason ?: exception.name];
    } @finally {
        if (hooked2) GEFreshRestoreHook(gmClass, current2, original2, report);
        if (hooked1) GEFreshRestoreHook(gmClass, current1, original1, report);
        GEFreshOriginalCurrent1 = NULL;
        GEFreshOriginalCurrent2 = NULL;
    }

    NSArray<NSDictionary *> *captured = nil;
    @synchronized (GEFreshCapturedCalls) {
        captured = [GEFreshCapturedCalls copy];
    }
    GEFreshCapturedCalls = nil;

    [report appendFormat:@"Captured GM current* calls during FRESH init: %lu\n", (unsigned long)captured.count];
    NSUInteger index = 0;
    for (NSDictionary *entry in captured) {
        index++;
        [report appendFormat:@"  call[%lu] selector=%@ identifiersClass=%@ language=%@ languageClass=%@\n",
         (unsigned long)index,
         entry[@"selector"] ?: @"<nil>",
         entry[@"identifiersClass"] ?: @"<nil>",
         entry[@"language"] ?: @"<nil>",
         entry[@"languageClass"] ?: @"<nil>"];
        [report appendFormat:@"    identifiers=%@\n", entry[@"identifiers"] ?: @[]];
    }

    BOOL classSupports = NO;
    NSString *classError = nil;
    if (GEFreshReadBool(vkClass, @"supportsVI", &classSupports, &classError)) {
        [report appendFormat:@"Post-restore +VKCGMAvailability.supportsVI = %@\n", classSupports ? @"true" : @"false"];
    } else {
        [report appendFormat:@"Post-restore +supportsVI = <error: %@>\n", classError ?: @"unknown"];
    }

    [report appendString:@"NOTE: the previous secure availability query returned Sandbox restriction / XPC error in this diagnostic app. Therefore secure-access=false from that earlier probe is not treated as evidence that Camera is granted access. Camera may receive a different privileged availability-service result.\n"];

    if (vkHandle) dlclose(vkHandle);
    if (gmHandle) dlclose(gmHandle);
    return report;
}
