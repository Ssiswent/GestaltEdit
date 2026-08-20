#import "GEVIFreshInitProbe.h"

#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>

static long long (*GEFreshOriginalCurrent1)(id, SEL, id) = NULL;
static long long (*GEFreshOriginalCurrent2)(id, SEL, id, id) = NULL;
static NSMutableArray<NSDictionary *> *GEFreshCapturedCalls;

static NSArray<NSString *> *GEFreshFlattenIdentifiers(id value)
{
    if (!value) return @[];
    if ([value isKindOfClass:[NSString class]]) return @[(NSString *)value];

    NSMutableArray<NSString *> *result = [NSMutableArray array];
    @try {
        if ([value conformsToProtocol:@protocol(NSFastEnumeration)]) {
            for (id item in value) {
                if ([item isKindOfClass:[NSString class]]) {
                    [result addObject:item];
                } else if (item) {
                    [result addObject:[item description] ?: @"<description unavailable>"];
                }
            }
        }
    } @catch (__unused NSException *exception) {
    }

    if (result.count == 0) {
        [result addObject:[value description] ?: @"<description unavailable>"];
    }
    return result;
}

static void GEFreshRecordCall(SEL selector, id identifiers, id language)
{
    if (!GEFreshCapturedCalls) return;
    NSDictionary *entry = @{
        @"selector": NSStringFromSelector(selector),
        @"identifiers": GEFreshFlattenIdentifiers(identifiers),
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
    GEFreshRecordCall(_cmd, identifiers, nil);
    return GEFreshOriginalCurrent1 ? GEFreshOriginalCurrent1(self, _cmd, identifiers) : -9999;
}

static long long GEFreshHookCurrent2(id self, SEL _cmd, id identifiers, id language)
{
    GEFreshRecordCall(_cmd, identifiers, language);
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

static BOOL GEFreshInvokeZeroBool(id target, NSString *name, BOOL *value, NSString **error)
{
    SEL selector = NSSelectorFromString(name);
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

static BOOL GEFreshInvokeTwoObjectBool(Class cls,
                                       NSString *name,
                                       id identifiers,
                                       id language,
                                       BOOL *value,
                                       NSString **error)
{
    SEL selector = NSSelectorFromString(name);
    if (![cls respondsToSelector:selector]) {
        if (error) *error = @"selector unavailable";
        return NO;
    }
    NSMethodSignature *signature = [cls methodSignatureForSelector:selector];
    if (!signature || signature.numberOfArguments != 4 ||
        !(signature.methodReturnType[0] == 'B' || signature.methodReturnType[0] == 'c') ||
        [signature getArgumentTypeAtIndex:2][0] != '@' ||
        [signature getArgumentTypeAtIndex:3][0] != '@') {
        if (error) *error = @"unexpected signature";
        return NO;
    }
    @try {
        NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
        invocation.target = cls;
        invocation.selector = selector;
        id arg1 = identifiers;
        id arg2 = language;
        [invocation setArgument:&arg1 atIndex:2];
        [invocation setArgument:&arg2 atIndex:3];
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

static BOOL GEFreshInvokeCurrent(Class cls,
                                 id identifiers,
                                 id language,
                                 long long *status,
                                 NSString **error)
{
    SEL selector = NSSelectorFromString(@"currentWithUseCaseIdentifiers:language:");
    if (![cls respondsToSelector:selector]) {
        if (error) *error = @"selector unavailable";
        return NO;
    }
    NSMethodSignature *signature = [cls methodSignatureForSelector:selector];
    if (!signature || signature.numberOfArguments != 4 || signature.methodReturnType[0] != 'q') {
        if (error) *error = @"unexpected signature";
        return NO;
    }
    @try {
        NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
        invocation.target = cls;
        invocation.selector = selector;
        id arg1 = identifiers;
        id arg2 = language;
        [invocation setArgument:&arg1 atIndex:2];
        [invocation setArgument:&arg2 atIndex:3];
        [invocation invoke];
        long long raw = 0;
        [invocation getReturnValue:&raw];
        if (status) *status = raw;
        return YES;
    } @catch (NSException *exception) {
        if (error) *error = exception.reason ?: exception.name;
        return NO;
    }
}

static BOOL GEFreshInvokeSecureAccess(Class cls,
                                      id identifiers,
                                      id language,
                                      BOOL *value,
                                      NSError *__autoreleasing * _Nullable *returnedError,
                                      NSString **invokeError)
{
    SEL selector = NSSelectorFromString(@"isUseCaseAccessNotGrantedSecureWithUseCaseIdentifiers:language:error:");
    if (![cls respondsToSelector:selector]) {
        if (invokeError) *invokeError = @"selector unavailable";
        return NO;
    }
    NSMethodSignature *signature = [cls methodSignatureForSelector:selector];
    if (!signature || signature.numberOfArguments != 5 ||
        !(signature.methodReturnType[0] == 'B' || signature.methodReturnType[0] == 'c')) {
        if (invokeError) *invokeError = @"unexpected signature";
        return NO;
    }
    @try {
        NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
        invocation.target = cls;
        invocation.selector = selector;
        id arg1 = identifiers;
        id arg2 = language;
        __autoreleasing NSError *nsError = nil;
        NSError *__autoreleasing *errorPointer = &nsError;
        [invocation setArgument:&arg1 atIndex:2];
        [invocation setArgument:&arg2 atIndex:3];
        [invocation setArgument:&errorPointer atIndex:4];
        [invocation invoke];
        unsigned char raw = 0;
        [invocation getReturnValue:&raw];
        if (value) *value = raw ? YES : NO;
        if (returnedError) *returnedError = nsError;
        return YES;
    } @catch (NSException *exception) {
        if (invokeError) *invokeError = exception.reason ?: exception.name;
        return NO;
    }
}

static void GEFreshAppendBoolQuery(NSMutableString *report,
                                   Class gmClass,
                                   NSString *label,
                                   NSString *selector,
                                   NSArray<NSString *> *identifiers)
{
    BOOL value = NO;
    NSString *error = nil;
    if (GEFreshInvokeTwoObjectBool(gmClass, selector, identifiers, nil, &value, &error)) {
        [report appendFormat:@"    %@ = %@\n", label, value ? @"true" : @"false"];
    } else {
        [report appendFormat:@"    %@ = <error: %@>\n", label, error ?: @"unknown"];
    }
}

static void GEFreshAppendPolicyGroup(NSMutableString *report,
                                     Class gmClass,
                                     NSArray<NSString *> *identifiers,
                                     NSString *label)
{
    [report appendFormat:@"  %@ identifiers=%@\n", label, identifiers];

    long long status = 0;
    NSString *error = nil;
    if (GEFreshInvokeCurrent(gmClass, identifiers, nil, &status, &error)) {
        [report appendFormat:@"    current.rawStatus = %lld\n", status];
    } else {
        [report appendFormat:@"    current = <error: %@>\n", error ?: @"unknown"];
    }

    GEFreshAppendBoolQuery(report, gmClass, @"enabled", @"enabledWithUseCaseIdentifiers:language:", identifiers);
    GEFreshAppendBoolQuery(report, gmClass, @"isUseCaseDisabled", @"isUseCaseDisabledWithUseCaseIdentifiers:language:", identifiers);
    GEFreshAppendBoolQuery(report, gmClass, @"assetIsNotReady", @"assetIsNotReadyWithUseCaseIdentifiers:language:", identifiers);
    GEFreshAppendBoolQuery(report, gmClass, @"partnerAllowedInUserLocaleRegion", @"useCasePartnerAllowedInUserLocaleRegionWithUseCaseIdentifiers:language:", identifiers);

    BOOL secureValue = NO;
    NSError *secureNSError = nil;
    NSString *invokeError = nil;
    if (GEFreshInvokeSecureAccess(gmClass, identifiers, nil, &secureValue, &secureNSError, &invokeError)) {
        if (secureNSError) {
            [report appendFormat:@"    accessNotGrantedSecure = INCONCLUSIVE (raw=%@; NSError=%@)\n",
             secureValue ? @"true" : @"false", secureNSError];
        } else {
            [report appendFormat:@"    accessNotGrantedSecure = %@\n", secureValue ? @"true" : @"false"];
        }
    } else {
        [report appendFormat:@"    accessNotGrantedSecure = <error: %@>\n", invokeError ?: @"unknown"];
    }
}

NSString *GEVIFreshInitProbeReport(void)
{
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"--- Fresh VK init / GM argument capture probe ---\n"];
    [report appendString:@"READ-ONLY / EPHEMERAL: records GM current* arguments only inside this app process, restores original IMPs, creates one temporary VKCGMAvailability instance, and calls query-only methods. No availability return value is modified and no system file/preference is written.\n"];
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

    id fresh = nil;
    @try {
        id allocated = ((id (*)(id, SEL))objc_msgSend)((id)vkClass, sel_registerName("alloc"));
        fresh = ((id (*)(id, SEL))objc_msgSend)(allocated, sel_registerName("init"));
        [report appendFormat:@"Fresh VKCGMAvailability init = %@\n", fresh ?: @"<nil>"];

        if (fresh) {
            NSArray<NSString *> *selectors = @[
                @"deviceIsEligibleForVI",
                @"supportsVI",
                @"enhancedSiriAvailable",
                @"enhancedSiriEnabled"
            ];
            for (NSString *selectorName in selectors) {
                BOOL value = NO;
                NSString *error = nil;
                if (GEFreshInvokeZeroBool(fresh, selectorName, &value, &error)) {
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
    NSMutableArray<NSArray<NSString *> *> *uniqueGroups = [NSMutableArray array];
    NSUInteger index = 0;
    for (NSDictionary *entry in captured) {
        index++;
        NSArray<NSString *> *identifiers = entry[@"identifiers"] ?: @[];
        [report appendFormat:@"  call[%lu] selector=%@ identifiersClass=%@ language=%@ languageClass=%@\n",
         (unsigned long)index,
         entry[@"selector"] ?: @"<nil>",
         entry[@"identifiersClass"] ?: @"<nil>",
         entry[@"language"] ?: @"<nil>",
         entry[@"languageClass"] ?: @"<nil>"];
        [report appendFormat:@"    identifiers=%@\n", identifiers];
        if (identifiers.count > 0 && ![uniqueGroups containsObject:identifiers]) {
            [uniqueGroups addObject:identifiers];
        }
    }

    [report appendString:@"\nPolicy matrix for exact captured group(s):\n"];
    if (uniqueGroups.count == 0) {
        [report appendString:@"  <no captured identifier group>\n"];
    } else {
        NSUInteger groupIndex = 0;
        for (NSArray<NSString *> *group in uniqueGroups) {
            groupIndex++;
            GEFreshAppendPolicyGroup(report, gmClass, group,
                                     [NSString stringWithFormat:@"capturedGroup[%lu]", (unsigned long)groupIndex]);
        }
    }

    [report appendString:@"\nKnown Camera VI groups for comparison:\n"];
    NSArray<NSArray<NSString *> *> *knownGroups = @[
        @[@"VisualIntelligence.gvicc"],
        @[@"GenerativeAssistant.visualIntelligenceCamera"],
        @[@"com.apple.VisualIntelligenceCamera.ImageSearch"],
        @[@"com.apple.VisualIntelligenceCamera.VisualLookup"],
        @[@"com.apple.Settings.AppleIntelligence"]
    ];
    NSUInteger knownIndex = 0;
    for (NSArray<NSString *> *group in knownGroups) {
        knownIndex++;
        GEFreshAppendPolicyGroup(report, gmClass, group,
                                 [NSString stringWithFormat:@"known[%lu]", (unsigned long)knownIndex]);
    }

    BOOL deviceEligible = NO;
    NSString *deviceError = nil;
    if (GEFreshInvokeZeroBool(gmClass, @"isDeviceEligible", &deviceEligible, &deviceError)) {
        [report appendFormat:@"\nGM +isDeviceEligible = %@\n", deviceEligible ? @"true" : @"false"];
    } else {
        [report appendFormat:@"\nGM +isDeviceEligible = <error: %@>\n", deviceError ?: @"unknown"];
    }

    [report appendString:@"NOTE: accessNotGrantedSecure is not treated as false when its NSError is non-nil. A sandbox/XPC error means this unprivileged diagnostic process cannot reproduce Camera's secure availability-service context.\n"];

    if (vkHandle) dlclose(vkHandle);
    if (gmHandle) dlclose(gmHandle);
    return report;
}
