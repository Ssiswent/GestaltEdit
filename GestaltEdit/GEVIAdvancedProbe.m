#import "GEVIAdvancedProbe.h"

#import <dlfcn.h>
#import <objc/runtime.h>

static long long (*GEOriginalGMCurrent1)(id, SEL, id) = NULL;
static long long (*GEOriginalGMCurrent2)(id, SEL, id, id) = NULL;
static NSMutableArray<NSDictionary *> *GECapturedGMCalls;

static NSArray<NSString *> *GEFlattenIdentifiers(id value)
{
    if (!value) return @[];
    if ([value isKindOfClass:[NSString class]]) return @[(NSString *)value];

    NSMutableArray<NSString *> *items = [NSMutableArray array];
    if ([value isKindOfClass:[NSArray class]] || [value isKindOfClass:[NSSet class]] ||
        [value conformsToProtocol:@protocol(NSFastEnumeration)]) {
        @try {
            for (id item in value) {
                if ([item isKindOfClass:[NSString class]]) {
                    [items addObject:item];
                } else if (item) {
                    [items addObject:[item description] ?: @"<description unavailable>"];
                }
            }
        } @catch (__unused NSException *exception) {
        }
    }

    if (items.count == 0) {
        [items addObject:[value description] ?: @"<description unavailable>"];
    }
    return items;
}

static void GERecordGMCall(SEL selector, id identifiers, id language)
{
    if (!GECapturedGMCalls) return;
    NSArray<NSString *> *flat = GEFlattenIdentifiers(identifiers);
    NSString *languageDescription = language ? ([language description] ?: @"<description unavailable>") : @"<nil>";
    NSDictionary *entry = @{
        @"selector": NSStringFromSelector(selector),
        @"identifiers": flat,
        @"identifiersClass": identifiers ? NSStringFromClass([identifiers class]) : @"<nil>",
        @"language": languageDescription,
        @"languageClass": language ? NSStringFromClass([language class]) : @"<nil>"
    };
    @synchronized (GECapturedGMCalls) {
        [GECapturedGMCalls addObject:entry];
    }
}

static long long GEHookGMCurrent1(id self, SEL _cmd, id identifiers)
{
    GERecordGMCall(_cmd, identifiers, nil);
    return GEOriginalGMCurrent1 ? GEOriginalGMCurrent1(self, _cmd, identifiers) : -9999;
}

static long long GEHookGMCurrent2(id self, SEL _cmd, id identifiers, id language)
{
    GERecordGMCall(_cmd, identifiers, language);
    return GEOriginalGMCurrent2 ? GEOriginalGMCurrent2(self, _cmd, identifiers, language) : -9999;
}

static BOOL GEHookClassMethodIfExact(Class cls,
                                     SEL selector,
                                     const char *expectedEncoding,
                                     IMP replacement,
                                     IMP *originalOut,
                                     NSMutableString *report)
{
    Method method = class_getClassMethod(cls, selector);
    if (!method) {
        [report appendFormat:@"  hook %@: selector unavailable\n", NSStringFromSelector(selector)];
        return NO;
    }

    const char *encoding = method_getTypeEncoding(method);
    if (!encoding || strcmp(encoding, expectedEncoding) != 0) {
        [report appendFormat:@"  hook %@: skipped, encoding=%s expected=%s\n",
         NSStringFromSelector(selector), encoding ?: "<nil>", expectedEncoding];
        return NO;
    }

    IMP original = method_getImplementation(method);
    if (!original) {
        [report appendFormat:@"  hook %@: original IMP unavailable\n", NSStringFromSelector(selector)];
        return NO;
    }

    *originalOut = original;
    method_setImplementation(method, replacement);
    [report appendFormat:@"  hook %@: installed temporarily\n", NSStringFromSelector(selector)];
    return YES;
}

static void GERestoreClassMethod(Class cls, SEL selector, IMP original, NSMutableString *report)
{
    if (!cls || !selector || !original) return;
    Method method = class_getClassMethod(cls, selector);
    if (!method) return;
    method_setImplementation(method, original);
    [report appendFormat:@"  hook %@: restored original IMP\n", NSStringFromSelector(selector)];
}

static BOOL GEInvokeZeroArgBool(id target, NSString *selectorName, BOOL *outValue, NSString **outError)
{
    SEL selector = NSSelectorFromString(selectorName);
    if (![target respondsToSelector:selector]) {
        if (outError) *outError = @"selector unavailable";
        return NO;
    }
    NSMethodSignature *sig = [target methodSignatureForSelector:selector];
    if (!sig || sig.numberOfArguments != 2 || !(sig.methodReturnType[0] == 'B' || sig.methodReturnType[0] == 'c')) {
        if (outError) *outError = [NSString stringWithFormat:@"unexpected signature: %s", sig ? sig.methodReturnType : "<nil>"];
        return NO;
    }

    @try {
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.target = target;
        inv.selector = selector;
        [inv invoke];
        unsigned char value = 0;
        [inv getReturnValue:&value];
        if (outValue) *outValue = value ? YES : NO;
        return YES;
    } @catch (NSException *exception) {
        if (outError) *outError = [NSString stringWithFormat:@"exception: %@", exception.reason ?: exception.name];
        return NO;
    }
}

static BOOL GEInvokeTwoObjectBool(Class cls,
                                  NSString *selectorName,
                                  id arg1,
                                  id arg2,
                                  BOOL *outValue,
                                  NSString **outError)
{
    SEL selector = NSSelectorFromString(selectorName);
    if (![cls respondsToSelector:selector]) {
        if (outError) *outError = @"selector unavailable";
        return NO;
    }
    NSMethodSignature *sig = [cls methodSignatureForSelector:selector];
    if (!sig || sig.numberOfArguments != 4 || !(sig.methodReturnType[0] == 'B' || sig.methodReturnType[0] == 'c') ||
        [sig getArgumentTypeAtIndex:2][0] != '@' || [sig getArgumentTypeAtIndex:3][0] != '@') {
        if (outError) *outError = @"unexpected signature";
        return NO;
    }

    @try {
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.target = cls;
        inv.selector = selector;
        id a1 = arg1;
        id a2 = arg2;
        [inv setArgument:&a1 atIndex:2];
        [inv setArgument:&a2 atIndex:3];
        [inv invoke];
        unsigned char value = 0;
        [inv getReturnValue:&value];
        if (outValue) *outValue = value ? YES : NO;
        return YES;
    } @catch (NSException *exception) {
        if (outError) *outError = [NSString stringWithFormat:@"exception: %@", exception.reason ?: exception.name];
        return NO;
    }
}

static BOOL GEInvokeSecureAccessBool(Class cls,
                                     id identifiers,
                                     id language,
                                     BOOL *outValue,
                                     NSString **returnedNSError,
                                     NSString **outError)
{
    SEL selector = NSSelectorFromString(@"isUseCaseAccessNotGrantedSecureWithUseCaseIdentifiers:language:error:");
    if (![cls respondsToSelector:selector]) {
        if (outError) *outError = @"selector unavailable";
        return NO;
    }
    NSMethodSignature *sig = [cls methodSignatureForSelector:selector];
    if (!sig || sig.numberOfArguments != 5 || !(sig.methodReturnType[0] == 'B' || sig.methodReturnType[0] == 'c') ||
        [sig getArgumentTypeAtIndex:2][0] != '@' || [sig getArgumentTypeAtIndex:3][0] != '@' ||
        [sig getArgumentTypeAtIndex:4][0] != '^') {
        if (outError) *outError = @"unexpected signature";
        return NO;
    }

    @try {
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.target = cls;
        inv.selector = selector;
        id a1 = identifiers;
        id a2 = language;
        __autoreleasing NSError *nsError = nil;
        NSError *__autoreleasing *errorPtr = &nsError;
        [inv setArgument:&a1 atIndex:2];
        [inv setArgument:&a2 atIndex:3];
        [inv setArgument:&errorPtr atIndex:4];
        [inv invoke];
        unsigned char value = 0;
        [inv getReturnValue:&value];
        if (outValue) *outValue = value ? YES : NO;
        if (returnedNSError) *returnedNSError = nsError ? [nsError description] : @"<nil>";
        return YES;
    } @catch (NSException *exception) {
        if (outError) *outError = [NSString stringWithFormat:@"exception: %@", exception.reason ?: exception.name];
        return NO;
    }
}

static BOOL GEInvokeCurrent(Class cls, id identifiers, id language, long long *outStatus, NSString **outError)
{
    SEL selector = NSSelectorFromString(@"currentWithUseCaseIdentifiers:language:");
    if (![cls respondsToSelector:selector]) {
        if (outError) *outError = @"selector unavailable";
        return NO;
    }
    NSMethodSignature *sig = [cls methodSignatureForSelector:selector];
    if (!sig || sig.numberOfArguments != 4 || sig.methodReturnType[0] != 'q' ||
        [sig getArgumentTypeAtIndex:2][0] != '@' || [sig getArgumentTypeAtIndex:3][0] != '@') {
        if (outError) *outError = @"unexpected signature";
        return NO;
    }

    @try {
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.target = cls;
        inv.selector = selector;
        id a1 = identifiers;
        id a2 = language;
        [inv setArgument:&a1 atIndex:2];
        [inv setArgument:&a2 atIndex:3];
        [inv invoke];
        long long status = 0;
        [inv getReturnValue:&status];
        if (outStatus) *outStatus = status;
        return YES;
    } @catch (NSException *exception) {
        if (outError) *outError = [NSString stringWithFormat:@"exception: %@", exception.reason ?: exception.name];
        return NO;
    }
}

static void GEAppendBoolQuery(NSMutableString *report,
                              Class gmClass,
                              NSString *label,
                              NSString *selector,
                              id identifiers,
                              id language)
{
    BOOL value = NO;
    NSString *error = nil;
    if (GEInvokeTwoObjectBool(gmClass, selector, identifiers, language, &value, &error)) {
        [report appendFormat:@"    %@ = %@\n", label, value ? @"true" : @"false"];
    } else {
        [report appendFormat:@"    %@ = <error: %@>\n", label, error ?: @"unknown"];
    }
}

NSString *GEVIAdvancedProbeReport(void)
{
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"--- Advanced GM / VisionKit VI probe ---\n"];
    [report appendString:@"READ-ONLY / EPHEMERAL: temporarily replaces only GMAvailabilityWrapper current* IMPs to record arguments, restores them immediately, and calls query-only selectors. No return values are changed, no setter/update method is called, and no system preference/file is written.\n"];

    void *gmHandle = dlopen("/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels", RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    [report appendFormat:@"GenerativeModels dlopen: %@\n", gmHandle ? @"OK" : @"FAILED"];
    [report appendFormat:@"VisionKitCore dlopen: %@\n", vkHandle ? @"OK" : @"FAILED"];

    Class gmClass = NSClassFromString(@"GMAvailabilityWrapper");
    Class vkClass = NSClassFromString(@"VKCGMAvailability");
    [report appendFormat:@"GMAvailabilityWrapper: %@\n", gmClass ? @"FOUND" : @"MISSING"];
    [report appendFormat:@"VKCGMAvailability: %@\n", vkClass ? @"FOUND" : @"MISSING"];

    if (!gmClass || !vkClass) {
        if (vkHandle) dlclose(vkHandle);
        if (gmHandle) dlclose(gmHandle);
        return report;
    }

    GECapturedGMCalls = [NSMutableArray array];
    SEL current1 = NSSelectorFromString(@"currentWithUseCaseIdentifiers:");
    SEL current2 = NSSelectorFromString(@"currentWithUseCaseIdentifiers:language:");
    IMP original1 = NULL;
    IMP original2 = NULL;

    [report appendString:@"\nTemporary argument capture:\n"];
    BOOL hooked1 = GEHookClassMethodIfExact(gmClass, current1, "q24@0:8@16", (IMP)GEHookGMCurrent1, &original1, report);
    BOOL hooked2 = GEHookClassMethodIfExact(gmClass, current2, "q32@0:8@16@24", (IMP)GEHookGMCurrent2, &original2, report);
    GEOriginalGMCurrent1 = (void *)original1;
    GEOriginalGMCurrent2 = (void *)original2;

    [report appendString:@"\nVKCGMAvailability getters while capture is active:\n"];
    NSArray<NSString *> *vkSelectors = @[
        @"supportsVI",
        @"deviceIsEligibleForVI",
        @"enhancedSiriAvailable",
        @"enhancedSiriEnabled"
    ];
    for (NSString *selectorName in vkSelectors) {
        BOOL value = NO;
        NSString *error = nil;
        if (GEInvokeZeroArgBool(vkClass, selectorName, &value, &error)) {
            [report appendFormat:@"  +%@ = %@\n", selectorName, value ? @"true" : @"false"];
        } else {
            [report appendFormat:@"  +%@ = <error: %@>\n", selectorName, error ?: @"unknown"];
        }
    }

    if (hooked2) GERestoreClassMethod(gmClass, current2, original2, report);
    if (hooked1) GERestoreClassMethod(gmClass, current1, original1, report);
    GEOriginalGMCurrent1 = NULL;
    GEOriginalGMCurrent2 = NULL;

    NSArray<NSDictionary *> *captured;
    @synchronized (GECapturedGMCalls) {
        captured = [GECapturedGMCalls copy];
    }
    GECapturedGMCalls = nil;

    [report appendFormat:@"\nCaptured GM current* calls: %lu\n", (unsigned long)captured.count];
    NSMutableOrderedSet<NSString *> *capturedIdentifiers = [NSMutableOrderedSet orderedSet];
    NSUInteger callIndex = 0;
    for (NSDictionary *entry in captured) {
        callIndex++;
        NSArray<NSString *> *ids = entry[@"identifiers"] ?: @[];
        [report appendFormat:@"  call[%lu] selector=%@ identifiersClass=%@ language=%@ languageClass=%@\n",
         (unsigned long)callIndex,
         entry[@"selector"] ?: @"<nil>",
         entry[@"identifiersClass"] ?: @"<nil>",
         entry[@"language"] ?: @"<nil>",
         entry[@"languageClass"] ?: @"<nil>"];
        [report appendFormat:@"    identifiers=%@\n", ids];
        for (NSString *identifier in ids) {
            if (identifier.length > 0) [capturedIdentifiers addObject:identifier];
        }
    }

    NSMutableOrderedSet<NSString *> *allUseCases = [NSMutableOrderedSet orderedSetWithArray:@[
        @"com.apple.Settings.AppleIntelligence",
        @"VisualIntelligence.gvicc",
        @"GenerativeAssistant.visualIntelligenceCamera",
        @"com.apple.VisualIntelligenceCamera.ImageSearch",
        @"com.apple.VisualIntelligenceCamera.VisualLookup"
    ]];
    [allUseCases addObjectsFromArray:capturedIdentifiers.array];

    [report appendString:@"\nPer-use-case policy matrix (system language / nil):\n"];
    for (NSString *useCase in allUseCases) {
        id identifiers = @[useCase];
        id language = nil;
        [report appendFormat:@"  useCase=%@\n", useCase];

        long long status = 0;
        NSString *error = nil;
        if (GEInvokeCurrent(gmClass, identifiers, language, &status, &error)) {
            [report appendFormat:@"    current.rawStatus = %lld\n", status];
        } else {
            [report appendFormat:@"    current.rawStatus = <error: %@>\n", error ?: @"unknown"];
        }

        BOOL deviceEligible = NO;
        error = nil;
        if (GEInvokeZeroArgBool(gmClass, @"isDeviceEligible", &deviceEligible, &error)) {
            [report appendFormat:@"    isDeviceEligible = %@\n", deviceEligible ? @"true" : @"false"];
        } else {
            [report appendFormat:@"    isDeviceEligible = <error: %@>\n", error ?: @"unknown"];
        }

        GEAppendBoolQuery(report, gmClass, @"enabled", @"enabledWithUseCaseIdentifiers:language:", identifiers, language);
        GEAppendBoolQuery(report, gmClass, @"isUseCaseDisabled", @"isUseCaseDisabledWithUseCaseIdentifiers:language:", identifiers, language);
        GEAppendBoolQuery(report, gmClass, @"assetIsNotReady", @"assetIsNotReadyWithUseCaseIdentifiers:language:", identifiers, language);
        GEAppendBoolQuery(report, gmClass, @"partnerAllowedInUserLocaleRegion", @"useCasePartnerAllowedInUserLocaleRegionWithUseCaseIdentifiers:language:", identifiers, language);

        BOOL accessNotGranted = NO;
        NSString *returnedNSError = nil;
        error = nil;
        if (GEInvokeSecureAccessBool(gmClass, identifiers, language, &accessNotGranted, &returnedNSError, &error)) {
            [report appendFormat:@"    accessNotGrantedSecure = %@\n", accessNotGranted ? @"true" : @"false"];
            [report appendFormat:@"    accessNotGrantedSecure.error = %@\n", returnedNSError ?: @"<nil>"];
        } else {
            [report appendFormat:@"    accessNotGrantedSecure = <error: %@>\n", error ?: @"unknown"];
        }
    }

    [report appendString:@"\nProbe complete: temporary IMP hooks were restored before the policy matrix was queried.\n"];

    if (vkHandle) dlclose(vkHandle);
    if (gmHandle) dlclose(gmHandle);
    return report;
}
