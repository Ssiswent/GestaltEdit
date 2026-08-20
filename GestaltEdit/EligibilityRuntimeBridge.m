#import "EligibilityRuntimeBridge.h"

#import <dlfcn.h>
#import <objc/runtime.h>
#import <stdint.h>
#import <stdlib.h>

// Keep this bridge self-contained: use opaque XPC pointers and dynamically
// resolve all private/system symbols instead of linking private headers.
typedef void *GEXPCObject;
typedef int (*GEGetXPCFn)(GEXPCObject *outObject);
typedef int (*GEGetDomainAnswerFn)(uint64_t domain,
                                   uint64_t *answer,
                                   uint64_t *source,
                                   GEXPCObject *status,
                                   GEXPCObject *context);
typedef char *(*GEXPCDescriptionFn)(GEXPCObject object);

static NSString *GEAnswerName(uint64_t answer)
{
    switch (answer) {
        case 0: return @"INVALID";
        case 1: return @"NOT_YET_AVAILABLE";
        case 2: return @"NOT_ELIGIBLE";
        case 3: return @"MAYBE";
        case 4: return @"ELIGIBLE";
        default: return [NSString stringWithFormat:@"UNKNOWN(%llu)", answer];
    }
}

static NSString *GESourceName(uint64_t source)
{
    switch (source) {
        case 0: return @"INVALID";
        case 1: return @"COMPUTED";
        case 2: return @"FORCED";
        default: return [NSString stringWithFormat:@"UNKNOWN(%llu)", source];
    }
}

static NSString *GEDomainKnownName(uint64_t domain)
{
    switch (domain) {
        case 39:  return @"STRONTIUM";
        case 122: return @"GREYMATTER";
        case 130: return @"FOUNDATION_MODELS";
        case 155: return @"SIRI_MODE";
        default:  return nil;
    }
}

static NSString *GEDescribeXPC(GEXPCObject object, GEXPCDescriptionFn copyDescription)
{
    if (!object) return @"<nil>";
    if (!copyDescription) {
        return [NSString stringWithFormat:@"<xpc %p; xpc_copy_description unavailable>", object];
    }

    char *description = copyDescription(object);
    if (!description) return @"<description unavailable>";
    NSString *string = [NSString stringWithUTF8String:description] ?: @"<invalid UTF-8 description>";
    free(description);
    return string;
}

static void GEAppendXPCProbe(NSMutableString *report,
                             NSString *name,
                             GEGetXPCFn function,
                             GEXPCDescriptionFn copyDescription)
{
    if (!function) {
        [report appendFormat:@"%@ = <symbol unavailable>\n", name];
        return;
    }

    GEXPCObject object = NULL;
    int result = function(&object);
    [report appendFormat:@"%@ rc=%d\n", name, result];
    if (object) {
        [report appendFormat:@"%@ value=%@\n", name, GEDescribeXPC(object, copyDescription)];
    } else {
        [report appendFormat:@"%@ value=<nil>\n", name];
    }
}

static BOOL GEStatusContainsRelevantInput(NSString *statusDescription)
{
    if (statusDescription.length == 0) return NO;
    return [statusDescription containsString:@"OS_ELIGIBILITY_INPUT_COUNTRY_LOCATION"] ||
           [statusDescription containsString:@"OS_ELIGIBILITY_INPUT_DEVICE_REGION_CODE"] ||
           [statusDescription containsString:@"OS_ELIGIBILITY_INPUT_COUNTRY_BILLING"] ||
           [statusDescription containsString:@"OS_ELIGIBILITY_INPUT_CHINA_CELLULAR"];
}

static void GEAppendDomainProbe(NSMutableString *report,
                                GEGetDomainAnswerFn getDomainAnswer,
                                GEXPCDescriptionFn copyDescription,
                                uint64_t domain,
                                BOOL includeStatus,
                                BOOL includeContext)
{
    uint64_t answer = 0;
    uint64_t source = 0;
    GEXPCObject status = NULL;
    GEXPCObject context = NULL;
    int rc = getDomainAnswer(domain, &answer, &source, &status, &context);

    NSString *knownName = GEDomainKnownName(domain);
    if (knownName) {
        [report appendFormat:@"%@(%llu): rc=%d answer=%@ source=%@\n",
         knownName, domain, rc, GEAnswerName(answer), GESourceName(source)];
    } else {
        [report appendFormat:@"DOMAIN(%llu): rc=%d answer=%@ source=%@\n",
         domain, rc, GEAnswerName(answer), GESourceName(source)];
    }

    if (includeStatus) {
        [report appendFormat:@"  status=%@\n", GEDescribeXPC(status, copyDescription)];
    }
    if (includeContext) {
        [report appendFormat:@"  context=%@\n", GEDescribeXPC(context, copyDescription)];
    }
}

static const char *GESkipObjCTypeQualifiers(const char *type)
{
    if (!type) return "";
    while (*type == 'r' || *type == 'n' || *type == 'N' || *type == 'o' ||
           *type == 'O' || *type == 'R' || *type == 'V') {
        type++;
    }
    return type;
}

static BOOL GETypeIsObject(const char *type)
{
    type = GESkipObjCTypeQualifiers(type);
    return type[0] == '@';
}

static BOOL GETypeIsBool(const char *type)
{
    type = GESkipObjCTypeQualifiers(type);
    return type[0] == 'B' || type[0] == 'c' || type[0] == 'C';
}

static BOOL GETypeIsInteger(const char *type)
{
    type = GESkipObjCTypeQualifiers(type);
    switch (type[0]) {
        case 'q': case 'Q': case 'l': case 'L': case 'i': case 'I':
        case 's': case 'S': case 'c': case 'C':
            return YES;
        default:
            return NO;
    }
}

static void GEAppendMethodList(NSMutableString *report, Class cls, BOOL classMethods)
{
    Class targetClass = classMethods ? object_getClass(cls) : cls;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(targetClass, &count);
    [report appendFormat:@"%@ methods (%u):\n", classMethods ? @"class" : @"instance", count];
    for (unsigned int i = 0; i < count; i++) {
        SEL selector = method_getName(methods[i]);
        const char *types = method_getTypeEncoding(methods[i]);
        [report appendFormat:@"  %@  types=%s\n",
         NSStringFromSelector(selector),
         types ?: "<nil>"];
    }
    free(methods);
}

static void GEAppendClassLayout(NSMutableString *report, Class cls)
{
    unsigned int propertyCount = 0;
    objc_property_t *properties = class_copyPropertyList(cls, &propertyCount);
    [report appendFormat:@"properties (%u):\n", propertyCount];
    for (unsigned int i = 0; i < propertyCount; i++) {
        const char *name = property_getName(properties[i]);
        const char *attributes = property_getAttributes(properties[i]);
        [report appendFormat:@"  %s  attrs=%s\n",
         name ?: "<nil>", attributes ?: "<nil>"];
    }
    free(properties);

    unsigned int ivarCount = 0;
    Ivar *ivars = class_copyIvarList(cls, &ivarCount);
    [report appendFormat:@"ivars (%u):\n", ivarCount];
    for (unsigned int i = 0; i < ivarCount; i++) {
        const char *name = ivar_getName(ivars[i]);
        const char *type = ivar_getTypeEncoding(ivars[i]);
        [report appendFormat:@"  %s  type=%s offset=%td\n",
         name ?: "<nil>", type ?: "<nil>", ivar_getOffset(ivars[i])];
    }
    free(ivars);
}

static BOOL GEInvokeZeroArgBool(id target, SEL selector, BOOL *value, NSString **error)
{
    if (![target respondsToSelector:selector]) {
        if (error) *error = @"selector unavailable";
        return NO;
    }

    NSMethodSignature *signature = [target methodSignatureForSelector:selector];
    if (!signature || signature.numberOfArguments != 2 || !GETypeIsBool(signature.methodReturnType)) {
        if (error) {
            *error = [NSString stringWithFormat:@"unexpected signature: %@",
                      signature ? [NSString stringWithUTF8String:signature.methodReturnType] : @"<nil>"];
        }
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
        if (error) *error = [NSString stringWithFormat:@"exception: %@", exception.reason ?: exception.name];
        return NO;
    }
}

static BOOL GEInvokeZeroArgObject(id target, SEL selector, id __autoreleasing *value, NSString **error)
{
    if (![target respondsToSelector:selector]) {
        if (error) *error = @"selector unavailable";
        return NO;
    }

    NSMethodSignature *signature = [target methodSignatureForSelector:selector];
    if (!signature || signature.numberOfArguments != 2 || !GETypeIsObject(signature.methodReturnType)) {
        if (error) *error = @"unexpected signature";
        return NO;
    }

    @try {
        NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
        invocation.target = target;
        invocation.selector = selector;
        [invocation invoke];
        __unsafe_unretained id raw = nil;
        [invocation getReturnValue:&raw];
        if (value) *value = raw;
        return YES;
    } @catch (NSException *exception) {
        if (error) *error = [NSString stringWithFormat:@"exception: %@", exception.reason ?: exception.name];
        return NO;
    }
}

static BOOL GEInvokeGMCurrent(Class gmClass,
                              NSString *useCase,
                              long long *status,
                              NSString **selectorUsed,
                              NSString **error)
{
    // iOS 26 runtime headers describe both selectors as returning long long and
    // taking object arguments. Runtime encoding is checked again before invoking.
    SEL selectors[] = {
        NSSelectorFromString(@"currentWithUseCaseIdentifiers:language:"),
        NSSelectorFromString(@"currentWithUseCaseIdentifiers:")
    };

    for (NSUInteger index = 0; index < 2; index++) {
        SEL selector = selectors[index];
        if (![gmClass respondsToSelector:selector]) continue;

        NSMethodSignature *signature = [gmClass methodSignatureForSelector:selector];
        NSUInteger expectedArgumentCount = index == 0 ? 4 : 3;
        if (!signature || signature.numberOfArguments != expectedArgumentCount ||
            !GETypeIsInteger(signature.methodReturnType) ||
            !GETypeIsObject([signature getArgumentTypeAtIndex:2])) {
            continue;
        }
        if (index == 0 && !GETypeIsObject([signature getArgumentTypeAtIndex:3])) {
            continue;
        }

        @try {
            NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
            invocation.target = gmClass;
            invocation.selector = selector;

            // Compiler-generated callers use a constant collection. NSArray is
            // intentionally used as the least surprising Foundation collection.
            id identifiers = @[useCase];
            [invocation setArgument:&identifiers atIndex:2];
            if (index == 0) {
                id language = nil; // system language, matching Apple's language:0 call path
                [invocation setArgument:&language atIndex:3];
            }

            [invocation invoke];
            uint64_t raw = 0;
            NSUInteger length = MIN(signature.methodReturnLength, sizeof(raw));
            if (length > 0) {
                uint8_t buffer[sizeof(uint64_t)] = {0};
                [invocation getReturnValue:buffer];
                memcpy(&raw, buffer, length);
            }
            if (status) *status = (long long)raw;
            if (selectorUsed) *selectorUsed = NSStringFromSelector(selector);
            return YES;
        } @catch (NSException *exception) {
            if (error) *error = [NSString stringWithFormat:@"exception: %@", exception.reason ?: exception.name];
            return NO;
        }
    }

    if (error) *error = @"no ABI-compatible currentWithUseCaseIdentifiers selector";
    return NO;
}

static void GEAppendGMAndVisionKitProbe(NSMutableString *report)
{
    [report appendString:@"\n--- GM / VisionKit runtime probe ---\n"];
    [report appendString:@"NO PERSISTENT WRITES: loads private frameworks, enumerates Objective-C runtime metadata, calls VKCGMAvailability read getters, and queries GMAvailabilityWrapper current/isDeviceEligible/wasEverAvailable. updateAvailability, setters and preference writes are NOT called.\n"];

    const char *gmPath = "/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels";
    const char *vkPath = "/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore";
    void *gmHandle = dlopen(gmPath, RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen(vkPath, RTLD_NOW | RTLD_LOCAL);
    [report appendFormat:@"GenerativeModels dlopen: %@\n", gmHandle ? @"OK" : @"FAILED"];
    if (!gmHandle) {
        const char *error = dlerror();
        [report appendFormat:@"  error=%s\n", error ?: "unknown"];
    }
    [report appendFormat:@"VisionKitCore dlopen: %@\n", vkHandle ? @"OK" : @"FAILED"];
    if (!vkHandle) {
        const char *error = dlerror();
        [report appendFormat:@"  error=%s\n", error ?: "unknown"];
    }

    Class gmClass = NSClassFromString(@"GMAvailabilityWrapper");
    Class vkClass = NSClassFromString(@"VKCGMAvailability");

    [report appendFormat:@"GMAvailabilityWrapper class: %@\n", gmClass ? NSStringFromClass(gmClass) : @"<nil>"];
    if (gmClass) {
        GEAppendMethodList(report, gmClass, YES);
        GEAppendMethodList(report, gmClass, NO);
        GEAppendClassLayout(report, gmClass);
    }

    [report appendFormat:@"VKCGMAvailability class: %@\n", vkClass ? NSStringFromClass(vkClass) : @"<nil>"];
    if (vkClass) {
        GEAppendMethodList(report, vkClass, YES);
        GEAppendMethodList(report, vkClass, NO);
        GEAppendClassLayout(report, vkClass);

        [report appendString:@"\nVKCGMAvailability direct read getters:\n"];
        BOOL boolValue = NO;
        NSString *error = nil;
        if (GEInvokeZeroArgBool(vkClass, NSSelectorFromString(@"deviceIsEligibleForVI"), &boolValue, &error)) {
            [report appendFormat:@"  +deviceIsEligibleForVI = %@\n", boolValue ? @"true" : @"false"];
        } else {
            [report appendFormat:@"  +deviceIsEligibleForVI = <error: %@>\n", error ?: @"unknown"];
        }

        error = nil;
        if (GEInvokeZeroArgBool(vkClass, NSSelectorFromString(@"supportsVI"), &boolValue, &error)) {
            [report appendFormat:@"  +supportsVI = %@\n", boolValue ? @"true" : @"false"];
        } else {
            [report appendFormat:@"  +supportsVI = <error: %@>\n", error ?: @"unknown"];
        }

        id listener = nil;
        error = nil;
        if (GEInvokeZeroArgObject(vkClass, NSSelectorFromString(@"sharedListener"), &listener, &error)) {
            [report appendFormat:@"  +sharedListener = %@\n", listener ?: @"<nil>"];
            if (listener) {
                error = nil;
                if (GEInvokeZeroArgBool(listener, NSSelectorFromString(@"deviceIsEligibleForVI"), &boolValue, &error)) {
                    [report appendFormat:@"  listener.deviceIsEligibleForVI = %@\n", boolValue ? @"true" : @"false"];
                } else {
                    [report appendFormat:@"  listener.deviceIsEligibleForVI = <error: %@>\n", error ?: @"unknown"];
                }
                error = nil;
                if (GEInvokeZeroArgBool(listener, NSSelectorFromString(@"supportsVI"), &boolValue, &error)) {
                    [report appendFormat:@"  listener.supportsVI = %@\n", boolValue ? @"true" : @"false"];
                } else {
                    [report appendFormat:@"  listener.supportsVI = <error: %@>\n", error ?: @"unknown"];
                }
            }
        } else {
            [report appendFormat:@"  +sharedListener = <error: %@>\n", error ?: @"unknown"];
        }
    }

    if (gmClass) {
        [report appendString:@"\nGMAvailabilityWrapper per-use-case query:\n"];
        NSArray<NSString *> *useCases = @[
            @"com.apple.Settings.AppleIntelligence",
            @"VisualIntelligence.gvicc",
            @"GenerativeAssistant.visualIntelligenceCamera",
            @"com.apple.VisualIntelligenceCamera.ImageSearch",
            @"com.apple.VisualIntelligenceCamera.VisualLookup"
        ];

        for (NSString *useCase in useCases) {
            [report appendFormat:@"  useCase=%@\n", useCase];
            long long currentStatus = 0;
            NSString *selectorUsed = nil;
            NSString *error = nil;
            if (GEInvokeGMCurrent(gmClass, useCase, &currentStatus, &selectorUsed, &error)) {
                [report appendFormat:@"    %@ -> rawStatus=%lld\n", selectorUsed, currentStatus];

                BOOL boolValue = NO;
                error = nil;
                if (GEInvokeZeroArgBool(gmClass, NSSelectorFromString(@"isDeviceEligible"), &boolValue, &error)) {
                    [report appendFormat:@"    +isDeviceEligible = %@\n", boolValue ? @"true" : @"false"];
                } else {
                    [report appendFormat:@"    +isDeviceEligible = <error: %@>\n", error ?: @"unknown"];
                }

                error = nil;
                if (GEInvokeZeroArgBool(gmClass, NSSelectorFromString(@"wasEverAvailable"), &boolValue, &error)) {
                    [report appendFormat:@"    +wasEverAvailable = %@\n", boolValue ? @"true" : @"false"];
                } else {
                    [report appendFormat:@"    +wasEverAvailable = <error: %@>\n", error ?: @"unknown"];
                }
            } else {
                [report appendFormat:@"    query skipped/failed: %@\n", error ?: @"unknown"];
            }
        }
    }

    if (vkHandle) dlclose(vkHandle);
    if (gmHandle) dlclose(gmHandle);
}

NSString *GEEligibilityRuntimeReport(void)
{
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"--- libsystem_eligibility runtime API ---\n"];
    [report appendString:@"READ-ONLY: only get_state_dump / get_all_domain_answers / get_internal_state / get_domain_answer are called.\n"];

    const char *paths[] = {
        "/usr/lib/system/libsystem_eligibility.dylib",
        "/usr/lib/libsystem_eligibility.dylib"
    };

    void *handle = NULL;
    const char *loadedPath = NULL;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        handle = dlopen(paths[i], RTLD_NOW | RTLD_LOCAL);
        if (handle) {
            loadedPath = paths[i];
            break;
        }
    }

    if (!handle) {
        const char *error = dlerror();
        [report appendFormat:@"dlopen failed: %s\n", error ?: "unknown error"];
        GEAppendGMAndVisionKitProbe(report);
        return report;
    }

    [report appendFormat:@"Loaded: %s\n", loadedPath ?: "<unknown>"];

    GEGetXPCFn getStateDump = (GEGetXPCFn)dlsym(handle, "os_eligibility_get_state_dump");
    GEGetXPCFn getAllAnswers = (GEGetXPCFn)dlsym(handle, "os_eligibility_get_all_domain_answers");
    GEGetXPCFn getInternalState = (GEGetXPCFn)dlsym(handle, "os_eligibility_get_internal_state");
    GEGetDomainAnswerFn getDomainAnswer =
        (GEGetDomainAnswerFn)dlsym(handle, "os_eligibility_get_domain_answer");

    void *xpcHandle = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW | RTLD_LOCAL);
    GEXPCDescriptionFn copyDescription = NULL;
    if (xpcHandle) {
        copyDescription = (GEXPCDescriptionFn)dlsym(xpcHandle, "xpc_copy_description");
    }
    if (!copyDescription) {
        copyDescription = (GEXPCDescriptionFn)dlsym(RTLD_DEFAULT, "xpc_copy_description");
    }

    GEAppendXPCProbe(report, @"os_eligibility_get_state_dump", getStateDump, copyDescription);
    GEAppendXPCProbe(report, @"os_eligibility_get_all_domain_answers", getAllAnswers, copyDescription);
    GEAppendXPCProbe(report, @"os_eligibility_get_internal_state", getInternalState, copyDescription);

    [report appendString:@"\n--- selected domain answers ---\n"];
    if (!getDomainAnswer) {
        [report appendString:@"os_eligibility_get_domain_answer = <symbol unavailable>\n"];
    } else {
        const uint64_t selectedDomains[] = { 39, 122, 130, 155 };
        for (size_t i = 0; i < sizeof(selectedDomains) / sizeof(selectedDomains[0]); i++) {
            GEAppendDomainProbe(report,
                                getDomainAnswer,
                                copyDescription,
                                selectedDomains[i],
                                YES,
                                YES);
        }

        [report appendString:@"\n--- domain scan 1...220: country/region-related or computed non-eligible ---\n"];
        [report appendString:@"Filter: rc=0 AND (status mentions COUNTRY_LOCATION / DEVICE_REGION_CODE / COUNTRY_BILLING / CHINA_CELLULAR, OR a COMPUTED/FORCED answer is not ELIGIBLE).\n"];

        NSUInteger matched = 0;
        for (uint64_t domain = 1; domain <= 220; domain++) {
            uint64_t answer = 0;
            uint64_t source = 0;
            GEXPCObject status = NULL;
            GEXPCObject context = NULL;
            int rc = getDomainAnswer(domain, &answer, &source, &status, &context);
            if (rc != 0) continue;

            NSString *statusDescription = GEDescribeXPC(status, copyDescription);
            BOOL statusRelevant = GEStatusContainsRelevantInput(statusDescription);
            BOOL computedNonEligible = (source == 1 || source == 2) && answer != 4;
            if (!statusRelevant && !computedNonEligible) continue;

            matched++;
            NSString *knownName = GEDomainKnownName(domain);
            if (knownName) {
                [report appendFormat:@"%@(%llu): answer=%@ source=%@\n",
                 knownName, domain, GEAnswerName(answer), GESourceName(source)];
            } else {
                [report appendFormat:@"DOMAIN(%llu): answer=%@ source=%@\n",
                 domain, GEAnswerName(answer), GESourceName(source)];
            }
            [report appendFormat:@"  status=%@\n", statusDescription];
            if (context) {
                [report appendFormat:@"  context=%@\n", GEDescribeXPC(context, copyDescription)];
            }
        }
        [report appendFormat:@"Domain scan matches: %lu\n", (unsigned long)matched];
    }

    if (xpcHandle) dlclose(xpcHandle);
    dlclose(handle);

    GEAppendGMAndVisionKitProbe(report);
    return report;
}
