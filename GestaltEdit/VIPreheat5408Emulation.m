#import "VIPreheat5408Emulation.h"

#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>

static NSString *VITypeEncoding(Method method) {
    if (!method) return @"<missing>";
    const char *types = method_getTypeEncoding(method);
    return types ? [NSString stringWithUTF8String:types] : @"<nil>";
}

static BOOL VIEncodingEquals(Method method, const char *expected) {
    if (!method) return NO;
    const char *types = method_getTypeEncoding(method);
    return types && strcmp(types, expected) == 0;
}

static void VIAppendKnownSafeAvailabilitySnapshot(NSMutableString *out, NSString *label) {
    [out appendFormat:@"\n--- known-safe availability snapshot: %@ ---\n", label];

    Class gm = NSClassFromString(@"GMAvailabilityWrapper");
    if (!gm) {
        [out appendString:@"GMAvailabilityWrapper=<missing>\n"];
    } else {
        SEL currentSel = NSSelectorFromString(@"currentWithUseCaseIdentifiers:language:");
        Method currentMethod = class_getClassMethod(gm, currentSel);
        [out appendFormat:@"GM +currentWithUseCaseIdentifiers:language: types=%@\n", VITypeEncoding(currentMethod)];
        if (VIEncodingEquals(currentMethod, "q32@0:8@16@24")) {
            typedef NSInteger (*CurrentFn)(id, SEL, id, id);
            CurrentFn currentFn = (CurrentFn)objc_msgSend;
            @try {
                NSInteger settings = currentFn(gm, currentSel, @[@"com.apple.Settings.AppleIntelligence"], nil);
                NSInteger gvicc = currentFn(gm, currentSel, @[@"VisualIntelligence.gvicc"], nil);
                [out appendFormat:@"GM Settings.AppleIntelligence rawStatus=%ld\n", (long)settings];
                [out appendFormat:@"GM VisualIntelligence.gvicc rawStatus=%ld\n", (long)gvicc];
            } @catch (NSException *exception) {
                [out appendFormat:@"GM snapshot exception=%@ %@\n", exception.name, exception.reason ?: @""];
            }
        }
    }

    Class vk = NSClassFromString(@"VKCGMAvailability");
    if (!vk) {
        [out appendString:@"VKCGMAvailability=<missing>\n"];
        return;
    }

    for (NSString *name in @[@"supportsVI", @"deviceIsEligibleForVI", @"enhancedSiriAvailable", @"enhancedSiriEnabled"]) {
        SEL sel = NSSelectorFromString(name);
        Method method = class_getClassMethod(vk, sel);
        [out appendFormat:@"VK +%@ types=%@", name, VITypeEncoding(method)];
        if (VIEncodingEquals(method, "B16@0:8")) {
            typedef BOOL (*BoolFn)(id, SEL);
            BOOL value = ((BoolFn)objc_msgSend)(vk, sel);
            [out appendFormat:@" value=%@\n", value ? @"true" : @"false"];
        } else {
            [out appendString:@" value=<not-called>\n"];
        }
    }
}

NSString *VIPreheat5408EmulationGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];

    [out appendString:@"========== iOS 27 VI 24A5408d BUNDLE-AWARE PREHEAT EMULATION Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [formatter stringFromDate:[NSDate date]]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"EXPERIMENT: transient/private VI preheat only. This build intentionally calls the already-present +[VICVisualIntelligenceAnalyzer preheatFor:environmentBundleIdentifier:] after obtaining requestType exclusively from a fresh VICVisualIntelligenceAnalysisRequestConfig getter with an exact ABI match. No arbitrary enum value is supplied. No rich-analysis availability call, setters, XPC, swizzling/IMP replacement, notifications, preferences/MobileGestalt/file writes, respring or reboot.\n\n"];

    void *vic = dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore", RTLD_NOW | RTLD_LOCAL);
    void *gmh = dlopen("/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels", RTLD_NOW | RTLD_LOCAL);
    void *vkc = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vic ? @"OK" : @"FAIL"];
    [out appendFormat:@"GenerativeModels dlopen=%@\n", gmh ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen=%@\n", vkc ? @"OK" : @"FAIL"];

    VIAppendKnownSafeAvailabilitySnapshot(out, @"before-preheat");

    Class configClass = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");
    Class analyzerClass = NSClassFromString(@"VICVisualIntelligenceAnalyzer");
    [out appendString:@"\n--- 24A5408d emulation preflight ---\n"];
    [out appendFormat:@"VICVisualIntelligenceAnalysisRequestConfig=%@\n", configClass ? @"FOUND" : @"MISSING"];
    [out appendFormat:@"VICVisualIntelligenceAnalyzer=%@\n", analyzerClass ? @"FOUND" : @"MISSING"];

    if (!configClass || !analyzerClass) {
        [out appendString:@"invoked=false reason=required-class-missing\n"];
        return out;
    }

    SEL requestTypeSel = NSSelectorFromString(@"requestType");
    Method requestTypeMethod = class_getInstanceMethod(configClass, requestTypeSel);
    [out appendFormat:@"-requestType types=%@ expected=q16@0:8\n", VITypeEncoding(requestTypeMethod)];

    SEL preheatSel = NSSelectorFromString(@"preheatFor:environmentBundleIdentifier:");
    Method preheatMethod = class_getClassMethod(analyzerClass, preheatSel);
    [out appendFormat:@"+preheatFor:environmentBundleIdentifier: types=%@ expected=v32@0:8q16@24\n", VITypeEncoding(preheatMethod)];

    if (!VIEncodingEquals(requestTypeMethod, "q16@0:8")) {
        [out appendString:@"invoked=false reason=requestType-ABI-mismatch\n"];
        return out;
    }
    if (!VIEncodingEquals(preheatMethod, "v32@0:8q16@24")) {
        [out appendString:@"invoked=false reason=preheat-ABI-mismatch\n"];
        return out;
    }

    id config = [[configClass alloc] init];
    if (!config) {
        [out appendString:@"invoked=false reason=fresh-config-init-failed\n"];
        return out;
    }

    typedef int64_t (*RequestTypeFn)(id, SEL);
    int64_t requestType = ((RequestTypeFn)objc_msgSend)(config, requestTypeSel);
    NSString *environmentBundleIdentifier = @"com.apple.camera";
    [out appendFormat:@"freshConfig.requestType=%lld (value obtained from getter; not guessed)\n", requestType];
    [out appendFormat:@"environmentBundleIdentifier=%@\n", environmentBundleIdentifier];

    @try {
        typedef void (*PreheatFn)(id, SEL, int64_t, id);
        ((PreheatFn)objc_msgSend)(analyzerClass, preheatSel, requestType, environmentBundleIdentifier);
        [out appendString:@"invoked=true\n"];
        [out appendString:@"call=+[VICVisualIntelligenceAnalyzer preheatFor:freshConfig.requestType environmentBundleIdentifier:@\"com.apple.camera\"]\n"];
    } @catch (NSException *exception) {
        [out appendFormat:@"invoked=false exception=%@ reason=%@\n", exception.name, exception.reason ?: @""];
    }

    VIAppendKnownSafeAvailabilitySnapshot(out, @"immediately-after-preheat");

    [out appendString:@"\n--- test instruction ---\n"];
    [out appendString:@"1. Do not open Camera manually.\n"];
    [out appendString:@"2. Immediately leave GestaltEdit to Home after this report appears.\n"];
    [out appendString:@"3. Directly long-press Camera Control to invoke Camera Visual Intelligence.\n"];
    [out appendString:@"4. Report whether VI opens or falls back to Photo, then paste this full report.\n"];
    [out appendString:@"\nINTERPRETATION: success would strongly support a 24A5390f generic-preheat/caller-context regression. Failure would mean an external process cannot seed the Camera-local VisionKit/VI state, so the next target is the Camera-local coordinator/config construction path rather than region/language/entitlement guessing.\n"];
    [out appendString:@"================================================================================\n"];
    return out;
}
