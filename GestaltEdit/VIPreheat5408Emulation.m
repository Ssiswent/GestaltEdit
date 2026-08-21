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

static void VIAppendAvailabilitySnapshot(NSMutableString *out, NSString *label) {
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
            CurrentFn fn = (CurrentFn)objc_msgSend;
            @try {
                NSInteger settings = fn(gm, currentSel, @[@"com.apple.Settings.AppleIntelligence"], nil);
                NSInteger gvicc = fn(gm, currentSel, @[@"VisualIntelligence.gvicc"], nil);
                [out appendFormat:@"GM Settings.AppleIntelligence rawStatus=%ld\n", (long)settings];
                [out appendFormat:@"GM VisualIntelligence.gvicc rawStatus=%ld\n", (long)gvicc];
            } @catch (NSException *e) {
                [out appendFormat:@"GM snapshot exception=%@ reason=%@\n", e.name, e.reason ?: @""];
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

static NSString *VIPreheatGenerateReportForBundle(NSString *environmentBundleIdentifier) {
    NSMutableString *out = [NSMutableString string];
    NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];

    [out appendString:@"========== iOS 27 VI 24A5408d BUNDLE-AWARE PREHEAT BACKPORT EXPERIMENT ==========\n"];
    [out appendFormat:@"Generated: %@\n", [formatter stringFromDate:[NSDate date]]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendFormat:@"targetEnvironmentBundleIdentifier=%@\n", environmentBundleIdentifier];
    [out appendString:@"SAFETY: transient in-process private-framework preheat experiment only. It invokes the already-present +preheatFor:environmentBundleIdentifier: only when its ABI is exactly v32@0:8q16@24 AND both a fresh VIC request config getter and VKCImageAnalyzer.viEntryType independently report the already-observed value 0. No enum value is guessed. No rich-analysis call, private setters, swizzling/IMP replacement, Darwin notification, preferences/MobileGestalt/file writes, respring or reboot. This does NOT patch Camera or backport beta 5 GenerativeModels cache logic.\n\n"];

    void *vic = dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore", RTLD_NOW | RTLD_LOCAL);
    void *gmh = dlopen("/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels", RTLD_NOW | RTLD_LOCAL);
    void *vkc = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vic ? @"OK" : @"FAIL"];
    [out appendFormat:@"GenerativeModels dlopen=%@\n", gmh ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen=%@\n", vkc ? @"OK" : @"FAIL"];

    VIAppendAvailabilitySnapshot(out, @"before-preheat");

    Class configClass = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");
    Class analyzerClass = NSClassFromString(@"VICVisualIntelligenceAnalyzer");
    Class imageAnalyzerClass = NSClassFromString(@"VKCImageAnalyzer");
    [out appendString:@"\n--- beta5-path ABI/value guard ---\n"];
    [out appendFormat:@"VICVisualIntelligenceAnalysisRequestConfig=%@\n", configClass ? @"FOUND" : @"MISSING"];
    [out appendFormat:@"VICVisualIntelligenceAnalyzer=%@\n", analyzerClass ? @"FOUND" : @"MISSING"];
    [out appendFormat:@"VKCImageAnalyzer=%@\n", imageAnalyzerClass ? @"FOUND" : @"MISSING"];

    if (!configClass || !analyzerClass || !imageAnalyzerClass) {
        [out appendString:@"invoked=false reason=required-class-missing\n"];
        return out;
    }

    SEL requestTypeSel = NSSelectorFromString(@"requestType");
    Method requestTypeMethod = class_getInstanceMethod(configClass, requestTypeSel);
    SEL viEntryTypeSel = NSSelectorFromString(@"viEntryType");
    Method viEntryTypeMethod = class_getClassMethod(imageAnalyzerClass, viEntryTypeSel);
    SEL preheatSel = NSSelectorFromString(@"preheatFor:environmentBundleIdentifier:");
    Method preheatMethod = class_getClassMethod(analyzerClass, preheatSel);

    [out appendFormat:@"freshConfig -requestType types=%@ expected=q16@0:8\n", VITypeEncoding(requestTypeMethod)];
    [out appendFormat:@"VKCImageAnalyzer +viEntryType types=%@ expected=Q16@0:8\n", VITypeEncoding(viEntryTypeMethod)];
    [out appendFormat:@"VIC +preheatFor:environmentBundleIdentifier: types=%@ expected=v32@0:8q16@24\n", VITypeEncoding(preheatMethod)];

    if (!VIEncodingEquals(requestTypeMethod, "q16@0:8") ||
        !VIEncodingEquals(viEntryTypeMethod, "Q16@0:8") ||
        !VIEncodingEquals(preheatMethod, "v32@0:8q16@24")) {
        [out appendString:@"invoked=false reason=ABI-mismatch\n"];
        return out;
    }

    id config = [[configClass alloc] init];
    if (!config) {
        [out appendString:@"invoked=false reason=fresh-config-init-failed\n"];
        return out;
    }

    typedef int64_t (*RequestTypeFn)(id, SEL);
    typedef uint64_t (*EntryTypeFn)(id, SEL);
    int64_t requestType = ((RequestTypeFn)objc_msgSend)(config, requestTypeSel);
    uint64_t viEntryType = ((EntryTypeFn)objc_msgSend)(imageAnalyzerClass, viEntryTypeSel);
    [out appendFormat:@"freshConfig.requestType=%lld\n", requestType];
    [out appendFormat:@"VKCImageAnalyzer.viEntryType=%llu\n", viEntryType];

    if (requestType != 0 || viEntryType != 0) {
        [out appendString:@"invoked=false reason=validated-values-no-longer-zero; refusing-to-guess-enum\n"];
        return out;
    }

    @try {
        typedef void (*PreheatFn)(id, SEL, int64_t, id);
        ((PreheatFn)objc_msgSend)(analyzerClass, preheatSel, requestType, environmentBundleIdentifier);
        [out appendString:@"invoked=true\n"];
        [out appendFormat:@"call=+[VICVisualIntelligenceAnalyzer preheatFor:0 environmentBundleIdentifier:%@]\n", environmentBundleIdentifier];
    } @catch (NSException *e) {
        [out appendFormat:@"invoked=false exception=%@ reason=%@\n", e.name, e.reason ?: @""];
    }

    VIAppendAvailabilitySnapshot(out, @"immediately-after-preheat");

    [out appendString:@"\n--- real-entry test ---\n"];
    [out appendString:@"Force-quit Camera BEFORE the experiment. After invoked=true appears, go Home immediately and DIRECTLY long-press Camera Control. Do not manually open Camera first. Record whether Visual Intelligence opens or Camera falls back to Photo.\n"];
    [out appendString:@"\nINTERPRETATION: success would show that beta 5's bundle-aware preheat path alone can seed enough shared state to change beta 4 behavior. Failure does NOT disprove the beta 5 fix: beta 5 also changed GenerativeModels to avoid caching transient availability states, and a third-party process cannot safely replace that Camera-local cache implementation.\n"];
    [out appendString:@"================================================================================\n"];
    return out;
}

NSString *VIPreheat5408EmulationGenerateCameraReport(void) {
    return VIPreheatGenerateReportForBundle(@"com.apple.camera");
}

NSString *VIPreheat5408EmulationGenerateVisualIntelligenceCameraReport(void) {
    return VIPreheatGenerateReportForBundle(@"com.apple.VisualIntelligenceCamera");
}

NSString *VIPreheat5408EmulationGenerateReport(void) {
    return VIPreheat5408EmulationGenerateCameraReport();
}
