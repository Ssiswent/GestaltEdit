#import "CallerIdentityBridge.h"

#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>

static NSString *TypeEncodingForClassMethod(Class cls, SEL sel) {
    if (!cls || !sel) return @"<missing>";
    Method m = class_getClassMethod(cls, sel);
    if (!m) return @"<missing>";
    const char *t = method_getTypeEncoding(m);
    return t ? [NSString stringWithUTF8String:t] : @"<nil>";
}

static BOOL ClassMethodHasTypes(Class cls, SEL sel, const char *expected) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    const char *t = method_getTypeEncoding(m);
    return t && expected && strcmp(t, expected) == 0;
}

static void AppendSelector(NSMutableString *out, Class cls, NSString *name) {
    SEL sel = NSSelectorFromString(name);
    Method m = class_getClassMethod(cls, sel);
    [out appendFormat:@"  +%@ present=%@ types=%@\n",
     name, m ? @"YES" : @"NO", m ? TypeEncodingForClassMethod(cls, sel) : @"<missing>"];
}

static NSString *BoolString(BOOL v) { return v ? @"true" : @"false"; }

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI Rich-Analysis BundleID Differential READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: read-only availability getters only. No setters, no preheat, no XPC service call made directly by this app, no method swizzling/IMP replacement, no preference/MobileGestalt writes, no respring/reboot. Every private selector is invoked only when its runtime type encoding matches the ABI observed on this exact device build.\n\n"];

    const char *vicPath = "/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore";
    const char *vkPath  = "/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore";
    void *vicHandle = dlopen(vicPath, RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen(vkPath, RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen = %@\n", vicHandle ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen = %@\n", vkHandle ? @"OK" : @"FAIL"];

    Class vic = NSClassFromString(@"VICVisualIntelligenceAnalyzer");
    Class vkc = NSClassFromString(@"VKCImageAnalyzer");
    [out appendFormat:@"VICVisualIntelligenceAnalyzer = %@\n", vic ? @"FOUND" : @"MISSING"];
    [out appendFormat:@"VKCImageAnalyzer = %@\n", vkc ? @"FOUND" : @"MISSING"];

    [out appendString:@"\n--- exact selector inventory ---\n"];
    if (vic) {
        AppendSelector(out, vic, @"isRichAnalysisAvailableForRequestType:bundleID:");
        AppendSelector(out, vic, @"shouldShowEnhancedSiri");
        AppendSelector(out, vic, @"preheat");
        AppendSelector(out, vic, @"preheatFor:environmentBundleIdentifier:");
    }
    if (vkc) {
        AppendSelector(out, vkc, @"supportedAnalysisTypes");
        AppendSelector(out, vkc, @"deviceIsEligibleForVI");
        AppendSelector(out, vkc, @"isEnhancedSiriAvailable");
        AppendSelector(out, vkc, @"isEnhancedSiriEnabled");
        AppendSelector(out, vkc, @"shouldShowEnhancedSiri");
        AppendSelector(out, vkc, @"viEntryType");
        AppendSelector(out, vkc, @"setViEntryType:");
        AppendSelector(out, vkc, @"viBundleIdentifier");
        AppendSelector(out, vkc, @"setViBundleIdentifier:");
    }

    [out appendString:@"\n--- VKCImageAnalyzer read-only baseline ---\n"];
    if (vkc) {
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"supportedAnalysisTypes"), "Q16@0:8")) {
            unsigned long long v = ((unsigned long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"supportedAnalysisTypes"));
            [out appendFormat:@"supportedAnalysisTypes = %llu (0x%llx)\n", v, v];
        }
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"deviceIsEligibleForVI"), "B16@0:8")) {
            BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"deviceIsEligibleForVI"));
            [out appendFormat:@"deviceIsEligibleForVI = %@\n", BoolString(v)];
        }
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"isEnhancedSiriAvailable"), "B16@0:8")) {
            BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"isEnhancedSiriAvailable"));
            [out appendFormat:@"isEnhancedSiriAvailable = %@\n", BoolString(v)];
        }
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"isEnhancedSiriEnabled"), "B16@0:8")) {
            BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"isEnhancedSiriEnabled"));
            [out appendFormat:@"isEnhancedSiriEnabled = %@\n", BoolString(v)];
        }
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"shouldShowEnhancedSiri"), "B16@0:8")) {
            BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"shouldShowEnhancedSiri"));
            [out appendFormat:@"shouldShowEnhancedSiri = %@\n", BoolString(v)];
        }
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"viEntryType"), "q16@0:8")) {
            long long v = ((long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viEntryType"));
            [out appendFormat:@"viEntryType = %lld\n", v];
        } else if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"viEntryType"), "Q16@0:8")) {
            unsigned long long v = ((unsigned long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viEntryType"));
            [out appendFormat:@"viEntryType = %llu\n", v];
        }
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"viBundleIdentifier"), "@16@0:8")) {
            id v = ((id (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viBundleIdentifier"));
            [out appendFormat:@"viBundleIdentifier = %@\n", v ?: @"<nil>"];
        }
    }

    [out appendString:@"\n--- VIC rich-analysis availability matrix ---\n"];
    SEL richSel = NSSelectorFromString(@"isRichAnalysisAvailableForRequestType:bundleID:");
    if (!vic || !ClassMethodHasTypes(vic, richSel, "B32@0:8q16@24")) {
        [out appendFormat:@"SKIPPED: selector missing or ABI mismatch; observed types=%@\n", vic ? TypeEncodingForClassMethod(vic, richSel) : @"<class missing>"];
    } else {
        NSString *selfBundle = NSBundle.mainBundle.bundleIdentifier ?: @"me.ssus.gestaltedit";
        NSArray *bundleIDs = @[
            selfBundle,
            @"com.apple.camera",
            @"com.apple.Camera",
            @"com.apple.springboard",
            @"com.apple.visualintelligenced",
            @"com.apple.ScreenshotServicesService",
            @"com.apple.screenshotservices",
            @"com.apple.mobileslideshow",
            @"com.apple.Photos"
        ];
        long long requestTypes[] = {0, 1, 2, 3, 4, 5, 6, 7};
        for (NSString *bundleID in bundleIDs) {
            [out appendFormat:@"bundleID=%@\n", bundleID];
            for (NSUInteger i = 0; i < sizeof(requestTypes)/sizeof(requestTypes[0]); i++) {
                long long requestType = requestTypes[i];
                BOOL available = NO;
                @try {
                    available = ((BOOL (*)(id, SEL, long long, id))objc_msgSend)(vic, richSel, requestType, bundleID);
                    [out appendFormat:@"  requestType=%lld -> %@\n", requestType, BoolString(available)];
                } @catch (NSException *e) {
                    [out appendFormat:@"  requestType=%lld -> EXCEPTION %@: %@\n", requestType, e.name, e.reason ?: @"<nil>"];
                }
            }
        }
    }

    [out appendString:@"\n--- VIC global read-only baseline ---\n"];
    if (vic && ClassMethodHasTypes(vic, NSSelectorFromString(@"shouldShowEnhancedSiri"), "B16@0:8")) {
        BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(vic, NSSelectorFromString(@"shouldShowEnhancedSiri"));
        [out appendFormat:@"VIC.shouldShowEnhancedSiri = %@\n", BoolString(v)];
    } else {
        [out appendString:@"VIC.shouldShowEnhancedSiri = <unavailable or ABI mismatch>\n"];
    }

    [out appendString:@"\nNOTE: preheat / preheatFor / setViEntryType / setViBundleIdentifier were intentionally NOT called. This build only compares the bundleID-aware availability getter that VisionKitCore itself calls on newer iOS 27 betas.\n"];
    [out appendString:@"===============================================================================\n"];
    return out;
}
