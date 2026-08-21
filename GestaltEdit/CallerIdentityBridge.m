#import "CallerIdentityBridge.h"

#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>

static NSString *BoolString(BOOL v) { return v ? @"true" : @"false"; }

static NSString *ClassMethodTypes(Class cls, SEL sel) {
    Method m = cls ? class_getClassMethod(cls, sel) : NULL;
    if (!m) return @"<missing>";
    const char *t = method_getTypeEncoding(m);
    return t ? [NSString stringWithUTF8String:t] : @"<nil>";
}

static BOOL ClassMethodHasTypes(Class cls, SEL sel, const char *expected) {
    Method m = cls ? class_getClassMethod(cls, sel) : NULL;
    if (!m) return NO;
    const char *t = method_getTypeEncoding(m);
    return t && expected && strcmp(t, expected) == 0;
}

static void AppendClassMethod(NSMutableString *out, Class cls, NSString *name) {
    SEL sel = NSSelectorFromString(name);
    [out appendFormat:@"  +%@ types=%@\n", name, ClassMethodTypes(cls, sel)];
}

static void AppendAllMetadataForClass(NSMutableString *out, Class cls) {
    if (!cls) return;
    NSString *name = NSStringFromClass(cls) ?: @"<unknown>";
    Class superCls = class_getSuperclass(cls);
    [out appendFormat:@"\nclass=%@\nsuperclass=%@\n", name,
     superCls ? NSStringFromClass(superCls) : @"<nil>"];

    unsigned int ic = 0;
    Ivar *ivars = class_copyIvarList(cls, &ic);
    [out appendFormat:@"ivars=%u\n", ic];
    for (unsigned int i = 0; i < ic; i++) {
        const char *n = ivar_getName(ivars[i]);
        const char *t = ivar_getTypeEncoding(ivars[i]);
        [out appendFormat:@"  ivar %s type=%s offset=%td\n",
         n ?: "<nil>", t ?: "<nil>", ivar_getOffset(ivars[i])];
    }
    free(ivars);

    unsigned int pc = 0;
    objc_property_t *props = class_copyPropertyList(cls, &pc);
    [out appendFormat:@"properties=%u\n", pc];
    for (unsigned int i = 0; i < pc; i++) {
        const char *n = property_getName(props[i]);
        const char *a = property_getAttributes(props[i]);
        [out appendFormat:@"  property %s attrs=%s\n", n ?: "<nil>", a ?: "<nil>"];
    }
    free(props);

    unsigned int mc = 0;
    Method *methods = class_copyMethodList(cls, &mc);
    [out appendFormat:@"instanceMethods=%u\n", mc];
    for (unsigned int i = 0; i < mc; i++) {
        SEL s = method_getName(methods[i]);
        const char *t = method_getTypeEncoding(methods[i]);
        [out appendFormat:@"  -%@ types=%s\n", NSStringFromSelector(s), t ?: "<nil>"];
    }
    free(methods);
}

static void AppendGreymatterRuntimeMetadata(NSMutableString *out) {
    [out appendString:@"\n--- VisualIntelligenceCore GreymatterAvailability runtime metadata ---\n"];
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        [out appendString:@"objc_getClassList returned no classes\n"];
        return;
    }
    Class *classes = (__unsafe_unretained Class *)calloc((size_t)count, sizeof(Class));
    int actual = objc_getClassList(classes, count);
    NSUInteger hits = 0;
    for (int i = 0; i < actual; i++) {
        Class cls = classes[i];
        NSString *name = NSStringFromClass(cls);
        if ([name containsString:@"GreymatterAvailability"]) {
            hits++;
            AppendAllMetadataForClass(out, cls);
        }
    }
    free(classes);
    [out appendFormat:@"GreymatterAvailability-related classes=%lu\n", (unsigned long)hits];
    [out appendString:@"NOTE: the previous device-local Swift reflection scan exposed fields named availability, partnerAvailability, hasAdditionalChinaPolicy, availabilityKey, useCaseIdentifier and languageOption. This section checks which of those fields are materialized as Objective-C-visible runtime storage on 24A5390f.\n"];
}

static void AppendGMSUseCase(NSMutableString *out, Class gm, NSString *useCase) {
    [out appendFormat:@"useCase=%@\n", useCase];
    NSArray *ids = @[useCase];
    id language = nil;

    SEL currentSel = NSSelectorFromString(@"currentWithUseCaseIdentifiers:language:");
    if (ClassMethodHasTypes(gm, currentSel, "q32@0:8@16@24")) {
        long long v = ((long long (*)(id, SEL, id, id))objc_msgSend)(gm, currentSel, ids, language);
        [out appendFormat:@"  current.rawStatus=%lld\n", v];
    }
    SEL enabledSel = NSSelectorFromString(@"enabledWithUseCaseIdentifiers:language:");
    if (ClassMethodHasTypes(gm, enabledSel, "B32@0:8@16@24")) {
        BOOL v = ((BOOL (*)(id, SEL, id, id))objc_msgSend)(gm, enabledSel, ids, language);
        [out appendFormat:@"  enabled=%@\n", BoolString(v)];
    }
    SEL partnerSel = NSSelectorFromString(@"useCasePartnerAllowedInUserLocaleRegionWithUseCaseIdentifiers:language:");
    if (ClassMethodHasTypes(gm, partnerSel, "B32@0:8@16@24")) {
        BOOL v = ((BOOL (*)(id, SEL, id, id))objc_msgSend)(gm, partnerSel, ids, language);
        [out appendFormat:@"  partnerAllowedInUserLocaleRegion=%@\n", BoolString(v)];
    }
    SEL disabledSel = NSSelectorFromString(@"isUseCaseDisabledWithUseCaseIdentifiers:language:");
    if (ClassMethodHasTypes(gm, disabledSel, "B32@0:8@16@24")) {
        BOOL v = ((BOOL (*)(id, SEL, id, id))objc_msgSend)(gm, disabledSel, ids, language);
        [out appendFormat:@"  useCaseDisabled=%@\n", BoolString(v)];
    }
    SEL assetSel = NSSelectorFromString(@"assetIsNotReadyWithUseCaseIdentifiers:language:");
    if (ClassMethodHasTypes(gm, assetSel, "B32@0:8@16@24")) {
        BOOL v = ((BOOL (*)(id, SEL, id, id))objc_msgSend)(gm, assetSel, ids, language);
        [out appendFormat:@"  assetIsNotReady=%@\n", BoolString(v)];
    }
}

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI VALID-REQUEST + CHINA-POLICY READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: read-only availability getters and Objective-C runtime metadata only. Request type 0 is used exclusively because the immediately preceding crash-safe probe proved that a fresh VICVisualIntelligenceAnalysisRequestConfig has requestType(raw)=0 and VKCImageAnalyzer.viEntryType(raw)=0 on this exact 24A5390f device. No arbitrary enum values are probed. No setters, preheat, swizzling/IMP replacement, preference/MobileGestalt writes, respring or reboot.\n\n"];

    void *vicHandle = dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore", RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    void *gmHandle = dlopen("/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels", RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vicHandle ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen=%@\n", vkHandle ? @"OK" : @"FAIL"];
    [out appendFormat:@"GenerativeModels dlopen=%@\n", gmHandle ? @"OK" : @"FAIL"];

    Class vic = NSClassFromString(@"VICVisualIntelligenceAnalyzer");
    Class vkc = NSClassFromString(@"VKCImageAnalyzer");
    Class gm = NSClassFromString(@"GMAvailabilityWrapper");
    Class config = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");

    [out appendString:@"\n--- ABI verification ---\n"];
    AppendClassMethod(out, vic, @"isRichAnalysisAvailableForRequestType:bundleID:");
    AppendClassMethod(out, vkc, @"viEntryType");
    AppendClassMethod(out, vkc, @"viBundleIdentifier");
    AppendClassMethod(out, vkc, @"supportedAnalysisTypes");
    AppendClassMethod(out, vkc, @"deviceIsEligibleForVI");
    AppendClassMethod(out, gm, @"currentWithUseCaseIdentifiers:language:");
    AppendClassMethod(out, gm, @"useCasePartnerAllowedInUserLocaleRegionWithUseCaseIdentifiers:language:");

    [out appendString:@"\n--- local baseline proving request type 0 remains the active/default type ---\n"];
    if (vkc && ClassMethodHasTypes(vkc, NSSelectorFromString(@"viEntryType"), "Q16@0:8")) {
        unsigned long long v = ((unsigned long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viEntryType"));
        [out appendFormat:@"VKCImageAnalyzer.viEntryType=%llu\n", v];
    }
    if (vkc && ClassMethodHasTypes(vkc, NSSelectorFromString(@"viBundleIdentifier"), "@16@0:8")) {
        id v = ((id (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viBundleIdentifier"));
        [out appendFormat:@"VKCImageAnalyzer.viBundleIdentifier=%@\n", v ?: @"<nil>"];
    }
    if (config) {
        id obj = ((id (*)(id, SEL))objc_msgSend)((id)config, @selector(alloc));
        obj = ((id (*)(id, SEL))objc_msgSend)(obj, @selector(init));
        Method m = class_getInstanceMethod(config, NSSelectorFromString(@"requestType"));
        const char *t = m ? method_getTypeEncoding(m) : NULL;
        if (obj && t && strcmp(t, "q16@0:8") == 0) {
            long long v = ((long long (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"requestType"));
            [out appendFormat:@"freshConfig.requestType=%lld\n", v];
        }
    }

    [out appendString:@"\n--- VIC rich-analysis bundleID differential using ONLY validated requestType=0 ---\n"];
    SEL richSel = NSSelectorFromString(@"isRichAnalysisAvailableForRequestType:bundleID:");
    if (!vic || !ClassMethodHasTypes(vic, richSel, "B32@0:8q16@24")) {
        [out appendFormat:@"SKIPPED: selector missing/ABI mismatch (%@)\n", ClassMethodTypes(vic, richSel)];
    } else {
        NSArray<NSString *> *bundleIDs = @[
            NSBundle.mainBundle.bundleIdentifier ?: @"me.ssus.gestaltedit",
            @"com.apple.camera",
            @"com.apple.mobileslideshow",
            @"com.apple.VisualIntelligenceCamera",
            @"com.apple.VisualIntelligence",
            @"com.apple.visualintelligenced",
            @"com.apple.springboard"
        ];
        for (NSString *bundleID in bundleIDs) {
            BOOL available = ((BOOL (*)(id, SEL, long long, id))objc_msgSend)(vic, richSel, 0LL, bundleID);
            [out appendFormat:@"requestType=0 bundleID=%@ -> %@\n", bundleID, BoolString(available)];
        }
    }

    [out appendString:@"\n--- GenerativeModels public-in-process policy decomposition ---\n"];
    if (gm) {
        NSArray<NSString *> *useCases = @[
            @"VisualIntelligence.gvicc",
            @"VisualIntelligence.vi_content_classifier",
            @"GenerativeAssistant.visualIntelligenceCamera",
            @"summarization.visualIntelligenceCamera",
            @"com.apple.Settings.AppleIntelligence",
            @"com.apple.VisualIntelligenceCamera.ImageSearch",
            @"com.apple.VisualIntelligenceCamera.VisualLookup"
        ];
        for (NSString *useCase in useCases) AppendGMSUseCase(out, gm, useCase);
    } else {
        [out appendString:@"GMAvailabilityWrapper missing\n"];
    }

    AppendGreymatterRuntimeMetadata(out);

    [out appendString:@"\n--- interpretation guardrails ---\n"];
    [out appendString:@"1. A false result for com.apple.camera with requestType=0 while generic GM use cases remain available would directly demonstrate a bundle/environment-specific VisualIntelligenceCore gate.\n"];
    [out appendString:@"2. A true result for com.apple.camera would mean the Camera failure occurs after this rich-analysis availability getter, or depends on caller process privileges/state not reproduced by merely supplying the Camera bundle identifier.\n"];
    [out appendString:@"3. hasAdditionalChinaPolicy is treated as a discovered implementation field, not automatically as the proven failing predicate; this probe does not modify it.\n"];
    [out appendString:@"====================================================================================\n"];
    return out;
}
