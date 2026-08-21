#import "CallerIdentityBridge.h"

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <objc/message.h>
#import <objc/runtime.h>

static NSString *TypeEncodingForClassMethod(Class cls, SEL sel) {
    if (!cls || !sel) return @"<missing>";
    Method m = class_getClassMethod(cls, sel);
    if (!m) return @"<missing>";
    const char *t = method_getTypeEncoding(m);
    return t ? [NSString stringWithUTF8String:t] : @"<nil>";
}

static NSString *TypeEncodingForInstanceMethod(Class cls, SEL sel) {
    if (!cls || !sel) return @"<missing>";
    Method m = class_getInstanceMethod(cls, sel);
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

static BOOL InstanceMethodHasTypes(Class cls, SEL sel, const char *expected) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    const char *t = method_getTypeEncoding(m);
    return t && expected && strcmp(t, expected) == 0;
}

static void AppendClassSelector(NSMutableString *out, Class cls, NSString *name) {
    SEL sel = NSSelectorFromString(name);
    Method m = class_getClassMethod(cls, sel);
    [out appendFormat:@"  +%@ present=%@ types=%@\n",
     name, m ? @"YES" : @"NO", m ? TypeEncodingForClassMethod(cls, sel) : @"<missing>"];
}

static void AppendInstanceSelector(NSMutableString *out, Class cls, NSString *name) {
    SEL sel = NSSelectorFromString(name);
    Method m = class_getInstanceMethod(cls, sel);
    [out appendFormat:@"  -%@ present=%@ types=%@\n",
     name, m ? @"YES" : @"NO", m ? TypeEncodingForInstanceMethod(cls, sel) : @"<missing>"];
}

static NSString *BoolString(BOOL v) { return v ? @"true" : @"false"; }

static BOOL StringMatchesProbeKeywords(NSString *s) {
    if (!s.length) return NO;
    NSString *l = s.lowercaseString;
    NSArray<NSString *> *keys = @[
        @"requesttype", @"request type", @"richanalysis", @"rich analysis",
        @"vientry", @"entrytype", @"entry type", @"viewfinder", @"tamale",
        @"camera", @"visualintelligence", @"visual intelligence", @"bundleidentifier",
        @"bundle identifier", @"greymatter", @"china", @"country", @"region",
        @"availability", @"enhancedsiri", @"enhanced siri"
    ];
    for (NSString *k in keys) if ([l containsString:k]) return YES;
    return NO;
}

static NSArray<NSString *> *ExtractNulTerminatedStrings(const uint8_t *data, uint64_t size) {
    if (!data || size == 0) return @[];
    NSMutableArray<NSString *> *result = [NSMutableArray array];
    uint64_t pos = 0;
    while (pos < size) {
        const uint8_t *start = data + pos;
        const void *nul = memchr(start, 0, (size_t)(size - pos));
        uint64_t len = nul ? (uint64_t)((const uint8_t *)nul - start) : (size - pos);
        if (len > 0 && len <= 240) {
            NSData *d = [NSData dataWithBytes:start length:(NSUInteger)len];
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s.length) {
                NSUInteger printable = 0;
                for (NSUInteger i = 0; i < s.length; i++) {
                    unichar c = [s characterAtIndex:i];
                    if ((c >= 0x20 && c < 0x7f) || c >= 0xa0) printable++;
                }
                if (printable * 10 >= s.length * 8) [result addObject:s];
            }
        }
        if (!nul) break;
        pos += len + 1;
    }
    return result;
}

static const struct mach_header_64 *LoadedHeaderContaining(NSString *needle) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *path = [NSString stringWithUTF8String:name];
        if ([path containsString:needle]) {
            const struct mach_header *h = _dyld_get_image_header(i);
            if (h && h->magic == MH_MAGIC_64) return (const struct mach_header_64 *)h;
        }
    }
    return NULL;
}

static void AppendSectionKeywordContext(NSMutableString *out,
                                        NSString *imageNeedle,
                                        const char *seg,
                                        const char *sect) {
    const struct mach_header_64 *h = LoadedHeaderContaining(imageNeedle);
    [out appendFormat:@"\n--- %@ %s,%s string context ---\n", imageNeedle, seg, sect];
    if (!h) {
        [out appendString:@"image header not found\n"];
        return;
    }
    unsigned long size = 0;
    const uint8_t *bytes = getsectiondata(h, seg, sect, &size);
    if (!bytes || size == 0) {
        [out appendFormat:@"section unavailable size=%lu\n", size];
        return;
    }
    NSArray<NSString *> *strings = ExtractNulTerminatedStrings(bytes, (uint64_t)size);
    [out appendFormat:@"sectionSize=%lu parsedStrings=%lu\n", size, (unsigned long)strings.count];

    NSMutableIndexSet *wanted = [NSMutableIndexSet indexSet];
    NSUInteger directMatches = 0;
    for (NSUInteger i = 0; i < strings.count; i++) {
        if (!StringMatchesProbeKeywords(strings[i])) continue;
        directMatches++;
        NSUInteger lo = (i > 4) ? i - 4 : 0;
        NSUInteger hi = MIN(strings.count - 1, i + 4);
        [wanted addIndexesInRange:NSMakeRange(lo, hi - lo + 1)];
        if (directMatches >= 80) break;
    }
    [out appendFormat:@"keywordMatches=%lu contextStrings=%lu\n",
     (unsigned long)directMatches, (unsigned long)wanted.count];
    __block NSUInteger emitted = 0;
    [wanted enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop) {
        if (emitted >= 360) { *stop = YES; return; }
        NSString *mark = StringMatchesProbeKeywords(strings[idx]) ? @"*" : @" ";
        [out appendFormat:@"%@ [%04lu] %@\n", mark, (unsigned long)idx, strings[idx]];
        emitted++;
    }];
    if (wanted.count > emitted) [out appendFormat:@"... %lu context strings omitted\n", (unsigned long)(wanted.count - emitted)];
}

static void AppendRequestConfigMetadata(NSMutableString *out, Class configClass) {
    [out appendString:@"\n--- VICVisualIntelligenceAnalysisRequestConfig metadata ---\n"];
    if (!configClass) {
        [out appendString:@"class missing\n"];
        return;
    }
    AppendInstanceSelector(out, configClass, @"init");
    AppendInstanceSelector(out, configClass, @"requestType");
    AppendInstanceSelector(out, configClass, @"setRequestType:");
    AppendInstanceSelector(out, configClass, @"environmentBundleIdentifier");
    AppendInstanceSelector(out, configClass, @"vluAuthorized");

    unsigned int pc = 0;
    objc_property_t *props = class_copyPropertyList(configClass, &pc);
    [out appendFormat:@"properties=%u\n", pc];
    for (unsigned int i = 0; i < pc; i++) {
        const char *n = property_getName(props[i]);
        const char *a = property_getAttributes(props[i]);
        [out appendFormat:@"  property %s attrs=%s\n", n ?: "<nil>", a ?: "<nil>"];
    }
    free(props);

    unsigned int ic = 0;
    Ivar *ivars = class_copyIvarList(configClass, &ic);
    [out appendFormat:@"ivars=%u\n", ic];
    for (unsigned int i = 0; i < ic; i++) {
        const char *n = ivar_getName(ivars[i]);
        const char *t = ivar_getTypeEncoding(ivars[i]);
        [out appendFormat:@"  ivar %s type=%s offset=%td\n", n ?: "<nil>", t ?: "<nil>", ivar_getOffset(ivars[i])];
    }
    free(ivars);

    // A fresh config object's getters are safe to inspect; no setter is called.
    if (InstanceMethodHasTypes(configClass, @selector(init), "@16@0:8")) {
        id obj = ((id (*)(id, SEL))objc_msgSend)((id)configClass, @selector(alloc));
        obj = ((id (*)(id, SEL))objc_msgSend)(obj, @selector(init));
        [out appendFormat:@"freshConfig=%@\n", obj ?: @"<nil>"];
        if (obj && InstanceMethodHasTypes(configClass, NSSelectorFromString(@"requestType"), "q16@0:8")) {
            long long v = ((long long (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"requestType"));
            [out appendFormat:@"freshConfig.requestType(raw)=%lld\n", v];
        } else if (obj && InstanceMethodHasTypes(configClass, NSSelectorFromString(@"requestType"), "Q16@0:8")) {
            unsigned long long v = ((unsigned long long (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"requestType"));
            [out appendFormat:@"freshConfig.requestType(raw)=%llu\n", v];
        }
        if (obj && InstanceMethodHasTypes(configClass, NSSelectorFromString(@"environmentBundleIdentifier"), "@16@0:8")) {
            id v = ((id (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"environmentBundleIdentifier"));
            [out appendFormat:@"freshConfig.environmentBundleIdentifier=%@\n", v ?: @"<nil>"];
        }
    }
}

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI Request-Type CRASH-SAFE READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: no call to +isRichAnalysisAvailableForRequestType:bundleID:. The previous build proved that probing arbitrary integer raw values can trigger Swift _diagnoseUnexpectedEnumCaseValue (SIGTRAP), which Objective-C @try cannot catch. This build uses only ABI-verified read-only getters, Objective-C metadata, and loaded Mach-O string-section inspection. No setters, preheat, XPC availability call, swizzling/IMP replacement, preference/MobileGestalt writes, respring or reboot.\n\n"];

    const char *vicPath = "/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore";
    const char *vkPath  = "/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore";
    void *vicHandle = dlopen(vicPath, RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen(vkPath, RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen = %@\n", vicHandle ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen = %@\n", vkHandle ? @"OK" : @"FAIL"];

    Class vic = NSClassFromString(@"VICVisualIntelligenceAnalyzer");
    Class vkc = NSClassFromString(@"VKCImageAnalyzer");
    Class config = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");
    [out appendFormat:@"VICVisualIntelligenceAnalyzer = %@\n", vic ? @"FOUND" : @"MISSING"];
    [out appendFormat:@"VKCImageAnalyzer = %@\n", vkc ? @"FOUND" : @"MISSING"];
    [out appendFormat:@"VICVisualIntelligenceAnalysisRequestConfig = %@\n", config ? @"FOUND" : @"MISSING"];

    [out appendString:@"\n--- exact selector inventory ---\n"];
    if (vic) {
        AppendClassSelector(out, vic, @"isRichAnalysisAvailableForRequestType:bundleID:");
        AppendClassSelector(out, vic, @"shouldShowEnhancedSiri");
        AppendClassSelector(out, vic, @"preheat");
        AppendClassSelector(out, vic, @"preheatFor:environmentBundleIdentifier:");
    }
    if (vkc) {
        AppendClassSelector(out, vkc, @"supportedAnalysisTypes");
        AppendClassSelector(out, vkc, @"deviceIsEligibleForVI");
        AppendClassSelector(out, vkc, @"isEnhancedSiriAvailable");
        AppendClassSelector(out, vkc, @"isEnhancedSiriEnabled");
        AppendClassSelector(out, vkc, @"shouldShowEnhancedSiri");
        AppendClassSelector(out, vkc, @"viEntryType");
        AppendClassSelector(out, vkc, @"setViEntryType:");
        AppendClassSelector(out, vkc, @"viBundleIdentifier");
        AppendClassSelector(out, vkc, @"setViBundleIdentifier:");
    }

    [out appendString:@"\n--- VKCImageAnalyzer safe read-only baseline ---\n"];
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
            [out appendFormat:@"viEntryType(raw) = %lld\n", v];
        } else if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"viEntryType"), "Q16@0:8")) {
            unsigned long long v = ((unsigned long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viEntryType"));
            [out appendFormat:@"viEntryType(raw) = %llu\n", v];
        } else {
            [out appendFormat:@"viEntryType = SKIPPED ABI=%@\n", TypeEncodingForClassMethod(vkc, NSSelectorFromString(@"viEntryType"))];
        }
        if (ClassMethodHasTypes(vkc, NSSelectorFromString(@"viBundleIdentifier"), "@16@0:8")) {
            id v = ((id (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viBundleIdentifier"));
            [out appendFormat:@"viBundleIdentifier = %@\n", v ?: @"<nil>"];
        }
    }

    AppendRequestConfigMetadata(out, config);

    if (vic && ClassMethodHasTypes(vic, NSSelectorFromString(@"shouldShowEnhancedSiri"), "B16@0:8")) {
        BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(vic, NSSelectorFromString(@"shouldShowEnhancedSiri"));
        [out appendFormat:@"\nVIC.shouldShowEnhancedSiri = %@\n", BoolString(v)];
    }

    // Reflection/cstring inspection is deliberately used instead of calling the enum-consuming
    // rich-analysis API with guessed raw values.
    AppendSectionKeywordContext(out, @"VisualIntelligenceCore.framework", "__TEXT", "__swift5_reflstr");
    AppendSectionKeywordContext(out, @"VisualIntelligenceCore.framework", "__TEXT", "__cstring");
    AppendSectionKeywordContext(out, @"VisionKitCore.framework", "__TEXT", "__cstring");

    [out appendString:@"\nIMPORTANT: +isRichAnalysisAvailableForRequestType:bundleID: was NOT invoked in this build. The previous SIGTRAP is now explained as a Swift enum raw-value trap rather than an Objective-C exception.\n"];
    [out appendString:@"===============================================================================\n"];
    return out;
}
