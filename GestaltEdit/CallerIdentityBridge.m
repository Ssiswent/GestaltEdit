#import "CallerIdentityBridge.h"

#import <dlfcn.h>
#import <objc/runtime.h>
#import <stdlib.h>

static BOOL ContainsAny(NSString *value, NSArray<NSString *> *needles) {
    if (!value.length) return NO;
    NSString *s = value.lowercaseString;
    for (NSString *needle in needles) {
        if ([s containsString:needle.lowercaseString]) return YES;
    }
    return NO;
}

static NSString *CStringOrNil(const char *s) {
    if (!s) return @"<nil>";
    NSString *v = [NSString stringWithUTF8String:s];
    return v ?: @"<invalid-utf8>";
}

static NSArray<NSString *> *ClassKeywords(void) {
    return @[
        @"availability", @"available", @"eligibility", @"eligible", @"greymatter",
        @"tamale", @"visualintelligence", @"visual intelligence", @"policy",
        @"region", @"country", @"china", @"locale", @"usecase", @"use case",
        @"feature", @"viewfinder", @"camera", @"gms", @"access"
    ];
}

static NSArray<NSString *> *SelectorKeywords(void) {
    return @[
        @"availability", @"available", @"unavailable", @"reason", @"eligible",
        @"eligibility", @"greymatter", @"tamale", @"region", @"country", @"china",
        @"policy", @"locale", @"usecase", @"use case", @"partner", @"access",
        @"enabled", @"support", @"preheat", @"feature", @"viewfinder", @"camera",
        @"gms", @"asset", @"current", @"status"
    ];
}

static BOOL IsTargetImage(NSString *image) {
    if (!image.length) return NO;
    NSArray *targets = @[
        @"VisualIntelligenceCore.framework",
        @"VisualIntelligenceServices.framework",
        @"VisionKitCore.framework",
        @"GenerativeModels.framework"
    ];
    return ContainsAny(image, targets);
}

static BOOL ClassHasInterestingMethod(Class cls) {
    if (!cls) return NO;
    NSArray *keywords = SelectorKeywords();
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    BOOL hit = NO;
    for (unsigned int i = 0; i < count; i++) {
        NSString *name = NSStringFromSelector(method_getName(methods[i]));
        if (ContainsAny(name, keywords)) { hit = YES; break; }
    }
    free(methods);
    if (hit) return YES;

    Class meta = object_getClass(cls);
    count = 0;
    methods = class_copyMethodList(meta, &count);
    for (unsigned int i = 0; i < count; i++) {
        NSString *name = NSStringFromSelector(method_getName(methods[i]));
        if (ContainsAny(name, keywords)) { hit = YES; break; }
    }
    free(methods);
    return hit;
}

static void AppendMethodList(NSMutableString *out, Class owner, NSString *label, BOOL dumpAll) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(owner, &count);
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    NSArray *keywords = SelectorKeywords();

    for (unsigned int i = 0; i < count; i++) {
        SEL sel = method_getName(methods[i]);
        NSString *name = NSStringFromSelector(sel) ?: @"<unknown>";
        if (!dumpAll && !ContainsAny(name, keywords)) continue;
        const char *types = method_getTypeEncoding(methods[i]);
        [lines addObject:[NSString stringWithFormat:@"%@  types=%@", name, CStringOrNil(types)]];
    }
    free(methods);

    [lines sortUsingSelector:@selector(compare:)];
    [out appendFormat:@"  %@ (%lu%@):\n", label, (unsigned long)lines.count,
     (!dumpAll && lines.count < count) ? @" filtered" : @""];
    NSUInteger cap = MIN((NSUInteger)120, lines.count);
    for (NSUInteger i = 0; i < cap; i++) [out appendFormat:@"    %@\n", lines[i]];
    if (lines.count > cap) [out appendFormat:@"    ... %lu more omitted\n", (unsigned long)(lines.count - cap)];
}

static void AppendProperties(NSMutableString *out, Class cls) {
    unsigned int count = 0;
    objc_property_t *props = class_copyPropertyList(cls, &count);
    if (!props || count == 0) { free(props); return; }
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (unsigned int i = 0; i < count; i++) {
        const char *name = property_getName(props[i]);
        const char *attrs = property_getAttributes(props[i]);
        NSString *n = CStringOrNil(name);
        if (!ContainsAny(n, ClassKeywords()) && !ContainsAny(n, SelectorKeywords())) continue;
        [lines addObject:[NSString stringWithFormat:@"%@ attrs=%@", n, CStringOrNil(attrs)]];
    }
    free(props);
    [lines sortUsingSelector:@selector(compare:)];
    if (!lines.count) return;
    [out appendFormat:@"  interesting properties (%lu):\n", (unsigned long)lines.count];
    for (NSString *line in lines) [out appendFormat:@"    %@\n", line];
}

static void AppendIvars(NSMutableString *out, Class cls) {
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList(cls, &count);
    if (!ivars || count == 0) { free(ivars); return; }
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (unsigned int i = 0; i < count; i++) {
        NSString *name = CStringOrNil(ivar_getName(ivars[i]));
        if (!ContainsAny(name, ClassKeywords()) && !ContainsAny(name, SelectorKeywords())) continue;
        [lines addObject:[NSString stringWithFormat:@"%@ type=%@ offset=%td",
                          name, CStringOrNil(ivar_getTypeEncoding(ivars[i])), ivar_getOffset(ivars[i])]];
    }
    free(ivars);
    [lines sortUsingSelector:@selector(compare:)];
    if (!lines.count) return;
    [out appendFormat:@"  interesting ivars (%lu):\n", (unsigned long)lines.count];
    for (NSString *line in lines) [out appendFormat:@"    %@\n", line];
}

static void AppendClassDetail(NSMutableString *out, Class cls) {
    NSString *name = NSStringFromClass(cls) ?: @"<unknown>";
    NSString *image = CStringOrNil(class_getImageName(cls));
    Class superclass = class_getSuperclass(cls);
    NSString *superName = superclass ? (NSStringFromClass(superclass) ?: @"<unknown>") : @"<nil>";
    BOOL nameInteresting = ContainsAny(name, ClassKeywords());

    [out appendFormat:@"\n--- class %@ ---\n", name];
    [out appendFormat:@"image=%@\n", image];
    [out appendFormat:@"superclass=%@\n", superName];
    [out appendFormat:@"nameKeywordMatch=%@\n", nameInteresting ? @"true" : @"false"];

    AppendMethodList(out, cls, @"instance methods", nameInteresting);
    AppendMethodList(out, object_getClass(cls), @"class methods", nameInteresting);
    AppendProperties(out, cls);
    AppendIvars(out, cls);
}

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI Availability Runtime Metadata READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: Objective-C runtime metadata only. Frameworks are dlopen'ed and class/method/property/ivar metadata is enumerated. No availability getter is invoked, no XPC connection, no method swizzling/IMP replacement, no setters, no preference/MobileGestalt writes, no respring/reboot.\n"];
    [out appendString:@"PURPOSE: previous probes proved LaunchServices/libproc/protected Camera code-signing paths are sandbox-blocked, while Camera itself logs a caller-context-specific VI denial. This probe identifies the private VI availability/policy classes and selectors so the next probe can call only ABI-verified read-only APIs.\n\n"];

    NSArray<NSString *> *frameworks = @[
        @"/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels",
        @"/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore",
        @"/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore",
        @"/System/Library/PrivateFrameworks/VisualIntelligenceServices.framework/VisualIntelligenceServices"
    ];

    [out appendString:@"--- framework loads ---\n"];
    for (NSString *path in frameworks) {
        dlerror();
        void *handle = dlopen(path.UTF8String, RTLD_NOW | RTLD_LOCAL);
        const char *err = dlerror();
        [out appendFormat:@"%@ -> %@", path.lastPathComponent, handle ? @"OK" : @"FAIL"];
        if (!handle && err) [out appendFormat:@" (%@)", CStringOrNil(err)];
        [out appendString:@"\n"];
    }

    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    NSMutableArray<NSDictionary *> *matches = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSNumber *> *imageCounts = [NSMutableDictionary dictionary];

    for (unsigned int i = 0; i < count; i++) {
        Class cls = classes[i];
        NSString *image = CStringOrNil(class_getImageName(cls));
        if (!IsTargetImage(image)) continue;
        NSString *imageLeaf = image.lastPathComponent ?: image;
        imageCounts[imageLeaf] = @([imageCounts[imageLeaf] unsignedIntegerValue] + 1);

        NSString *name = NSStringFromClass(cls) ?: @"<unknown>";
        BOOL nameHit = ContainsAny(name, ClassKeywords());
        BOOL methodHit = ClassHasInterestingMethod(cls);
        if (!nameHit && !methodHit) continue;
        [matches addObject:@{@"class": cls, @"name": name, @"image": image, @"nameHit": @(nameHit), @"methodHit": @(methodHit)}];
    }
    free(classes);

    [matches sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSString *ai = a[@"image"];
        NSString *bi = b[@"image"];
        NSComparisonResult r = [ai compare:bi];
        if (r != NSOrderedSame) return r;
        return [a[@"name"] compare:b[@"name"]];
    }];

    [out appendString:@"\n--- target framework Objective-C class counts ---\n"];
    NSArray *sortedImages = [[imageCounts allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *image in sortedImages) [out appendFormat:@"%@ = %@ classes\n", image, imageCounts[image]];
    [out appendFormat:@"candidate classes = %lu\n", (unsigned long)matches.count];

    [out appendString:@"\n--- candidate class index ---\n"];
    NSUInteger indexCap = MIN((NSUInteger)300, matches.count);
    for (NSUInteger i = 0; i < indexCap; i++) {
        NSDictionary *item = matches[i];
        [out appendFormat:@"[%03lu] %@ | %@ | nameHit=%@ methodHit=%@\n",
         (unsigned long)(i + 1), item[@"name"], [item[@"image"] lastPathComponent],
         [item[@"nameHit"] boolValue] ? @"Y" : @"N", [item[@"methodHit"] boolValue] ? @"Y" : @"N"];
    }
    if (matches.count > indexCap) [out appendFormat:@"... %lu more candidates omitted from index\n", (unsigned long)(matches.count - indexCap)];

    [out appendString:@"\n--- detailed runtime metadata ---\n"];
    NSUInteger detailCap = MIN((NSUInteger)180, matches.count);
    for (NSUInteger i = 0; i < detailCap; i++) {
        Class cls = matches[i][@"class"];
        AppendClassDetail(out, cls);
    }
    if (matches.count > detailCap) [out appendFormat:@"\n... %lu candidate classes omitted from detailed section\n", (unsigned long)(matches.count - detailCap)];

    [out appendString:@"\n===============================================================================\n"];
    return out;
}
