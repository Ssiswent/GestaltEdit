#import "VICallerContextMetadataProbe.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>

static BOOL VIMetaInteresting(NSString *s) {
    if (!s.length) return NO;
    NSString *x = s.lowercaseString;
    NSArray<NSString *> *needles = @[
        @"availability", @"eligible", @"supportsvi", @"supportvi",
        @"visualintelligence", @"greymatter", @"generativemodel", @"gms",
        @"china", @"country", @"region", @"cellular", @"storefront",
        @"locale", @"language", @"gestalt", @"mgcopy", @"mobilegestalt",
        @"audit", @"entitlement", @"caller", @"process", @"bundle",
        @"settings.appleintelligence", @"gvicc", @"preheat"
    ];
    for (NSString *needle in needles) {
        if ([x containsString:needle]) return YES;
    }
    return NO;
}

static BOOL VIMetaTargetImagePath(const char *path) {
    if (!path) return NO;
    NSString *p = [NSString stringWithUTF8String:path];
    return [p containsString:@"VisualIntelligenceCore.framework"] ||
           [p containsString:@"VisionKitCore.framework"] ||
           [p containsString:@"GenerativeModels.framework"];
}

static NSString *VIMetaShortImage(const char *path) {
    if (!path) return @"<unknown>";
    NSString *p = [NSString stringWithUTF8String:path];
    if ([p containsString:@"VisualIntelligenceCore.framework"]) return @"VisualIntelligenceCore";
    if ([p containsString:@"VisionKitCore.framework"]) return @"VisionKitCore";
    if ([p containsString:@"GenerativeModels.framework"]) return @"GenerativeModels";
    return p.lastPathComponent ?: p;
}

static void VIMetaScanCStringSection(NSMutableString *out,
                                     const struct mach_header_64 *header,
                                     const char *section,
                                     NSString *imageName,
                                     NSUInteger cap) {
    unsigned long size = 0;
    const uint8_t *data = getsectiondata(header, "__TEXT", section, &size);
    if (!data || size == 0) {
        [out appendFormat:@"%@ %@=<missing>\n", imageName, [NSString stringWithUTF8String:section]];
        return;
    }

    [out appendFormat:@"\n--- %@ %s selected strings ---\n", imageName, section];
    NSUInteger emitted = 0;
    unsigned long offset = 0;
    while (offset < size && emitted < cap) {
        const char *s = (const char *)(data + offset);
        unsigned long remaining = size - offset;
        const void *nul = memchr(s, 0, remaining);
        if (!nul) break;
        size_t len = (const char *)nul - s;
        if (len > 0 && len < 1024) {
            NSString *value = [[NSString alloc] initWithBytes:s length:len encoding:NSUTF8StringEncoding];
            if (value && VIMetaInteresting(value)) {
                [out appendFormat:@"%@ %s+0x%lx: %@\n", imageName, section, offset, value];
                emitted++;
            }
        }
        offset += (unsigned long)len + 1;
    }
    [out appendFormat:@"selected=%lu sectionSize=%lu\n", (unsigned long)emitted, size];
}

static void VIMetaDumpClass(NSMutableString *out, Class cls, BOOL forceFull) {
    const char *cn = class_getName(cls);
    NSString *className = cn ? [NSString stringWithUTF8String:cn] : @"<unknown>";
    const char *imagePath = class_getImageName(cls);
    NSString *image = VIMetaShortImage(imagePath);

    BOOL classInteresting = forceFull || VIMetaInteresting(className);
    NSMutableArray<NSString *> *members = [NSMutableArray array];

    unsigned int ivarCount = 0;
    Ivar *ivars = class_copyIvarList(cls, &ivarCount);
    for (unsigned int i = 0; i < ivarCount; i++) {
        const char *n = ivar_getName(ivars[i]);
        const char *t = ivar_getTypeEncoding(ivars[i]);
        NSString *name = n ? [NSString stringWithUTF8String:n] : @"<nil>";
        if (forceFull || VIMetaInteresting(name)) {
            [members addObject:[NSString stringWithFormat:@"  ivar %@ type=%s offset=%td", name, t ?: "?", ivar_getOffset(ivars[i])]];
        }
    }
    free(ivars);

    unsigned int propCount = 0;
    objc_property_t *props = class_copyPropertyList(cls, &propCount);
    for (unsigned int i = 0; i < propCount; i++) {
        const char *n = property_getName(props[i]);
        const char *a = property_getAttributes(props[i]);
        NSString *name = n ? [NSString stringWithUTF8String:n] : @"<nil>";
        if (forceFull || VIMetaInteresting(name)) {
            [members addObject:[NSString stringWithFormat:@"  property %@ attrs=%s", name, a ?: "?"]];
        }
    }
    free(props);

    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        SEL sel = method_getName(methods[i]);
        NSString *name = NSStringFromSelector(sel);
        if (forceFull || VIMetaInteresting(name)) {
            const char *types = method_getTypeEncoding(methods[i]);
            [members addObject:[NSString stringWithFormat:@"  - %@ types=%s", name, types ?: "?"]];
        }
    }
    free(methods);

    Class meta = object_getClass(cls);
    unsigned int classMethodCount = 0;
    Method *classMethods = class_copyMethodList(meta, &classMethodCount);
    for (unsigned int i = 0; i < classMethodCount; i++) {
        SEL sel = method_getName(classMethods[i]);
        NSString *name = NSStringFromSelector(sel);
        if (forceFull || VIMetaInteresting(name)) {
            const char *types = method_getTypeEncoding(classMethods[i]);
            [members addObject:[NSString stringWithFormat:@"  + %@ types=%s", name, types ?: "?"]];
        }
    }
    free(classMethods);

    if (classInteresting || members.count > 0) {
        [out appendFormat:@"\nclass=%@ image=%@\n", className, image];
        for (NSString *line in members) [out appendFormat:@"%@\n", line];
    }
}

static void VIMetaRuntimeSurface(NSMutableString *out) {
    [out appendString:@"\n--- focused Objective-C runtime surfaces ---\n"];
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        [out appendString:@"objc_getClassList returned no classes\n"];
        return;
    }
    Class *classes = (__unsafe_unretained Class *)calloc((size_t)count, sizeof(Class));
    count = objc_getClassList(classes, count);
    NSUInteger emitted = 0;
    for (int i = 0; i < count && emitted < 300; i++) {
        Class cls = classes[i];
        const char *path = class_getImageName(cls);
        if (!VIMetaTargetImagePath(path)) continue;
        NSString *name = [NSString stringWithUTF8String:class_getName(cls) ?: ""];
        BOOL force = [name isEqualToString:@"VKCGMAvailability"] ||
                     [name isEqualToString:@"GMAvailabilityWrapper"] ||
                     [name containsString:@"GreymatterAvailability"];

        NSUInteger before = out.length;
        VIMetaDumpClass(out, cls, force);
        if (out.length > before) emitted++;
    }
    free(classes);
    [out appendFormat:@"runtimeClassesEmitted=%lu\n", (unsigned long)emitted];

    [out appendString:@"\n--- matching Objective-C protocols ---\n"];
    unsigned int protocolCount = 0;
    Protocol *__unsafe_unretained *protocols = objc_copyProtocolList(&protocolCount);
    NSUInteger protocolEmitted = 0;
    for (unsigned int i = 0; i < protocolCount && protocolEmitted < 100; i++) {
        const char *pn = protocol_getName(protocols[i]);
        NSString *name = pn ? [NSString stringWithUTF8String:pn] : @"";
        if (!VIMetaInteresting(name)) continue;
        [out appendFormat:@"protocol=%@\n", name];
        protocolEmitted++;
    }
    free(protocols);
    [out appendFormat:@"protocolsEmitted=%lu\n", (unsigned long)protocolEmitted];
}

NSString *VICallerContextMetadataGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI CALLER-CONTEXT / AIAVAILABILITY METADATA READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSISO8601DateFormatter new].stringFromDate([NSDate date])];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: framework dlopen + mapped Mach-O string-section inspection + Objective-C runtime metadata enumeration only. No private availability getters/setters are invoked, no XPC, no swizzling/IMP replacement, no preferences/MobileGestalt/file writes, no sandbox-extension access, no respring/reboot.\n\n"];

    NSArray<NSString *> *paths = @[
        @"/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore",
        @"/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore",
        @"/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels"
    ];
    for (NSString *path in paths) {
        void *h = dlopen(path.UTF8String, RTLD_NOW);
        [out appendFormat:@"dlopen %@ = %@\n", path.lastPathComponent, h ? @"OK" : @"FAILED"];
    }

    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!VIMetaTargetImagePath(path)) continue;
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) continue;
        NSString *imageName = VIMetaShortImage(path);
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)mh;
        VIMetaScanCStringSection(out, h64, "__cstring", imageName, 350);
        VIMetaScanCStringSection(out, h64, "__swift5_reflstr", imageName, 350);
    }

    VIMetaRuntimeSurface(out);

    [out appendString:@"\n--- interpretation targets ---\n"];
    [out appendString:@"1. If VisionKitCore itself exposes China/country/cellular/MobileGestalt availability surfaces, prioritize the early VK AIAvailability gate.\n"];
    [out appendString:@"2. If those inputs are absent from VisionKitCore but present in VisualIntelligenceCore/Tamale-related metadata, Camera's extra policy likely sits above VKCGMAvailability.\n"];
    [out appendString:@"3. caller/audit/entitlement/bundle surfaces are metadata clues only; this build does not spoof identity or call secure availability XPC.\n"];
    [out appendString:@"============================================================================================\n"];
    return out;
}
