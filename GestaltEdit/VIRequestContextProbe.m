#import "VIRequestContextProbe.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <stdint.h>
#include <string.h>

typedef struct __attribute__((packed)) {
    int32_t mangledTypeName;
    int32_t superclass;
    uint16_t kind;
    uint16_t fieldRecordSize;
    uint32_t numFields;
} VIRCFieldDescriptor;

typedef struct __attribute__((packed)) {
    uint32_t flags;
    int32_t mangledTypeName;
    int32_t fieldName;
} VIRCFieldRecord;

typedef struct {
    const struct mach_header_64 *header;
    intptr_t slide;
} VIRCImage;

static BOOL VIRCFindImage(NSString *needle, VIRCImage *outImage) {
    if (!outImage) return NO;
    memset(outImage, 0, sizeof(*outImage));
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if (![path containsString:needle]) continue;
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        outImage->header = (const struct mach_header_64 *)h;
        outImage->slide = _dyld_get_image_vmaddr_slide(i);
        return YES;
    }
    return NO;
}

static BOOL VIRCContains(VIRCImage image, const void *ptr, size_t len) {
    if (!image.header || !ptr) return NO;
    uintptr_t p = (uintptr_t)ptr;
    if (len > UINTPTR_MAX - p) return NO;
    uintptr_t end = p + len;
    const uint8_t *cmd = (const uint8_t *)(image.header + 1);
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t start = (uintptr_t)(seg->vmaddr + image.slide);
            uintptr_t stop = start + (uintptr_t)seg->vmsize;
            if (p >= start && end <= stop) return YES;
        }
        cmd += lc->cmdsize;
    }
    return NO;
}

static const uint8_t *VIRCRel32(const int32_t *field, VIRCImage image) {
    if (!field || !VIRCContains(image, field, sizeof(*field))) return NULL;
    int32_t rel = 0;
    memcpy(&rel, field, sizeof(rel));
    if (!rel) return NULL;
    const uint8_t *target = (const uint8_t *)field + rel;
    return VIRCContains(image, target, 1) ? target : NULL;
}

static NSString *VIRCCString(const uint8_t *ptr, VIRCImage image, NSUInteger cap) {
    if (!ptr || !VIRCContains(image, ptr, 1)) return nil;
    const uint8_t *cmd = (const uint8_t *)(image.header + 1);
    size_t available = 0;
    uintptr_t p = (uintptr_t)ptr;
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t start = (uintptr_t)(seg->vmaddr + image.slide);
            uintptr_t stop = start + (uintptr_t)seg->vmsize;
            if (p >= start && p < stop) {
                available = MIN((size_t)(stop - p), (size_t)cap);
                break;
            }
        }
        cmd += lc->cmdsize;
    }
    if (!available) return nil;
    const void *nul = memchr(ptr, 0, available);
    if (!nul) return nil;
    NSUInteger len = (NSUInteger)((const uint8_t *)nul - ptr);
    NSData *data = [NSData dataWithBytes:ptr length:len];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static BOOL VIRCContextPlausible(const uint8_t *ctx, VIRCImage image) {
    if (!ctx || !VIRCContains(image, ctx, 12)) return NO;
    uint32_t flags = 0;
    memcpy(&flags, ctx, 4);
    uint32_t kind = flags & 0x1f;
    if (!(kind == 0 || kind == 1 || kind == 2 || kind == 3 || kind == 4 ||
          kind == 16 || kind == 17 || kind == 18)) return NO;
    NSString *name = VIRCCString(VIRCRel32((const int32_t *)(ctx + 8), image), image, 200);
    return name.length > 0;
}

static const uint8_t *VIRCResolveDirectContext(const uint8_t *mangled, VIRCImage image) {
    if (!mangled || !VIRCContains(image, mangled, 5) || mangled[0] != 0x01) return NULL;
    int32_t rel = 0;
    memcpy(&rel, mangled + 1, 4);

    // Current 24A5390f field metadata resolves these references from the
    // 4-byte payload address (mangled + 1). Keep the control-byte base as a
    // secondary plausibility check only.
    const uint8_t *payloadBase = mangled + 1;
    const uint8_t *candidate = payloadBase + rel;
    if (VIRCContextPlausible(candidate, image)) return candidate;

    candidate = mangled + rel;
    if (VIRCContextPlausible(candidate, image)) return candidate;
    return NULL;
}

static NSString *VIRCContextName(const uint8_t *ctx, VIRCImage image) {
    if (!ctx) return nil;
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    const uint8_t *cur = ctx;
    for (NSUInteger depth = 0; depth < 10 && cur; depth++) {
        if (!VIRCContains(image, cur, 12)) break;
        uint32_t flags = 0;
        memcpy(&flags, cur, 4);
        uint32_t kind = flags & 0x1f;
        NSString *name = VIRCCString(VIRCRel32((const int32_t *)(cur + 8), image), image, 200);
        if (name.length) [parts insertObject:name atIndex:0];
        if (kind == 0) break;
        cur = VIRCRel32((const int32_t *)(cur + 4), image);
    }
    return parts.count ? [parts componentsJoinedByString:@"."] : nil;
}

static const VIRCFieldDescriptor *VIRCDescriptorForContext(const uint8_t *ctx, VIRCImage image) {
    if (!ctx || !VIRCContains(image, ctx, 20)) return NULL;
    uint32_t flags = 0;
    memcpy(&flags, ctx, 4);
    uint32_t kind = flags & 0x1f;
    if (!(kind == 16 || kind == 17 || kind == 18)) return NULL;
    const uint8_t *fd = VIRCRel32((const int32_t *)(ctx + 16), image);
    return fd && VIRCContains(image, fd, sizeof(VIRCFieldDescriptor))
        ? (const VIRCFieldDescriptor *)fd : NULL;
}

static BOOL VIRCValidDescriptor(const VIRCFieldDescriptor *fd, VIRCImage image) {
    if (!fd || !VIRCContains(image, fd, sizeof(*fd))) return NO;
    if (fd->fieldRecordSize < sizeof(VIRCFieldRecord) || fd->fieldRecordSize > 128) return NO;
    if (fd->numFields > 1024) return NO;
    uint64_t total = sizeof(*fd) + (uint64_t)fd->fieldRecordSize * fd->numFields;
    return total <= SIZE_MAX && VIRCContains(image, fd, (size_t)total);
}

static void VIRCAppendRequestTypeCases(NSMutableString *out, VIRCImage image) {
    [out appendString:@"\n--- VICVisualIntelligenceAnalysisRequestType: real case names from Swift metadata ---\n"];
    unsigned long size = 0;
    const uint8_t *section = getsectiondata(image.header, "__TEXT", "__swift5_fieldmd", &size);
    if (!section || size < sizeof(VIRCFieldDescriptor)) {
        [out appendFormat:@"field metadata unavailable size=%lu\n", size];
        return;
    }

    const uint8_t *end = section + size;
    const uint8_t *cursor = section;
    BOOL found = NO;
    NSUInteger scanned = 0;

    while (cursor + sizeof(VIRCFieldDescriptor) <= end && scanned < 10000) {
        const VIRCFieldDescriptor *fd = (const VIRCFieldDescriptor *)cursor;
        if (!VIRCValidDescriptor(fd, image)) {
            cursor += 4;
            scanned++;
            continue;
        }

        const uint8_t *records = cursor + sizeof(*fd);
        const uint8_t *requestTypeMangled = NULL;
        BOOL hasEnvironmentBundle = NO;
        for (uint32_t i = 0; i < fd->numFields; i++) {
            const VIRCFieldRecord *fr =
                (const VIRCFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
            NSString *fieldName = VIRCCString(VIRCRel32(&fr->fieldName, image), image, 160);
            if ([fieldName isEqualToString:@"environmentBundleIdentifier"]) hasEnvironmentBundle = YES;
            if ([fieldName isEqualToString:@"requestType"]) {
                requestTypeMangled = VIRCRel32(&fr->mangledTypeName, image);
            }
        }

        if (requestTypeMangled && hasEnvironmentBundle) {
            const uint8_t *ctx = VIRCResolveDirectContext(requestTypeMangled, image);
            NSString *name = VIRCContextName(ctx, image);
            const VIRCFieldDescriptor *enumFD = VIRCDescriptorForContext(ctx, image);
            if (ctx && name.length && enumFD && VIRCValidDescriptor(enumFD, image) &&
                enumFD->kind == 2 && enumFD->numFields == 5) {
                [out appendFormat:@"context=%@\n", name];
                const uint8_t *enumRecords = (const uint8_t *)enumFD + sizeof(*enumFD);
                for (uint32_t j = 0; j < enumFD->numFields; j++) {
                    const VIRCFieldRecord *er =
                        (const VIRCFieldRecord *)(enumRecords + (uint64_t)j * enumFD->fieldRecordSize);
                    NSString *caseName = VIRCCString(VIRCRel32(&er->fieldName, image), image, 160)
                        ?: @"<unreadable>";
                    [out appendFormat:@"  case[%u]=%@\n", j, caseName];
                }
                found = YES;
                break;
            }
        }

        uint64_t total = sizeof(*fd) + (uint64_t)fd->fieldRecordSize * fd->numFields;
        cursor += total;
        scanned++;
    }

    if (!found) {
        [out appendString:@"target enum was not resolved; listing all 5-case enum descriptors as fallback:\n"];
        cursor = section;
        scanned = 0;
        NSUInteger emitted = 0;
        while (cursor + sizeof(VIRCFieldDescriptor) <= end && scanned < 10000 && emitted < 40) {
            const VIRCFieldDescriptor *fd = (const VIRCFieldDescriptor *)cursor;
            if (!VIRCValidDescriptor(fd, image)) {
                cursor += 4;
                scanned++;
                continue;
            }
            if (fd->kind == 2 && fd->numFields == 5) {
                [out appendFormat:@"  candidate offset=0x%lx:", (unsigned long)(cursor - section)];
                const uint8_t *records = cursor + sizeof(*fd);
                for (uint32_t i = 0; i < 5; i++) {
                    const VIRCFieldRecord *fr =
                        (const VIRCFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
                    NSString *caseName = VIRCCString(VIRCRel32(&fr->fieldName, image), image, 120)
                        ?: @"?";
                    [out appendFormat:@" %@", caseName];
                }
                [out appendString:@"\n"];
                emitted++;
            }
            uint64_t total = sizeof(*fd) + (uint64_t)fd->fieldRecordSize * fd->numFields;
            cursor += total;
            scanned++;
        }
    }
}

static NSString *VIRCMethodTypes(Method method) {
    if (!method) return @"<missing>";
    const char *types = method_getTypeEncoding(method);
    return types ? [NSString stringWithUTF8String:types] : @"<nil>";
}

static BOOL VIRCNameMatches(NSString *name) {
    NSString *s = name.lowercaseString;
    NSArray<NSString *> *needles = @[
        @"vi", @"vlu", @"visual", @"authorized", @"authorization",
        @"screen", @"camera", @"environment", @"bundle", @"request",
        @"entry", @"greymatter", @"availability"
    ];
    for (NSString *needle in needles) {
        if ([s containsString:needle]) return YES;
    }
    return NO;
}

static void VIRCAppendClassMetadata(NSMutableString *out, NSString *className) {
    Class cls = NSClassFromString(className);
    [out appendFormat:@"\nclass=%@ present=%@\n", className, cls ? @"true" : @"false"];
    if (!cls) return;

    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList(cls, &count);
    [out appendFormat:@"  ivars=%u\n", count];
    for (unsigned int i = 0; i < count; i++) {
        const char *n = ivar_getName(ivars[i]);
        const char *t = ivar_getTypeEncoding(ivars[i]);
        NSString *name = n ? [NSString stringWithUTF8String:n] : @"<nil>";
        if (VIRCNameMatches(name)) {
            [out appendFormat:@"    %@ type=%s offset=%td\n",
             name, t ?: "<nil>", ivar_getOffset(ivars[i])];
        }
    }
    free(ivars);

    objc_property_t *props = class_copyPropertyList(cls, &count);
    [out appendFormat:@"  properties=%u\n", count];
    for (unsigned int i = 0; i < count; i++) {
        const char *n = property_getName(props[i]);
        const char *a = property_getAttributes(props[i]);
        NSString *name = n ? [NSString stringWithUTF8String:n] : @"<nil>";
        if (VIRCNameMatches(name)) {
            [out appendFormat:@"    %@ attrs=%s\n", name, a ?: "<nil>"];
        }
    }
    free(props);

    Method *methods = class_copyMethodList(cls, &count);
    [out appendString:@"  relevant instanceMethods:\n"];
    NSUInteger emitted = 0;
    for (unsigned int i = 0; i < count && emitted < 100; i++) {
        NSString *name = NSStringFromSelector(method_getName(methods[i]));
        if (!VIRCNameMatches(name)) continue;
        [out appendFormat:@"    - %@ types=%@\n", name, VIRCMethodTypes(methods[i])];
        emitted++;
    }
    free(methods);

    Class meta = object_getClass(cls);
    methods = meta ? class_copyMethodList(meta, &count) : NULL;
    [out appendString:@"  relevant classMethods:\n"];
    emitted = 0;
    for (unsigned int i = 0; methods && i < count && emitted < 100; i++) {
        NSString *name = NSStringFromSelector(method_getName(methods[i]));
        if (!VIRCNameMatches(name)) continue;
        [out appendFormat:@"    + %@ types=%@\n", name, VIRCMethodTypes(methods[i])];
        emitted++;
    }
    free(methods);
}

static void VIRCAppendFreshRequestConfig(NSMutableString *out) {
    [out appendString:@"\n--- fresh VICVisualIntelligenceAnalysisRequestConfig values ---\n"];
    Class cls = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");
    if (!cls) {
        [out appendString:@"class missing\n"];
        return;
    }
    id obj = ((id (*)(id, SEL))objc_msgSend)((id)cls, @selector(alloc));
    obj = ((id (*)(id, SEL))objc_msgSend)(obj, @selector(init));
    if (!obj) {
        [out appendString:@"init returned nil\n"];
        return;
    }

    SEL rtSel = NSSelectorFromString(@"requestType");
    Method rt = class_getInstanceMethod(cls, rtSel);
    NSString *rtTypes = VIRCMethodTypes(rt);
    [out appendFormat:@"requestType types=%@", rtTypes];
    if ([rtTypes isEqualToString:@"q16@0:8"]) {
        long long value = ((long long (*)(id, SEL))objc_msgSend)(obj, rtSel);
        [out appendFormat:@" value=%lld\n", value];
    } else if ([rtTypes isEqualToString:@"Q16@0:8"]) {
        unsigned long long value = ((unsigned long long (*)(id, SEL))objc_msgSend)(obj, rtSel);
        [out appendFormat:@" value=%llu\n", value];
    } else {
        [out appendString:@" value=<not-called; ABI mismatch>\n"];
    }

    for (NSString *getter in @[@"environmentBundleIdentifier", @"vluAuthorized"]) {
        SEL sel = NSSelectorFromString(getter);
        Method method = class_getInstanceMethod(cls, sel);
        NSString *types = VIRCMethodTypes(method);
        [out appendFormat:@"%@ types=%@", getter, types];
        if ([types isEqualToString:@"@16@0:8"]) {
            id value = ((id (*)(id, SEL))objc_msgSend)(obj, sel);
            [out appendFormat:@" value=%@\n", value ?: @"<nil>"];
        } else {
            [out appendString:@" value=<not-called; ABI mismatch>\n"];
        }
    }
}

static void VIRCAppendVIConfigurationValues(NSMutableString *out) {
    [out appendString:@"\n--- fresh VKCImageAnalyzerRequestVIConfiguration known getters ---\n"];
    Class cls = NSClassFromString(@"VKCImageAnalyzerRequestVIConfiguration");
    if (!cls) {
        [out appendString:@"class missing\n"];
        return;
    }
    Method initMethod = class_getInstanceMethod(cls, @selector(init));
    NSString *initTypes = VIRCMethodTypes(initMethod);
    [out appendFormat:@"init types=%@\n", initTypes];
    if (![initTypes isEqualToString:@"@16@0:8"]) {
        [out appendString:@"not instantiated because init ABI is not the expected object getter ABI\n"];
        return;
    }

    id obj = ((id (*)(id, SEL))objc_msgSend)((id)cls, @selector(alloc));
    obj = ((id (*)(id, SEL))objc_msgSend)(obj, @selector(init));
    if (!obj) {
        [out appendString:@"init returned nil\n"];
        return;
    }

    NSArray<NSString *> *getters = @[
        @"isScreenshotsVLUAuthorized",
        @"environmentBundleIdentifier",
        @"vluAuthorized",
        @"isVLUAuthorized",
        @"cameraVLUAuthorized"
    ];
    for (NSString *getter in getters) {
        SEL sel = NSSelectorFromString(getter);
        Method method = class_getInstanceMethod(cls, sel);
        if (!method) {
            [out appendFormat:@"%@ = <method missing>\n", getter];
            continue;
        }
        NSString *types = VIRCMethodTypes(method);
        [out appendFormat:@"%@ types=%@", getter, types];
        if ([types isEqualToString:@"@16@0:8"]) {
            id value = ((id (*)(id, SEL))objc_msgSend)(obj, sel);
            [out appendFormat:@" value=%@\n", value ?: @"<nil>"];
        } else if ([types isEqualToString:@"B16@0:8"] || [types isEqualToString:@"c16@0:8"]) {
            BOOL value = ((BOOL (*)(id, SEL))objc_msgSend)(obj, sel);
            [out appendFormat:@" value=%@\n", value ? @"true" : @"false"];
        } else if ([types isEqualToString:@"Q16@0:8"]) {
            unsigned long long value = ((unsigned long long (*)(id, SEL))objc_msgSend)(obj, sel);
            [out appendFormat:@" value=%llu\n", value];
        } else if ([types isEqualToString:@"q16@0:8"]) {
            long long value = ((long long (*)(id, SEL))objc_msgSend)(obj, sel);
            [out appendFormat:@" value=%lld\n", value];
        } else {
            [out appendString:@" value=<not-called; ABI not allowlisted>\n"];
        }
    }
}

static void VIRCAppendAnalyzerScalars(NSMutableString *out) {
    [out appendString:@"\n--- VKCImageAnalyzer safe class getters ---\n"];
    Class cls = NSClassFromString(@"VKCImageAnalyzer");
    if (!cls) {
        [out appendString:@"class missing\n"];
        return;
    }

    for (NSString *getter in @[@"viEntryType", @"viBundleIdentifier", @"supportedAnalysisTypes"]) {
        SEL sel = NSSelectorFromString(getter);
        Method method = class_getClassMethod(cls, sel);
        NSString *types = VIRCMethodTypes(method);
        [out appendFormat:@"+%@ types=%@", getter, types];
        if ([types isEqualToString:@"Q16@0:8"]) {
            unsigned long long value = ((unsigned long long (*)(id, SEL))objc_msgSend)((id)cls, sel);
            [out appendFormat:@" value=%llu\n", value];
        } else if ([types isEqualToString:@"q16@0:8"]) {
            long long value = ((long long (*)(id, SEL))objc_msgSend)((id)cls, sel);
            [out appendFormat:@" value=%lld\n", value];
        } else if ([types isEqualToString:@"@16@0:8"]) {
            id value = ((id (*)(id, SEL))objc_msgSend)((id)cls, sel);
            [out appendFormat:@" value=%@\n", value ?: @"<nil>"];
        } else {
            [out appendString:@" value=<not-called; ABI mismatch/missing>\n"];
        }
    }
}

static void VIRCAppendFilteredStrings(NSMutableString *out, VIRCImage image) {
    [out appendString:@"\n--- VisualIntelligenceCore selected embedded strings ---\n"];
    NSArray<NSString *> *needles = @[
        @"vlu", @"authorized", @"authorization", @"requesttype",
        @"china", @"gvicc", @"visualintelligencecamera",
        @"screenshot", @"camera stream", @"environmentbundle"
    ];
    const char *sections[] = {"__cstring", "__swift5_reflstr"};
    NSUInteger emitted = 0;

    for (NSUInteger sectionIndex = 0; sectionIndex < 2 && emitted < 160; sectionIndex++) {
        unsigned long size = 0;
        const uint8_t *section = getsectiondata(image.header, "__TEXT", sections[sectionIndex], &size);
        if (!section || !size) continue;
        const uint8_t *p = section;
        const uint8_t *end = section + size;
        while (p < end && emitted < 160) {
            const uint8_t *nul = memchr(p, 0, (size_t)(end - p));
            if (!nul) break;
            size_t len = (size_t)(nul - p);
            if (len >= 3 && len <= 500) {
                NSString *s = [[NSString alloc] initWithBytes:p length:len encoding:NSUTF8StringEncoding];
                NSString *lower = s.lowercaseString;
                BOOL hit = NO;
                for (NSString *needle in needles) {
                    if ([lower containsString:needle]) { hit = YES; break; }
                }
                if (hit) {
                    [out appendFormat:@"%@: %@\n",
                     [NSString stringWithUTF8String:sections[sectionIndex]], s];
                    emitted++;
                }
            }
            p = nul + 1;
        }
    }
    [out appendFormat:@"selectedStrings=%lu\n", (unsigned long)emitted];
}

NSString *VIRequestContextGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI REQUEST-CONTEXT + VLU AUTH READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n",
     NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:
     @"SAFETY: read-only Objective-C runtime metadata, Swift reflection metadata, embedded-string inspection, "
      "and allowlisted zero-argument getters with verified scalar/object ABIs only. No setters, no preheat, "
      "no rich-analysis enum call, no arbitrary enum values, no XPC, no swizzling/IMP replacement, "
      "no preferences/MobileGestalt writes, no respring/reboot.\n\n"];

    void *vic = dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore",
                      RTLD_NOW | RTLD_LOCAL);
    void *vkc = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore",
                      RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vic ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen=%@\n", vkc ? @"OK" : @"FAIL"];

    VIRCImage image;
    if (VIRCFindImage(@"VisualIntelligenceCore.framework/VisualIntelligenceCore", &image)) {
        VIRCAppendRequestTypeCases(out, image);
        VIRCAppendFilteredStrings(out, image);
    } else {
        [out appendString:@"VisualIntelligenceCore loaded image not found\n"];
    }

    [out appendString:@"\n--- focused Objective-C runtime surfaces ---\n"];
    VIRCAppendClassMetadata(out, @"VICVisualIntelligenceAnalysisRequestConfig");
    VIRCAppendClassMetadata(out, @"VKCImageAnalyzerRequestVIConfiguration");
    VIRCAppendClassMetadata(out, @"VKCImageAnalyzer");
    VIRCAppendClassMetadata(out, @"VICVisualIntelligenceAnalyzer");
    VIRCAppendClassMetadata(out, @"VKCGMAvailability");

    VIRCAppendFreshRequestConfig(out);
    VIRCAppendVIConfigurationValues(out);
    VIRCAppendAnalyzerScalars(out);

    [out appendString:
     @"\n--- interpretation targets ---\n"
      "1. The five real VICVisualIntelligenceAnalysisRequestType cases are recovered from metadata; none are invoked.\n"
      "2. Compare fresh config vluAuthorized with VKCImageAnalyzerRequestVIConfiguration authorization fields.\n"
      "3. ScreenshotServices on the public 26.1 reference explicitly populates isScreenshotsVLUAuthorized and environmentBundleIdentifier; "
      "this report checks whether the same request-context surface exists on 24A5390f.\n"
      "4. hasAdditionalChinaPolicy/currentIPCountryCodeAllowance are not modified or treated as proven root causes here.\n"
      "================================================================================\n"];

    return out;
}
