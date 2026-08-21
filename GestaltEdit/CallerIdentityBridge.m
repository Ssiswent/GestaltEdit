#import "CallerIdentityBridge.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <objc/message.h>
#import <objc/runtime.h>
#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct __attribute__((packed)) {
    int32_t mangledTypeName;
    int32_t superclass;
    uint16_t kind;
    uint16_t fieldRecordSize;
    uint32_t numFields;
} GEFieldDescriptor;

typedef struct __attribute__((packed)) {
    uint32_t flags;
    int32_t mangledTypeName;
    int32_t fieldName;
} GEFieldRecord;

typedef struct {
    const struct mach_header_64 *header;
    intptr_t slide;
} GELoadedImage;

static BOOL GEImageContains(GELoadedImage image, const void *ptr, size_t len) {
    if (!image.header || !ptr) return NO;
    uintptr_t p = (uintptr_t)ptr;
    if (len > UINTPTR_MAX - p) return NO;
    uintptr_t end = p + len;
    const uint8_t *cmdPtr = (const uint8_t *)(image.header + 1);
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmdsize < sizeof(struct load_command)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t s = (uintptr_t)(seg->vmaddr + image.slide);
            uintptr_t e = s + (uintptr_t)seg->vmsize;
            if (p >= s && end <= e) return YES;
        }
        cmdPtr += lc->cmdsize;
    }
    return NO;
}

static BOOL GEFindLoadedImage(NSString *needle, GELoadedImage *outInfo) {
    if (!outInfo) return NO;
    memset(outInfo, 0, sizeof(*outInfo));
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *path = [NSString stringWithUTF8String:name];
        if (![path containsString:needle]) continue;
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        outInfo->header = (const struct mach_header_64 *)h;
        outInfo->slide = _dyld_get_image_vmaddr_slide(i);
        return YES;
    }
    return NO;
}

static BOOL GEFindImageContaining(const void *ptr, size_t len, GELoadedImage *outInfo) {
    if (!ptr || !outInfo) return NO;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        GELoadedImage image = {
            .header = (const struct mach_header_64 *)h,
            .slide = _dyld_get_image_vmaddr_slide(i)
        };
        if (GEImageContains(image, ptr, len)) {
            *outInfo = image;
            return YES;
        }
    }
    memset(outInfo, 0, sizeof(*outInfo));
    return NO;
}

static NSString *GEImageName(GELoadedImage image) {
    if (!image.header) return @"<unmapped>";
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) != (const struct mach_header *)image.header) continue;
        const char *name = _dyld_get_image_name(i);
        if (!name) return @"<unknown>";
        NSString *path = [NSString stringWithUTF8String:name];
        return path.lastPathComponent.length ? path.lastPathComponent : path;
    }
    return @"<unknown>";
}

static size_t GEReadableBytesInImage(GELoadedImage image, const void *ptr, size_t cap) {
    if (!image.header || !ptr) return 0;
    uintptr_t p = (uintptr_t)ptr;
    const uint8_t *cmdPtr = (const uint8_t *)(image.header + 1);
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmdsize < sizeof(struct load_command)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t s = (uintptr_t)(seg->vmaddr + image.slide);
            uintptr_t e = s + (uintptr_t)seg->vmsize;
            if (p >= s && p < e) {
                size_t avail = (size_t)(e - p);
                return MIN(avail, cap);
            }
        }
        cmdPtr += lc->cmdsize;
    }
    return 0;
}

static size_t GEReadableBytesAny(const void *ptr, size_t cap, GELoadedImage *outImage) {
    GELoadedImage image;
    if (!GEFindImageContaining(ptr, 1, &image)) return 0;
    if (outImage) *outImage = image;
    return GEReadableBytesInImage(image, ptr, cap);
}

static const uint8_t *GEResolveRelative32Any(const int32_t *field, GELoadedImage *outImage) {
    GELoadedImage fieldImage;
    if (!GEFindImageContaining(field, sizeof(*field), &fieldImage)) return NULL;
    int32_t rel = 0;
    memcpy(&rel, field, sizeof(rel));
    if (rel == 0) return NULL;
    const uint8_t *target = (const uint8_t *)field + rel;
    GELoadedImage targetImage;
    if (!GEFindImageContaining(target, 1, &targetImage)) return NULL;
    if (outImage) *outImage = targetImage;
    return target;
}

static NSString *GESafeCStringAny(const uint8_t *ptr, NSUInteger maxLen) {
    if (!ptr) return nil;
    GELoadedImage image;
    size_t readable = GEReadableBytesAny(ptr, maxLen, &image);
    if (!readable) return nil;
    const void *nul = memchr(ptr, 0, readable);
    if (!nul) return nil;
    NSUInteger len = (NSUInteger)((const uint8_t *)nul - ptr);
    NSData *data = [NSData dataWithBytes:ptr length:len];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static NSString *GEHexPreviewBinaryMangled(const uint8_t *ptr, NSUInteger cap) {
    if (!ptr) return @"<nil>";
    GELoadedImage image;
    size_t readable = GEReadableBytesAny(ptr, cap, &image);
    if (!readable) return @"<unmapped>";

    NSMutableString *s = [NSMutableString string];
    size_t i = 0;
    while (i < readable) {
        uint8_t b = ptr[i];
        if (b == 0) break;

        if (b >= 0x01 && b <= 0x17) {
            if (i + 5 > readable) {
                [s appendFormat:@"<truncated-ref-0x%02x>", b];
                break;
            }
            [s appendFormat:@"\\x%02x", b];
            for (size_t j = 1; j < 5; j++) [s appendFormat:@"\\x%02x", ptr[i + j]];
            i += 5;
            continue;
        }

        if (b >= 0x18 && b <= 0x1f) {
            size_t width = 1 + sizeof(void *);
            if (i + width > readable) {
                [s appendFormat:@"<truncated-absref-0x%02x>", b];
                break;
            }
            [s appendFormat:@"\\x%02x", b];
            for (size_t j = 1; j < width; j++) [s appendFormat:@"\\x%02x", ptr[i + j]];
            i += width;
            continue;
        }

        if (b >= 0x20 && b <= 0x7e) [s appendFormat:@"%c", b];
        else [s appendFormat:@"\\x%02x", b];
        i++;
    }
    return s.length ? s : @"<empty>";
}

static NSString *GEContextKindName(uint32_t kind) {
    switch (kind) {
        case 0: return @"module";
        case 1: return @"extension";
        case 2: return @"anonymous";
        case 3: return @"protocol";
        case 4: return @"opaqueType";
        case 16: return @"class";
        case 17: return @"struct";
        case 18: return @"enum";
        default: return [NSString stringWithFormat:@"kind(%u)", kind];
    }
}

static NSString *GEFieldKindName(uint16_t kind) {
    switch (kind) {
        case 0: return @"struct";
        case 1: return @"class";
        case 2: return @"enum";
        case 3: return @"multiPayloadEnum";
        case 4: return @"protocol";
        case 5: return @"classProtocol";
        case 6: return @"objcProtocol";
        case 7: return @"objcClass";
        default: return [NSString stringWithFormat:@"kind(%u)", kind];
    }
}

static NSString *GEContextLocalName(const uint8_t *ctx) {
    GELoadedImage image;
    if (!GEFindImageContaining(ctx, 12, &image)) return nil;
    uint32_t flags = 0;
    memcpy(&flags, ctx, sizeof(flags));
    uint32_t kind = flags & 0x1f;
    if (!(kind == 0 || kind == 1 || kind == 2 || kind == 3 || kind == 4 ||
          kind == 16 || kind == 17 || kind == 18)) return nil;

    GELoadedImage nameImage;
    const uint8_t *namePtr = GEResolveRelative32Any((const int32_t *)(ctx + 8), &nameImage);
    NSString *name = GESafeCStringAny(namePtr, 256);
    if (!name.length || name.length > 200) return nil;
    return name;
}

static const uint8_t *GEContextParent(const uint8_t *ctx) {
    GELoadedImage image;
    if (!GEFindImageContaining(ctx, 8, &image)) return NULL;
    return GEResolveRelative32Any((const int32_t *)(ctx + 4), NULL);
}

static BOOL GEContextLooksPlausible(const uint8_t *ctx) {
    GELoadedImage image;
    if (!GEFindImageContaining(ctx, 12, &image)) return NO;
    uint32_t flags = 0;
    memcpy(&flags, ctx, sizeof(flags));
    uint32_t kind = flags & 0x1f;
    if (!(kind == 0 || kind == 1 || kind == 2 || kind == 3 || kind == 4 ||
          kind == 16 || kind == 17 || kind == 18)) return NO;
    NSString *name = GEContextLocalName(ctx);
    return name.length > 0;
}

static NSString *GEContextFullName(const uint8_t *ctx) {
    if (!ctx) return nil;
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    const uint8_t *cur = ctx;
    NSMutableSet<NSValue *> *seen = [NSMutableSet set];

    for (NSUInteger depth = 0; depth < 12 && cur; depth++) {
        NSValue *key = [NSValue valueWithPointer:cur];
        if ([seen containsObject:key]) break;
        [seen addObject:key];

        GELoadedImage image;
        if (!GEFindImageContaining(cur, 12, &image)) break;

        uint32_t flags = 0;
        memcpy(&flags, cur, sizeof(flags));
        uint32_t kind = flags & 0x1f;

        NSString *name = GEContextLocalName(cur);
        if (name.length) [parts insertObject:name atIndex:0];

        if (kind == 0) break;
        cur = GEContextParent(cur);
    }
    return parts.count ? [parts componentsJoinedByString:@"."] : nil;
}

static const GEFieldDescriptor *GEFieldDescriptorForContext(const uint8_t *ctx) {
    GELoadedImage image;
    if (!GEFindImageContaining(ctx, 20, &image)) return NULL;
    uint32_t flags = 0;
    memcpy(&flags, ctx, sizeof(flags));
    uint32_t kind = flags & 0x1f;
    if (!(kind == 16 || kind == 17 || kind == 18)) return NULL;

    const uint8_t *fieldPtr = GEResolveRelative32Any((const int32_t *)(ctx + 16), NULL);
    if (!fieldPtr) return NULL;

    GELoadedImage fdImage;
    if (!GEFindImageContaining(fieldPtr, sizeof(GEFieldDescriptor), &fdImage)) return NULL;
    return (const GEFieldDescriptor *)fieldPtr;
}

static BOOL GEValidFieldDescriptor(const GEFieldDescriptor *fd) {
    GELoadedImage image;
    if (!fd || !GEFindImageContaining(fd, sizeof(*fd), &image)) return NO;
    uint16_t recordSize = fd->fieldRecordSize;
    uint32_t numFields = fd->numFields;
    if (recordSize < sizeof(GEFieldRecord) || recordSize > 128 || numFields > 2048) return NO;
    uint64_t total = sizeof(GEFieldDescriptor) + (uint64_t)recordSize * (uint64_t)numFields;
    return total <= SIZE_MAX && GEImageContains(image, fd, (size_t)total);
}

static void GEAppendContextDescriptor(NSMutableString *out, const uint8_t *ctx, NSString *prefix) {
    GELoadedImage image;
    if (!ctx || !GEFindImageContaining(ctx, 12, &image)) {
        [out appendFormat:@"%@context=<unresolved>\n", prefix];
        return;
    }

    uint32_t flags = 0;
    memcpy(&flags, ctx, sizeof(flags));
    uint32_t kind = flags & 0x1f;
    NSString *full = GEContextFullName(ctx) ?: @"<unnamed>";
    [out appendFormat:@"%@context=%@ kind=%@ image=%@ flags=0x%x\n",
     prefix, full, GEContextKindName(kind), GEImageName(image), flags];

    if (kind == 18 && GEFindImageContaining(ctx + 20, 8, &image)) {
        uint32_t payloadPacked = 0, emptyCases = 0;
        memcpy(&payloadPacked, ctx + 20, 4);
        memcpy(&emptyCases, ctx + 24, 4);
        uint32_t payloadCases = payloadPacked & 0x00ffffff;
        [out appendFormat:@"%@enumPayloadCases=%u enumEmptyCases=%u totalCases=%u\n",
         prefix, payloadCases, emptyCases, payloadCases + emptyCases];
    }

    const GEFieldDescriptor *fd = GEFieldDescriptorForContext(ctx);
    if (!GEValidFieldDescriptor(fd)) return;

    [out appendFormat:@"%@fieldDescriptor kind=%@ numFields=%u\n",
     prefix, GEFieldKindName(fd->kind), fd->numFields];

    const uint8_t *records = (const uint8_t *)fd + sizeof(GEFieldDescriptor);
    for (uint32_t i = 0; i < fd->numFields && i < 80; i++) {
        const GEFieldRecord *fr = (const GEFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
        NSString *name = GESafeCStringAny(GEResolveRelative32Any(&fr->fieldName, NULL), 256) ?: @"<unreadable>";
        [out appendFormat:@"%@  case/field[%u]=%@ flags=0x%x\n", prefix, i, name, fr->flags];
    }
}

static const uint8_t *GEStripPossiblyAuthenticatedPointer(const void *raw) {
    if (!raw) return NULL;
#if __has_include(<ptrauth.h>)
    return (const uint8_t *)ptrauth_strip(raw, ptrauth_key_asda);
#else
    return (const uint8_t *)raw;
#endif
}

static const uint8_t *GEResolveContextSymbolicReferenceCandidate(const uint8_t *control,
                                                                 int32_t rel,
                                                                 uint8_t rawKind,
                                                                 BOOL usePayloadBase,
                                                                 NSString **detailOut) {
    const uint8_t *base = usePayloadBase ? control + 1 : control;
    const uint8_t *slotOrTarget = base + rel;

    GELoadedImage firstImage;
    if (!GEFindImageContaining(slotOrTarget, 1, &firstImage)) {
        if (detailOut) *detailOut = [NSString stringWithFormat:@"base=%@ firstTarget=<unmapped>",
                                    usePayloadBase ? @"payload" : @"control"];
        return NULL;
    }

    if (rawKind == 0x01) {
        if (detailOut) *detailOut = [NSString stringWithFormat:@"base=%@ direct firstImage=%@",
                                    usePayloadBase ? @"payload" : @"control", GEImageName(firstImage)];
        return slotOrTarget;
    }

    if (rawKind == 0x02) {
        if (!GEImageContains(firstImage, slotOrTarget, sizeof(void *))) {
            if (detailOut) *detailOut = [NSString stringWithFormat:@"base=%@ indirect slot=<short>",
                                        usePayloadBase ? @"payload" : @"control"];
            return NULL;
        }
        const void *raw = NULL;
        memcpy(&raw, slotOrTarget, sizeof(raw));
        const uint8_t *resolved = GEStripPossiblyAuthenticatedPointer(raw);
        GELoadedImage resolvedImage;
        if (!GEFindImageContaining(resolved, 1, &resolvedImage)) {
            if (detailOut) *detailOut = [NSString stringWithFormat:@"base=%@ indirect slotImage=%@ pointee=<unmapped>",
                                        usePayloadBase ? @"payload" : @"control", GEImageName(firstImage)];
            return NULL;
        }
        if (detailOut) *detailOut = [NSString stringWithFormat:@"base=%@ indirect slotImage=%@ pointeeImage=%@",
                                    usePayloadBase ? @"payload" : @"control",
                                    GEImageName(firstImage), GEImageName(resolvedImage)];
        return resolved;
    }

    if (detailOut) *detailOut = [NSString stringWithFormat:@"base=%@ kind=0x%02x not-context",
                                usePayloadBase ? @"payload" : @"control", rawKind];
    return NULL;
}

static void GEAppendSymbolicRefs(NSMutableString *out, const uint8_t *mangled, NSString *prefix) {
    if (!mangled) return;

    GELoadedImage originImage;
    size_t readable = GEReadableBytesAny(mangled, 256, &originImage);
    if (!readable) {
        [out appendFormat:@"%@symbolicRefs=<mangled pointer unmapped>\n", prefix];
        return;
    }

    NSUInteger refs = 0;
    size_t i = 0;
    while (i < readable) {
        uint8_t rawKind = mangled[i];
        if (rawKind == 0) break;

        if (rawKind >= 0x01 && rawKind <= 0x17) {
            if (i + 5 > readable) {
                [out appendFormat:@"%@symbolicRef[%lu] kind=0x%02x <truncated>\n",
                 prefix, (unsigned long)refs, rawKind];
                break;
            }

            int32_t rel = 0;
            memcpy(&rel, mangled + i + 1, 4);
            const uint8_t *control = mangled + i;

            [out appendFormat:@"%@symbolicRef[%lu] kind=0x%02x rel=%d originImage=%@\n",
             prefix, (unsigned long)refs, rawKind, rel, GEImageName(originImage)];

            if (rawKind == 0x01 || rawKind == 0x02) {
                NSString *primaryDetail = nil;
                const uint8_t *resolved = GEResolveContextSymbolicReferenceCandidate(
                    control, rel, rawKind, NO, &primaryDetail);

                BOOL plausible = GEContextLooksPlausible(resolved);
                [out appendFormat:@"%@  primary %@ plausible=%@\n",
                 prefix, primaryDetail ?: @"<no detail>", plausible ? @"true" : @"false"];

                if (!plausible) {
                    NSString *fallbackDetail = nil;
                    const uint8_t *fallback = GEResolveContextSymbolicReferenceCandidate(
                        control, rel, rawKind, YES, &fallbackDetail);
                    BOOL fallbackPlausible = GEContextLooksPlausible(fallback);
                    [out appendFormat:@"%@  fallback %@ plausible=%@\n",
                     prefix, fallbackDetail ?: @"<no detail>", fallbackPlausible ? @"true" : @"false"];
                    if (fallbackPlausible) resolved = fallback;
                }

                if (GEContextLooksPlausible(resolved)) {
                    GEAppendContextDescriptor(out, resolved, [prefix stringByAppendingString:@"  "]);
                } else {
                    [out appendFormat:@"%@  context=<unresolved/plausibility-check-failed>\n", prefix];
                }
            } else {
                [out appendFormat:@"%@  note=relative symbolic kind not interpreted; bytes skipped safely\n", prefix];
            }

            refs++;
            i += 5;
            continue;
        }

        if (rawKind >= 0x18 && rawKind <= 0x1f) {
            size_t width = 1 + sizeof(void *);
            if (i + width > readable) break;
            [out appendFormat:@"%@symbolicRef[%lu] kind=0x%02x absoluteRef width=%lu (not dereferenced)\n",
             prefix, (unsigned long)refs, rawKind, (unsigned long)sizeof(void *)];
            refs++;
            i += width;
            continue;
        }

        i++;
    }

    if (!refs) [out appendFormat:@"%@symbolicRefs=<none>\n", prefix];
}

static BOOL GENameInteresting(NSString *name) {
    if (!name.length) return NO;
    static NSSet<NSString *> *targets;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        targets = [NSSet setWithArray:@[
            @"requestType", @"environmentBundleIdentifier", @"useCaseIdentifier",
            @"availability", @"partnerAvailability", @"hasAdditionalChinaPolicy",
            @"availabilityEntries", @"availabilityKey", @"languageOption",
            @"currentIPCountryCodeAllowance", @"visualIntelligenceCamera",
            @"gviccContentClassifier", @"camera", @"screenshot", @"context",
            @"unspecified", @"unaware", @"opened", @"used"
        ]];
    });
    return [targets containsObject:name];
}

static void GEAppendResolvedFieldMetadata(NSMutableString *out, NSString *imageNeedle) {
    [out appendFormat:@"\n--- %@ binary-safe cross-image Swift symbolic metadata ---\n", imageNeedle];

    GELoadedImage image;
    if (!GEFindLoadedImage(imageNeedle, &image)) {
        [out appendString:@"loaded image not found\n"];
        return;
    }

    unsigned long size = 0;
    const uint8_t *section = getsectiondata(image.header, "__TEXT", "__swift5_fieldmd", &size);
    if (!section || size < sizeof(GEFieldDescriptor)) {
        [out appendFormat:@"fieldmd unavailable size=%lu\n", size];
        return;
    }

    const uint8_t *end = section + size;
    const uint8_t *cursor = section;
    NSUInteger index = 0, emitted = 0;

    while (cursor + sizeof(GEFieldDescriptor) <= end && index < 10000) {
        const GEFieldDescriptor *fd = (const GEFieldDescriptor *)cursor;
        if (!GEValidFieldDescriptor(fd)) {
            cursor += 4;
            index++;
            continue;
        }

        uint64_t total = sizeof(GEFieldDescriptor) + (uint64_t)fd->fieldRecordSize * fd->numFields;
        if (cursor + total > end) break;

        const uint8_t *records = cursor + sizeof(GEFieldDescriptor);
        BOOL hit = NO;
        NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];

        for (uint32_t i = 0; i < fd->numFields; i++) {
            const GEFieldRecord *fr = (const GEFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
            NSString *name = GESafeCStringAny(GEResolveRelative32Any(&fr->fieldName, NULL), 256) ?: @"<unreadable>";
            if (GENameInteresting(name)) hit = YES;

            const uint8_t *typePtr = GEResolveRelative32Any(&fr->mangledTypeName, NULL);
            [rows addObject:@{
                @"name": name,
                @"ptr": [NSValue valueWithPointer:typePtr],
                @"flags": @(fr->flags),
                @"index": @(i)
            }];
        }

        if (hit && emitted < 100) {
            [out appendFormat:@"\n[%lu] offset=0x%lx fieldKind=%@ numFields=%u\n",
             (unsigned long)index,
             (unsigned long)(cursor - section),
             GEFieldKindName(fd->kind),
             fd->numFields];

            const uint8_t *ownerMangled = GEResolveRelative32Any(&fd->mangledTypeName, NULL);
            [out appendFormat:@"ownerMangled(binary-aware)=%@\n", GEHexPreviewBinaryMangled(ownerMangled, 128)];
            GEAppendSymbolicRefs(out, ownerMangled, @"  owner.");

            for (NSDictionary *row in rows) {
                NSString *name = row[@"name"];
                if (!GENameInteresting(name)) continue;
                const uint8_t *typePtr = [row[@"ptr"] pointerValue];
                [out appendFormat:@"  field[%@] name=%@ flags=0x%x typeMangled(binary-aware)=%@\n",
                 row[@"index"],
                 name,
                 [row[@"flags"] unsignedIntValue],
                 GEHexPreviewBinaryMangled(typePtr, 128)];
                GEAppendSymbolicRefs(out, typePtr, @"    type.");
            }
            emitted++;
        }

        cursor += total;
        index++;
    }

    [out appendFormat:@"\nfieldmdSize=%lu descriptorsScanned=%lu relevantDescriptors=%lu\n",
     size, (unsigned long)index, (unsigned long)emitted];
}

static NSString *GEClassMethodTypes(Class cls, NSString *name) {
    Method m = cls ? class_getClassMethod(cls, NSSelectorFromString(name)) : NULL;
    if (!m) return @"<missing>";
    const char *t = method_getTypeEncoding(m);
    return t ? [NSString stringWithUTF8String:t] : @"<nil>";
}

static void GEAppendBaseline(NSMutableString *out) {
    Class vkc = NSClassFromString(@"VKCImageAnalyzer");
    Class config = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");
    Class vic = NSClassFromString(@"VICVisualIntelligenceAnalyzer");

    [out appendString:@"\n--- scalar ABI baseline; still NO rich-analysis enum call ---\n"];
    [out appendFormat:@"VIC +isRichAnalysisAvailableForRequestType:bundleID: types=%@\n",
     GEClassMethodTypes(vic, @"isRichAnalysisAvailableForRequestType:bundleID:")];
    [out appendFormat:@"VKC +viEntryType types=%@\n", GEClassMethodTypes(vkc, @"viEntryType")];

    if (vkc && [GEClassMethodTypes(vkc, @"viEntryType") isEqualToString:@"Q16@0:8"]) {
        unsigned long long raw =
            ((unsigned long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viEntryType"));
        [out appendFormat:@"VKC.viEntryType(raw)=%llu\n", raw];
    }

    if (config) {
        id obj = ((id (*)(id, SEL))objc_msgSend)((id)config, @selector(alloc));
        obj = ((id (*)(id, SEL))objc_msgSend)(obj, @selector(init));
        Method m = class_getInstanceMethod(config, NSSelectorFromString(@"requestType"));
        const char *t = m ? method_getTypeEncoding(m) : NULL;
        if (obj && t && strcmp(t, "q16@0:8") == 0) {
            long long raw =
                ((long long (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"requestType"));
            [out appendFormat:@"freshConfig.requestType(raw)=%lld\n", raw];
        }
    }
}

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];

    [out appendString:@"========== iOS 27 VI BINARY-SAFE SYMBOLIC REF + CROSS-IMAGE RESOLVER ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n",
     NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];

    [out appendString:
     @"SAFETY: read-only dyld/Swift reflection metadata parsing plus already-ABI-verified scalar getters. "
      "No +isRichAnalysisAvailableForRequestType:bundleID: invocation, no arbitrary enum values, no setters/preheat/XPC, "
      "no swizzling/IMP replacement, no preferences/MobileGestalt writes, no respring/reboot.\n\n"];

    [out appendString:
     @"FIXES VS PREVIOUS BUILD:\n"
      "1. Swift relative symbolic refs 0x01...0x17 are parsed as control-byte + FOUR ARBITRARY BYTES; embedded NUL bytes no longer terminate the mangled name.\n"
      "2. 0x01 direct-context and 0x02 indirect-context refs are resolved.\n"
      "3. References may resolve across any currently loaded dyld image instead of being restricted to the originating framework.\n"
      "4. GenerativeModels is explicitly loaded before metadata traversal because several VisualIntelligenceCore field types are imported from it.\n"];

    void *vicHandle = dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore", RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    void *gmHandle = dlopen("/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels", RTLD_NOW | RTLD_LOCAL);

    [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vicHandle ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen=%@\n", vkHandle ? @"OK" : @"FAIL"];
    [out appendFormat:@"GenerativeModels dlopen=%@\n", gmHandle ? @"OK" : @"FAIL"];

    GEAppendBaseline(out);
    GEAppendResolvedFieldMetadata(out, @"VisualIntelligenceCore.framework/VisualIntelligenceCore");
    GEAppendResolvedFieldMetadata(out, @"VisionKitCore.framework/VisionKitCore");

    [out appendString:
     @"\n--- decisive targets ---\n"
      "A. requestType should now resolve to its real enum context and case list without invoking the enum-taking API.\n"
      "B. useCaseIdentifier should resolve through its 0x02 indirect reference, ideally exposing the enum whose cases include visualIntelligenceCamera/gviccContentClassifier.\n"
      "C. availability / partnerAvailability should resolve to their imported GenerativeModels types.\n"
      "D. currentIPCountryCodeAllowance owner enums should reveal their concrete type names and all 11 cases.\n"
      "E. the owner of availability + partnerAvailability + hasAdditionalChinaPolicy should get a concrete Swift context name.\n"
      "================================================================================\n"];

    return out;
}
