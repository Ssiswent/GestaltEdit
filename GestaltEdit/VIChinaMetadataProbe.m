#import "VIChinaMetadataProbe.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
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
} VICMFieldDescriptor;

typedef struct __attribute__((packed)) {
    uint32_t flags;
    int32_t mangledTypeName;
    int32_t fieldName;
} VICMFieldRecord;

typedef struct {
    const struct mach_header_64 *header;
    intptr_t slide;
} VICMImage;

static BOOL VICMImageContains(VICMImage image, const void *ptr, size_t len) {
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

static BOOL VICMFindImage(NSString *needle, VICMImage *outImage) {
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

static BOOL VICMFindImageContaining(const void *ptr, size_t len, VICMImage *outImage) {
    if (!ptr || !outImage) return NO;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        VICMImage image = {
            .header = (const struct mach_header_64 *)h,
            .slide = _dyld_get_image_vmaddr_slide(i)
        };
        if (VICMImageContains(image, ptr, len)) {
            *outImage = image;
            return YES;
        }
    }
    memset(outImage, 0, sizeof(*outImage));
    return NO;
}

static NSString *VICMImageName(VICMImage image) {
    if (!image.header) return @"<unmapped>";
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) != (const struct mach_header *)image.header) continue;
        const char *raw = _dyld_get_image_name(i);
        if (!raw) return @"<unknown>";
        NSString *path = [NSString stringWithUTF8String:raw];
        return path.lastPathComponent.length ? path.lastPathComponent : path;
    }
    return @"<unknown>";
}

static size_t VICMReadableBytesInImage(VICMImage image, const void *ptr, size_t cap) {
    if (!image.header || !ptr) return 0;
    uintptr_t p = (uintptr_t)ptr;
    const uint8_t *cmd = (const uint8_t *)(image.header + 1);
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t start = (uintptr_t)(seg->vmaddr + image.slide);
            uintptr_t stop = start + (uintptr_t)seg->vmsize;
            if (p >= start && p < stop) {
                return MIN((size_t)(stop - p), cap);
            }
        }
        cmd += lc->cmdsize;
    }
    return 0;
}

static size_t VICMReadableBytesAny(const void *ptr, size_t cap, VICMImage *outImage) {
    VICMImage image;
    if (!VICMFindImageContaining(ptr, 1, &image)) return 0;
    if (outImage) *outImage = image;
    return VICMReadableBytesInImage(image, ptr, cap);
}

static const uint8_t *VICMResolveRelative32Any(const int32_t *field, VICMImage *outImage) {
    VICMImage fieldImage;
    if (!VICMFindImageContaining(field, sizeof(*field), &fieldImage)) return NULL;
    int32_t rel = 0;
    memcpy(&rel, field, sizeof(rel));
    if (!rel) return NULL;
    uintptr_t addr = (uintptr_t)field + (intptr_t)rel;
    const uint8_t *target = (const uint8_t *)addr;
    VICMImage targetImage;
    if (!VICMFindImageContaining(target, 1, &targetImage)) return NULL;
    if (outImage) *outImage = targetImage;
    return target;
}

static NSString *VICMSafeCStringAny(const uint8_t *ptr, NSUInteger cap) {
    if (!ptr) return nil;
    VICMImage image;
    size_t readable = VICMReadableBytesAny(ptr, cap, &image);
    if (!readable) return nil;
    const void *nul = memchr(ptr, 0, readable);
    if (!nul) return nil;
    NSUInteger len = (NSUInteger)((const uint8_t *)nul - ptr);
    NSData *data = [NSData dataWithBytes:ptr length:len];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static const uint8_t *VICMStripPossiblyAuthenticatedPointer(const void *raw) {
    if (!raw) return NULL;
#if __has_include(<ptrauth.h>)
    return (const uint8_t *)ptrauth_strip(raw, ptrauth_key_asda);
#else
    return (const uint8_t *)raw;
#endif
}

static NSString *VICMContextLocalName(const uint8_t *ctx) {
    VICMImage image;
    if (!ctx || !VICMFindImageContaining(ctx, 12, &image)) return nil;
    uint32_t flags = 0;
    memcpy(&flags, ctx, 4);
    uint32_t kind = flags & 0x1f;
    if (!(kind == 0 || kind == 1 || kind == 2 || kind == 3 || kind == 4 ||
          kind == 16 || kind == 17 || kind == 18)) return nil;
    const uint8_t *namePtr = VICMResolveRelative32Any((const int32_t *)(ctx + 8), NULL);
    NSString *name = VICMSafeCStringAny(namePtr, 256);
    if (!name.length || name.length > 200) return nil;
    return name;
}

static BOOL VICMContextPlausible(const uint8_t *ctx) {
    VICMImage image;
    if (!ctx || !VICMFindImageContaining(ctx, 12, &image)) return NO;
    uint32_t flags = 0;
    memcpy(&flags, ctx, 4);
    uint32_t kind = flags & 0x1f;
    if (!(kind == 0 || kind == 1 || kind == 2 || kind == 3 || kind == 4 ||
          kind == 16 || kind == 17 || kind == 18)) return NO;
    return VICMContextLocalName(ctx).length > 0;
}

static const uint8_t *VICMContextParent(const uint8_t *ctx) {
    VICMImage image;
    if (!ctx || !VICMFindImageContaining(ctx, 8, &image)) return NULL;
    return VICMResolveRelative32Any((const int32_t *)(ctx + 4), NULL);
}

static NSString *VICMContextFullName(const uint8_t *ctx) {
    if (!ctx) return nil;
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    NSMutableSet<NSValue *> *seen = [NSMutableSet set];
    const uint8_t *cur = ctx;
    for (NSUInteger depth = 0; depth < 12 && cur; depth++) {
        NSValue *key = [NSValue valueWithPointer:cur];
        if ([seen containsObject:key]) break;
        [seen addObject:key];
        VICMImage image;
        if (!VICMFindImageContaining(cur, 12, &image)) break;
        uint32_t flags = 0;
        memcpy(&flags, cur, 4);
        uint32_t kind = flags & 0x1f;
        NSString *name = VICMContextLocalName(cur);
        if (name.length) [parts insertObject:name atIndex:0];
        if (kind == 0) break;
        cur = VICMContextParent(cur);
    }
    return parts.count ? [parts componentsJoinedByString:@"."] : nil;
}

static NSString *VICMMangledPreview(const uint8_t *ptr, NSUInteger cap) {
    if (!ptr) return @"<nil>";
    VICMImage image;
    size_t readable = VICMReadableBytesAny(ptr, cap, &image);
    if (!readable) return @"<unmapped>";
    NSMutableString *s = [NSMutableString string];
    size_t i = 0;
    while (i < readable) {
        uint8_t b = ptr[i];
        if (b == 0) break;
        if (b >= 0x01 && b <= 0x17) {
            if (i + 5 > readable) break;
            [s appendFormat:@"\\x%02x", b];
            for (size_t j = 1; j < 5; j++) [s appendFormat:@"\\x%02x", ptr[i + j]];
            i += 5;
            continue;
        }
        if (b >= 0x18 && b <= 0x1f) {
            size_t width = 1 + sizeof(void *);
            if (i + width > readable) break;
            [s appendFormat:@"\\x%02x<absref>", b];
            i += width;
            continue;
        }
        if (b >= 0x20 && b <= 0x7e) [s appendFormat:@"%c", b];
        else [s appendFormat:@"\\x%02x", b];
        i++;
    }
    return s.length ? s : @"<empty>";
}

static const uint8_t *VICMResolveContextCandidate(const uint8_t *control,
                                                   int32_t rel,
                                                   uint8_t rawKind,
                                                   BOOL payloadBase) {
    if (!control) return NULL;
    const uint8_t *base = payloadBase ? control + 1 : control;
    uintptr_t addr = (uintptr_t)base + (intptr_t)rel;
    const uint8_t *target = (const uint8_t *)addr;

    if (rawKind == 0x01) {
        return VICMContextPlausible(target) ? target : NULL;
    }

    if (rawKind == 0x02) {
        if (VICMReadableBytesAny(target, sizeof(void *), NULL) < sizeof(void *)) return NULL;
        const void *raw = NULL;
        memcpy(&raw, target, sizeof(raw));
        const uint8_t *pointee = VICMStripPossiblyAuthenticatedPointer(raw);
        return VICMContextPlausible(pointee) ? pointee : NULL;
    }

    return NULL;
}

static const uint8_t *VICMResolveFirstContextFromMangled(const uint8_t *mangled) {
    if (!mangled) return NULL;
    VICMImage origin;
    size_t readable = VICMReadableBytesAny(mangled, 256, &origin);
    if (!readable) return NULL;

    size_t i = 0;
    while (i < readable) {
        uint8_t rawKind = mangled[i];
        if (rawKind == 0) break;
        if (rawKind >= 0x01 && rawKind <= 0x17) {
            if (i + 5 > readable) break;
            if (rawKind == 0x01 || rawKind == 0x02) {
                int32_t rel = 0;
                memcpy(&rel, mangled + i + 1, 4);
                const uint8_t *control = mangled + i;

                // 24A5390f has repeatedly resolved correctly from the 4-byte
                // payload address; keep control-byte base as fallback.
                const uint8_t *ctx = VICMResolveContextCandidate(control, rel, rawKind, YES);
                if (ctx) return ctx;
                ctx = VICMResolveContextCandidate(control, rel, rawKind, NO);
                if (ctx) return ctx;
            }
            i += 5;
            continue;
        }
        if (rawKind >= 0x18 && rawKind <= 0x1f) {
            size_t width = 1 + sizeof(void *);
            if (i + width > readable) break;
            i += width;
            continue;
        }
        i++;
    }
    return NULL;
}

static BOOL VICMValidDescriptor(const VICMFieldDescriptor *fd) {
    VICMImage image;
    if (!fd || !VICMFindImageContaining(fd, sizeof(*fd), &image)) return NO;
    if (fd->fieldRecordSize < sizeof(VICMFieldRecord) || fd->fieldRecordSize > 128) return NO;
    if (fd->numFields > 2048) return NO;
    uint64_t total = sizeof(*fd) + (uint64_t)fd->fieldRecordSize * fd->numFields;
    if (total > SIZE_MAX) return NO;
    return VICMImageContains(image, fd, (size_t)total);
}

static NSString *VICMFieldName(const VICMFieldRecord *fr) {
    if (!fr) return nil;
    return VICMSafeCStringAny(VICMResolveRelative32Any(&fr->fieldName, NULL), 200);
}

static const uint8_t *VICMFieldTypeMangled(const VICMFieldRecord *fr) {
    if (!fr) return NULL;
    return VICMResolveRelative32Any(&fr->mangledTypeName, NULL);
}

static const uint8_t *VICMOwnerContext(const VICMFieldDescriptor *fd) {
    if (!fd) return NULL;
    const uint8_t *ownerMangled = VICMResolveRelative32Any(&fd->mangledTypeName, NULL);
    return VICMResolveFirstContextFromMangled(ownerMangled);
}

static NSString *VICMFieldKindName(uint16_t kind) {
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

static void VICMAppendDescriptor(NSMutableString *out,
                                 const VICMFieldDescriptor *fd,
                                 const uint8_t *section,
                                 NSString *reason) {
    if (!VICMValidDescriptor(fd)) return;
    const uint8_t *ownerMangled = VICMResolveRelative32Any(&fd->mangledTypeName, NULL);
    const uint8_t *ownerCtx = VICMResolveFirstContextFromMangled(ownerMangled);
    NSString *ownerName = VICMContextFullName(ownerCtx) ?: @"<unresolved>";
    VICMImage ownerImage;
    NSString *ownerImageName = VICMFindImageContaining(ownerCtx, 1, &ownerImage)
        ? VICMImageName(ownerImage) : @"<unmapped>";

    [out appendFormat:@"\n[%@] descriptorOffset=0x%lx kind=%@ numFields=%u\n",
     reason,
     (unsigned long)((const uint8_t *)fd - section),
     VICMFieldKindName(fd->kind),
     fd->numFields];
    [out appendFormat:@"owner=%@ image=%@ ownerMangled=%@\n",
     ownerName, ownerImageName, VICMMangledPreview(ownerMangled, 80)];

    const uint8_t *records = (const uint8_t *)fd + sizeof(*fd);
    uint32_t limit = MIN(fd->numFields, 80u);
    for (uint32_t i = 0; i < limit; i++) {
        const VICMFieldRecord *fr =
            (const VICMFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
        NSString *fieldName = VICMFieldName(fr) ?: @"<unreadable>";
        const uint8_t *typeMangled = VICMFieldTypeMangled(fr);
        const uint8_t *typeCtx = VICMResolveFirstContextFromMangled(typeMangled);
        NSString *typeName = VICMContextFullName(typeCtx);
        [out appendFormat:@"  field[%u]=%@ flags=0x%x type=%@",
         i, fieldName, fr->flags, VICMMangledPreview(typeMangled, 64)];
        if (typeName.length) [out appendFormat:@" -> %@", typeName];
        [out appendString:@"\n"];
    }
}

static const uint8_t *VICMFindRequestTypeContext(const uint8_t *section, unsigned long size) {
    const uint8_t *cursor = section;
    const uint8_t *end = section + size;
    NSUInteger guard = 0;
    while (cursor + sizeof(VICMFieldDescriptor) <= end && guard < 20000) {
        const VICMFieldDescriptor *fd = (const VICMFieldDescriptor *)cursor;
        if (!VICMValidDescriptor(fd)) {
            cursor += 4;
            guard++;
            continue;
        }

        BOOL hasEnvironment = NO;
        BOOL hasVLU = NO;
        const uint8_t *requestTypeMangled = NULL;
        const uint8_t *records = cursor + sizeof(*fd);
        for (uint32_t i = 0; i < fd->numFields; i++) {
            const VICMFieldRecord *fr =
                (const VICMFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
            NSString *name = VICMFieldName(fr);
            if ([name isEqualToString:@"environmentBundleIdentifier"]) hasEnvironment = YES;
            else if ([name isEqualToString:@"vluAuthorized"]) hasVLU = YES;
            else if ([name isEqualToString:@"requestType"]) requestTypeMangled = VICMFieldTypeMangled(fr);
        }
        if (hasEnvironment && hasVLU && requestTypeMangled) {
            const uint8_t *ctx = VICMResolveFirstContextFromMangled(requestTypeMangled);
            if (ctx) return ctx;
        }

        uint64_t total = sizeof(*fd) + (uint64_t)fd->fieldRecordSize * fd->numFields;
        cursor += total;
        guard++;
    }
    return NULL;
}

static void VICMAppendRequestTypeEnum(NSMutableString *out, VICMImage image) {
    [out appendString:@"\n--- requestType enum: cross-descriptor owner match ---\n"];
    unsigned long size = 0;
    const uint8_t *section = getsectiondata(image.header, "__TEXT", "__swift5_fieldmd", &size);
    if (!section || size < sizeof(VICMFieldDescriptor)) {
        [out appendFormat:@"fieldmd unavailable size=%lu\n", size];
        return;
    }

    const uint8_t *targetCtx = VICMFindRequestTypeContext(section, size);
    NSString *targetName = VICMContextFullName(targetCtx);
    [out appendFormat:@"requestTypeContext=%@\n", targetName ?: @"<unresolved>"];
    if (!targetCtx) return;

    const uint8_t *cursor = section;
    const uint8_t *end = section + size;
    NSUInteger guard = 0;
    BOOL found = NO;
    while (cursor + sizeof(VICMFieldDescriptor) <= end && guard < 20000) {
        const VICMFieldDescriptor *fd = (const VICMFieldDescriptor *)cursor;
        if (!VICMValidDescriptor(fd)) {
            cursor += 4;
            guard++;
            continue;
        }
        const uint8_t *ownerCtx = VICMOwnerContext(fd);
        if (ownerCtx == targetCtx) {
            [out appendFormat:@"matchedDescriptorOffset=0x%lx kind=%@ numFields=%u\n",
             (unsigned long)(cursor - section), VICMFieldKindName(fd->kind), fd->numFields];
            const uint8_t *records = cursor + sizeof(*fd);
            for (uint32_t i = 0; i < fd->numFields; i++) {
                const VICMFieldRecord *fr =
                    (const VICMFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
                [out appendFormat:@"  case[%u]=%@ flags=0x%x\n",
                 i, VICMFieldName(fr) ?: @"<unreadable>", fr->flags];
            }
            found = YES;
            break;
        }
        uint64_t total = sizeof(*fd) + (uint64_t)fd->fieldRecordSize * fd->numFields;
        cursor += total;
        guard++;
    }
    if (!found) [out appendString:@"no field descriptor owner matched the resolved enum context\n"];
}

static void VICMAppendInterestingFieldOwners(NSMutableString *out, VICMImage image) {
    [out appendString:@"\n--- exact Swift field-owner mapping ---\n"];
    unsigned long size = 0;
    const uint8_t *section = getsectiondata(image.header, "__TEXT", "__swift5_fieldmd", &size);
    if (!section || size < sizeof(VICMFieldDescriptor)) {
        [out appendFormat:@"fieldmd unavailable size=%lu\n", size];
        return;
    }

    NSSet<NSString *> *targets = [NSSet setWithArray:@[
        @"isChinaRegion",
        @"hasAdditionalChinaPolicy",
        @"streamingVICC",
        @"enableStreamingViccAndRaveSTXDomains",
        @"requestType",
        @"vluAuthorized",
        @"environmentBundleIdentifier",
        @"visualIntelligenceCamera",
        @"gviccContentClassifier",
        @"screenshots",
        @"sharedVLUService",
        @"authorizationDelegate",
        @"_cachedAuthorizationStatus"
    ]];

    const uint8_t *cursor = section;
    const uint8_t *end = section + size;
    NSUInteger guard = 0;
    NSUInteger emitted = 0;
    NSMutableSet<NSValue *> *seen = [NSMutableSet set];

    while (cursor + sizeof(VICMFieldDescriptor) <= end && guard < 20000 && emitted < 80) {
        const VICMFieldDescriptor *fd = (const VICMFieldDescriptor *)cursor;
        if (!VICMValidDescriptor(fd)) {
            cursor += 4;
            guard++;
            continue;
        }

        NSMutableArray<NSString *> *matches = [NSMutableArray array];
        const uint8_t *records = cursor + sizeof(*fd);
        for (uint32_t i = 0; i < fd->numFields; i++) {
            const VICMFieldRecord *fr =
                (const VICMFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
            NSString *name = VICMFieldName(fr);
            if (name.length && [targets containsObject:name]) [matches addObject:name];
        }

        if (matches.count) {
            NSValue *key = [NSValue valueWithPointer:fd];
            if (![seen containsObject:key]) {
                [seen addObject:key];
                VICMAppendDescriptor(out, fd, section,
                                     [NSString stringWithFormat:@"matches=%@",
                                      [matches componentsJoinedByString:@","]]);
                emitted++;
            }
        }

        uint64_t total = sizeof(*fd) + (uint64_t)fd->fieldRecordSize * fd->numFields;
        cursor += total;
        guard++;
    }
    [out appendFormat:@"fieldmdSize=%lu descriptorsVisited=%lu descriptorsEmitted=%lu\n",
     size, (unsigned long)guard, (unsigned long)emitted];
}

static BOOL VICMSelectedString(NSString *s) {
    NSString *lower = s.lowercaseString;
    NSArray<NSString *> *needles = @[
        @"china", @"region", @"country", @"storefront", @"vlu",
        @"gvicc", @"visualintelligencecamera", @"authorization"
    ];
    for (NSString *needle in needles) {
        if ([lower containsString:needle]) return YES;
    }
    return NO;
}

static void VICMAppendStringSection(NSMutableString *out,
                                    VICMImage image,
                                    const char *sectionName,
                                    NSString *label,
                                    NSUInteger cap) {
    unsigned long size = 0;
    const uint8_t *section = getsectiondata(image.header, "__TEXT", sectionName, &size);
    [out appendFormat:@"\n--- %@ selected strings ---\n", label];
    if (!section || !size) {
        [out appendFormat:@"%@ unavailable\n", label];
        return;
    }

    NSUInteger emitted = 0;
    NSUInteger offset = 0;
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    while (offset < size && emitted < cap) {
        const uint8_t *ptr = section + offset;
        size_t remain = size - offset;
        const void *nul = memchr(ptr, 0, remain);
        if (!nul) break;
        size_t len = (const uint8_t *)nul - ptr;
        if (len >= 3 && len <= 512) {
            NSString *s = [[NSString alloc] initWithBytes:ptr length:len encoding:NSUTF8StringEncoding];
            if (s.length && VICMSelectedString(s) && ![seen containsObject:s]) {
                [seen addObject:s];
                [out appendFormat:@"%@+0x%lx: %@\n", label, (unsigned long)offset, s];
                emitted++;
            }
        }
        offset += len + 1;
    }
    [out appendFormat:@"selected=%lu sectionSize=%lu\n",
     (unsigned long)emitted, size];
}

static BOOL VICMClassRelevant(NSString *name) {
    NSString *lower = name.lowercaseString;
    return [lower containsString:@"visualintelligence"] ||
           [lower hasPrefix:@"vic"] ||
           [lower hasPrefix:@"vkc"] ||
           [lower containsString:@"greymatter"] ||
           [lower containsString:@"vlu"] ||
           [lower containsString:@"tamale"];
}

static BOOL VICMRegionMemberRelevant(NSString *name) {
    NSString *lower = name.lowercaseString;
    NSArray<NSString *> *needles = @[
        @"china", @"region", @"country", @"storefront", @"vlu", @"authoriz"
    ];
    for (NSString *needle in needles) {
        if ([lower containsString:needle]) return YES;
    }
    return NO;
}

static void VICMAppendObjCRuntimeSurfaces(NSMutableString *out) {
    [out appendString:@"\n--- Objective-C VI China/region/VLU metadata surfaces (not invoked) ---\n"];
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        [out appendString:@"objc_getClassList returned no classes\n"];
        return;
    }
    Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
    if (!classes) {
        [out appendString:@"class allocation failed\n"];
        return;
    }
    count = objc_getClassList(classes, count);
    NSUInteger classHits = 0;
    NSUInteger memberHits = 0;
    for (int i = 0; i < count && classHits < 120; i++) {
        const char *rawName = class_getName(classes[i]);
        if (!rawName) continue;
        NSString *className = [NSString stringWithUTF8String:rawName];
        if (!VICMClassRelevant(className)) continue;

        NSMutableArray<NSString *> *members = [NSMutableArray array];
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(classes[i], &mcount);
        for (unsigned int j = 0; j < mcount && members.count < 80; j++) {
            NSString *name = NSStringFromSelector(method_getName(methods[j]));
            if (!VICMRegionMemberRelevant(name)) continue;
            const char *types = method_getTypeEncoding(methods[j]);
            [members addObject:[NSString stringWithFormat:@"- %@ types=%s", name, types ?: "<nil>"]];
        }
        free(methods);

        Class meta = object_getClass(classes[i]);
        methods = meta ? class_copyMethodList(meta, &mcount) : NULL;
        for (unsigned int j = 0; j < mcount && members.count < 80; j++) {
            NSString *name = NSStringFromSelector(method_getName(methods[j]));
            if (!VICMRegionMemberRelevant(name)) continue;
            const char *types = method_getTypeEncoding(methods[j]);
            [members addObject:[NSString stringWithFormat:@"+ %@ types=%s", name, types ?: "<nil>"]];
        }
        free(methods);

        unsigned int pcount = 0;
        objc_property_t *props = class_copyPropertyList(classes[i], &pcount);
        for (unsigned int j = 0; j < pcount && members.count < 80; j++) {
            const char *raw = property_getName(props[j]);
            if (!raw) continue;
            NSString *name = [NSString stringWithUTF8String:raw];
            if (!VICMRegionMemberRelevant(name)) continue;
            const char *attrs = property_getAttributes(props[j]);
            [members addObject:[NSString stringWithFormat:@"property %@ attrs=%s", name, attrs ?: "<nil>"]];
        }
        free(props);

        if (members.count) {
            [out appendFormat:@"\nclass=%@\n", className];
            for (NSString *member in members) [out appendFormat:@"  %@\n", member];
            classHits++;
            memberHits += members.count;
        }
    }
    free(classes);
    [out appendFormat:@"runtimeClassesWithHits=%lu runtimeMembers=%lu\n",
     (unsigned long)classHits, (unsigned long)memberHits];
}

NSString *VIChinaMetadataGenerateReport(void) {
    @autoreleasepool {
        NSMutableString *out = [NSMutableString string];
        [out appendString:@"========== iOS 27 VI CHINA-FIELD OWNER + REQUESTTYPE ENUM READ-ONLY Diagnostic ==========\n"];
        [out appendFormat:@"Generated: %@\n", [NSDate date]];
        [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
        [out appendFormat:@"Process: %@ bundle=%@\n",
         NSProcessInfo.processInfo.processName,
         NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
        [out appendString:@"SAFETY: pure read-only dyld/Swift reflection metadata, Objective-C runtime metadata, and embedded-string inspection. No enum-taking API calls, no getters/setters on private VI objects, no preheat/XPC, no swizzling/IMP replacement, no preferences/MobileGestalt writes, no respring/reboot.\n\n"];

        NSString *vicPath = @"/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore";
        NSString *vkcPath = @"/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore";
        NSString *gmPath = @"/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels";
        void *vicHandle = dlopen(vicPath.UTF8String, RTLD_LAZY | RTLD_LOCAL);
        void *vkcHandle = dlopen(vkcPath.UTF8String, RTLD_LAZY | RTLD_LOCAL);
        void *gmHandle = dlopen(gmPath.UTF8String, RTLD_LAZY | RTLD_LOCAL);
        [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vicHandle ? @"OK" : @"FAIL"];
        [out appendFormat:@"VisionKitCore dlopen=%@\n", vkcHandle ? @"OK" : @"FAIL"];
        [out appendFormat:@"GenerativeModels dlopen=%@\n", gmHandle ? @"OK" : @"FAIL"];

        VICMImage vic;
        if (VICMFindImage(@"VisualIntelligenceCore.framework/VisualIntelligenceCore", &vic)) {
            VICMAppendRequestTypeEnum(out, vic);
            VICMAppendInterestingFieldOwners(out, vic);
            VICMAppendStringSection(out, vic, "__swift5_reflstr", @"__swift5_reflstr", 180);
            VICMAppendStringSection(out, vic, "__cstring", @"__cstring", 180);
        } else {
            [out appendString:@"VisualIntelligenceCore loaded image not found.\n"];
        }

        VICMAppendObjCRuntimeSurfaces(out);

        [out appendString:@"\n--- interpretation targets ---\n"];
        [out appendString:@"A. Identify the concrete owner of isChinaRegion and its sibling fields.\n"];
        [out appendString:@"B. Recover VICVisualIntelligenceAnalysisRequestType by matching the requestType field's resolved context to the enum field descriptor owner.\n"];
        [out appendString:@"C. Determine whether China/region/storefront logic belongs to request construction, VLU provider configuration, analytics only, or another unrelated subsystem.\n"];
        [out appendString:@"D. Do not infer Camera behavior from fresh vluAuthorized=nil; both fresh VIC and Screenshot VI configs default nil on this build.\n"];
        [out appendString:@"================================================================================\n"];

        if (vicHandle) dlclose(vicHandle);
        if (vkcHandle) dlclose(vkcHandle);
        if (gmHandle) dlclose(gmHandle);
        return out;
    }
}
