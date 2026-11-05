#include "polaris_mdt.h"
#include <string.h>

static uint32_t u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t u16(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

int polaris_mdt_plan(const uint8_t *metadata, size_t metadata_size,
    uint64_t reserved_base, uint64_t reserved_size,
    struct polaris_mdt_plan *output)
{
    if (!metadata || !output || metadata_size < 52 || !reserved_size ||
        reserved_base > UINT64_MAX - reserved_size ||
        memcmp(metadata, "\177ELF\1\1\1", 7) ||
        u16(metadata + 16) != 2 || u16(metadata + 18) != 164 ||
        u32(metadata + 20) != 1 || u16(metadata + 40) != 52 ||
        u16(metadata + 42) != 32) return -1;
    uint32_t table = u32(metadata + 28), count = u16(metadata + 44);
    if (!count || count > 100 || table < 52 || table > metadata_size ||
        (uint64_t)count * 32 > metadata_size - table) return -1;
    struct polaris_mdt_plan plan = {0};
    uint64_t minimum = UINT64_MAX, maximum = 0, total = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *p = metadata + table + i * 32;
        uint32_t flags = u32(p + 24), memory_size = u32(p + 20);
        if (u32(p) != 1 || ((flags >> 24) & 7u) == 2 || !memory_size)
            continue;
        uint32_t address = u32(p + 12), file_size = u32(p + 16);
        uint64_t end = (uint64_t)address + memory_size;
        if (file_size > memory_size || end > UINT32_MAX ||
            total + memory_size > UINT32_MAX) return -1;
        struct polaris_mdt_segment *segment = &plan.segments[plan.count++];
        segment->index = i;
        segment->file_offset = u32(p + 4);
        segment->file_size = file_size;
        segment->memory_size = memory_size;
        segment->destination = address;
        total += memory_size;
        segment->code_length = (uint32_t)total;
        if (address < minimum) minimum = address;
        if (end > maximum) maximum = end;
        if (flags & 0x08000000u) plan.relocatable = 1;
    }
    if (!plan.count) return -1;
    uint64_t origin = plan.relocatable ? minimum : reserved_base;
    for (uint32_t i = 0; i < plan.count; ++i) {
        struct polaris_mdt_segment *segment = &plan.segments[i];
        if (segment->destination < origin) return -1;
        uint64_t offset = segment->destination - origin;
        if (offset > reserved_size || segment->memory_size > reserved_size - offset)
            return -1;
        segment->destination = reserved_base + offset;
        for (uint32_t j = 0; j < i; ++j) {
            const struct polaris_mdt_segment *other = &plan.segments[j];
            if (segment->destination < other->destination + other->memory_size &&
                other->destination < segment->destination + segment->memory_size)
                return -1;
        }
    }
    plan.boot_address = plan.relocatable ? reserved_base : minimum;
    plan.span = ((maximum + 4095u) & ~4095ull) - minimum;
    if (plan.span > reserved_size) return -1;
    *output = plan;
    return 0;
}

static int overlaps_output(const void *data, size_t size,
    const uint8_t *output, size_t output_size)
{
    uintptr_t a = (uintptr_t)data, b = (uintptr_t)output;
    if (size > UINTPTR_MAX - a || output_size > UINTPTR_MAX - b) return 1;
    return size && a < b + output_size && b < a + size;
}

int polaris_mdt_metadata(const uint8_t *image, size_t image_size,
    const struct polaris_mdt_blob *split, uint32_t split_count,
    uint8_t *output, size_t output_size, size_t *written)
{
    if (!image || !written || image_size < 52 || (split_count && !split) ||
        split_count > 100 || (!output && output_size) ||
        memcmp(image, "\177ELF\1\1\1", 7) ||
        u16(image + 16) != 2 || u16(image + 18) != 164 ||
        u32(image + 20) != 1 || u16(image + 40) != 52 ||
        u16(image + 42) != 32) return -1;
    uint32_t table = u32(image + 28), count = u16(image + 44);
    if (count < 2 || count > 100 || table < 52 || table > image_size ||
        (uint64_t)count * 32 > image_size - table) return -1;
    const uint8_t *first = image + table;
    uint32_t header_size = u32(first + 16), hash_index = 0;
    if (u32(first) == 1 || u32(first + 4) != 0 ||
        ((u32(first + 24) >> 24) & 7u) == 2 ||
        header_size < (uint64_t)table + count * 32 ||
        header_size > image_size) return -1;
    for (uint32_t i = 1; i < count; ++i) {
        if (((u32(image + table + i * 32 + 24) >> 24) & 7u) != 2) continue;
        if (hash_index) return -1;
        hash_index = i;
    }
    if (!hash_index) return -1;
    const uint8_t *hash_header = image + table + hash_index * 32;
    uint32_t hash_size = u32(hash_header + 16), offset = u32(hash_header + 4);
    uint64_t total = (uint64_t)header_size + hash_size;
    if (!hash_size || total > SIZE_MAX) return -1;
    const uint8_t *hash;
    if (image_size == total) {
        hash = image + header_size;
    } else if (offset < image_size) {
        if (offset < header_size || hash_size > image_size - offset) return -1;
        hash = image + offset;
    } else {
        if (hash_index >= split_count || !split[hash_index].data ||
            split[hash_index].size != hash_size) return -1;
        hash = split[hash_index].data;
    }
    if (overlaps_output(image, image_size, (const uint8_t *)written, sizeof(*written)) ||
        overlaps_output(hash, hash_size, (const uint8_t *)written, sizeof(*written)))
        return -1;
    if (output) {
        if (output_size < total ||
            overlaps_output(image, image_size, output, output_size) ||
            overlaps_output(hash, hash_size, output, output_size) ||
            overlaps_output(written, sizeof(*written), output, output_size)) return -1;
        memcpy(output, image, header_size);
        memcpy(output + header_size, hash, hash_size);
    }
    *written = (size_t)total;
    return 0;
}

int polaris_mdt_stage(const uint8_t *metadata, size_t metadata_size,
    uint64_t reserved_base, uint64_t reserved_size,
    const struct polaris_mdt_blob *split, uint32_t split_count,
    uint8_t *output, size_t output_size)
{
    struct polaris_mdt_plan plan;
    if (!output || reserved_size > output_size || (split_count && !split) ||
        polaris_mdt_plan(metadata, metadata_size, reserved_base, reserved_size, &plan) ||
        overlaps_output(metadata, metadata_size, output, output_size)) return -1;
    const uint8_t *sources[100] = {0};
    for (uint32_t i = 0; i < plan.count; ++i) {
        const struct polaris_mdt_segment *segment = &plan.segments[i];
        if (!segment->file_size) continue;
        if (segment->file_offset < metadata_size) {
            if (segment->file_size > metadata_size - segment->file_offset) return -1;
            sources[i] = metadata + segment->file_offset;
        } else {
            if (segment->index >= split_count ||
                split[segment->index].size != segment->file_size ||
                !split[segment->index].data) return -1;
            sources[i] = split[segment->index].data;
        }
        if (overlaps_output(sources[i], segment->file_size, output, output_size))
            return -1;
    }
    for (uint32_t i = 0; i < plan.count; ++i) {
        const struct polaris_mdt_segment *segment = &plan.segments[i];
        uint8_t *destination = output + (size_t)(segment->destination - reserved_base);
        if (segment->file_size) memcpy(destination, sources[i], segment->file_size);
        memset(destination + segment->file_size, 0,
            segment->memory_size - segment->file_size);
    }
    return 0;
}
