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
