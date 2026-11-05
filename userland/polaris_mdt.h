#ifndef POLARIS_MDT_H
#define POLARIS_MDT_H

#include <stddef.h>
#include <stdint.h>

struct polaris_mdt_segment {
    uint32_t index;
    uint32_t file_offset;
    uint32_t file_size;
    uint32_t memory_size;
    uint64_t destination;
    uint32_t code_length;
};

struct polaris_mdt_plan {
    uint32_t count;
    uint32_t relocatable;
    uint64_t boot_address;
    uint64_t span;
    struct polaris_mdt_segment segments[100];
};

struct polaris_mdt_blob {
    const uint8_t *data;
    size_t size;
};

int polaris_mdt_plan(const uint8_t *metadata, size_t metadata_size,
    uint64_t reserved_base, uint64_t reserved_size,
    struct polaris_mdt_plan *output);
int polaris_mdt_stage(const uint8_t *metadata, size_t metadata_size,
    uint64_t reserved_base, uint64_t reserved_size,
    const struct polaris_mdt_blob *split, uint32_t split_count,
    uint8_t *output, size_t output_size);
int polaris_mdt_metadata(const uint8_t *image, size_t image_size,
    const struct polaris_mdt_blob *split, uint32_t split_count,
    uint8_t *output, size_t output_size, size_t *written);

#endif
