#include "polaris_bt_h4.h"
#include <string.h>

static uint32_t header_size(uint8_t type)
{
    return type == 2 ? 5 : type == 3 ? 4 : type == 4 ? 3 : 0;
}

static int overlaps(const void *first, uint32_t first_size,
    const void *second, uint32_t second_size)
{
    uintptr_t a = (uintptr_t)first, b = (uintptr_t)second;
    if (first_size > UINTPTR_MAX - a || second_size > UINTPTR_MAX - b) return 1;
    return first_size && second_size && a < b + second_size && b < a + first_size;
}

int polaris_bt_h4_init(struct polaris_bt_h4 *decoder, uint32_t max_acl,
    uint32_t ibs_enabled)
{
    if (!decoder || !max_acl || max_acl > 4096 || ibs_enabled > 1)
        return PH4_INVALID;
    memset(decoder, 0, sizeof(*decoder));
    decoder->max_acl = max_acl;
    decoder->ibs_enabled = ibs_enabled;
    return PH4_OK;
}

int polaris_bt_h4_receive(struct polaris_bt_h4 *decoder,
    const struct polaris_bt_h4_sink *sink, const uint8_t *data, uint32_t size,
    uint32_t *consumed)
{
    if (!consumed) return PH4_INVALID;
    if (decoder && overlaps(consumed, sizeof(*consumed), decoder, sizeof(*decoder)))
        return PH4_INVALID;
    if (sink && overlaps(consumed, sizeof(*consumed), sink, sizeof(*sink)))
        return PH4_INVALID;
    if (size && data && overlaps(consumed, sizeof(*consumed), data, size))
        return PH4_INVALID;
    *consumed = 0;
    if (!decoder || !sink || !sink->packet || (size && !data) || size > 16384)
        return PH4_INVALID;
    if (decoder->quarantined) return PH4_QUARANTINED;
    if (!decoder->max_acl || decoder->max_acl > 4096 || decoder->ibs_enabled > 1 ||
        (decoder->ibs_enabled && !sink->control) ||
        decoder->used > decoder->expected || decoder->expected > sizeof(decoder->packet) ||
        (!decoder->used && (decoder->header_size || decoder->expected)) ||
        overlaps(data, size, decoder, sizeof(*decoder))) return PH4_INVALID;
    if (decoder->used && (decoder->header_size != header_size(decoder->packet[0]) ||
        !decoder->header_size || decoder->expected < decoder->header_size ||
        (decoder->used < decoder->header_size && decoder->expected != decoder->header_size)))
        return PH4_INVALID;
    while (*consumed < size) {
        if (!decoder->used) {
            uint8_t type = data[(*consumed)++];
            if (type >= 0xfc && type <= 0xfe) {
                if (!decoder->ibs_enabled) goto protocol;
                if (sink->control(sink->context, type)) goto callback;
                continue;
            }
            decoder->header_size = header_size(type);
            if (!decoder->header_size) goto protocol;
            decoder->expected = decoder->header_size;
            decoder->packet[0] = type;
            decoder->used = 1;
        }
        uint32_t count = decoder->expected - decoder->used;
        if (count > size - *consumed) count = size - *consumed;
        memcpy(decoder->packet + decoder->used, data + *consumed, count);
        decoder->used += count;
        *consumed += count;
        if (decoder->used < decoder->header_size) continue;
        if (decoder->expected == decoder->header_size) {
            uint32_t payload = decoder->packet[0] == 2 ?
                (uint32_t)decoder->packet[3] | ((uint32_t)decoder->packet[4] << 8) :
                decoder->packet[decoder->header_size - 1];
            if (decoder->packet[0] == 2 && payload > decoder->max_acl) goto protocol;
            decoder->expected = decoder->header_size + payload;
        }
        if (decoder->used < decoder->expected) continue;
        if (sink->packet(sink->context, decoder->packet[0], decoder->packet + 1,
                decoder->used - 1)) goto callback;
        decoder->used = decoder->expected = decoder->header_size = 0;
    }
    return PH4_OK;
protocol:
    decoder->quarantined = 1;
    return PH4_PROTOCOL;
callback:
    decoder->quarantined = 1;
    return PH4_CALLBACK;
}

int polaris_bt_h4_command(uint16_t opcode, const uint8_t *parameters,
    uint32_t parameter_size, uint8_t *output, uint32_t output_capacity)
{
    if (!opcode || !output || parameter_size > 255 ||
        (parameter_size && !parameters) || output_capacity < parameter_size + 4)
        return PH4_INVALID;
    if (parameter_size) memmove(output + 4, parameters, parameter_size);
    output[0] = 1;
    output[1] = (uint8_t)opcode;
    output[2] = (uint8_t)(opcode >> 8);
    output[3] = (uint8_t)parameter_size;
    return PH4_OK;
}
