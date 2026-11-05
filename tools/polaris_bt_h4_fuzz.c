#include "polaris_bt_h4.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t seed = 0x845aecfu;

static uint32_t next_random(void)
{
    seed = seed * 1664525u + 1013904223u;
    return seed;
}

static int receive_packet(void *context, uint8_t type, const uint8_t *body, uint32_t size)
{
    assert(type >= 2 && type <= 4);
    uint32_t header = type == 2 ? 4 : type == 3 ? 3 : 2;
    assert(body && size >= header);
    uint32_t payload = type == 2 ? (uint32_t)body[2] | ((uint32_t)body[3] << 8) : body[header - 1];
    assert(size == header + payload);
    assert(type != 2 || payload <= *(uint32_t *)context);
    return 0;
}

static int receive_control(void *context, uint8_t value)
{
    (void)context;
    assert(value >= 0xfc && value <= 0xfe);
    return 0;
}

int main(void)
{
    struct polaris_bt_h4 decoder;
    uint32_t max_acl;
    struct polaris_bt_h4_sink sink = {&max_acl, receive_packet, receive_control};
    uint8_t data[512], output[260];
    for (uint32_t trial = 0; trial < 50000; ++trial) {
        max_acl = 1 + next_random() % 1024;
        assert(polaris_bt_h4_init(&decoder, max_acl, trial & 1) == PH4_OK);
        for (uint32_t i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)(next_random() >> 24);
        uint32_t size = 1 + next_random() % sizeof(data);
        if (trial % 4 < 3) {
            data[0] = 2 + trial % 3;
            uint32_t header = data[0] == 2 ? 5 : data[0] == 3 ? 4 : 3;
            data[header - 1] = (uint8_t)(trial % 64);
            if (data[0] == 2) {
                data[3] = (uint8_t)(trial % 64);
                data[4] = 0;
            }
        }
        for (uint32_t at = 0; at < size;) {
            uint32_t part = 1 + next_random() % 23, consumed = 0;
            if (part > size - at) part = size - at;
            int result = polaris_bt_h4_receive(&decoder, &sink, data + at, part, &consumed);
            assert(consumed <= part);
            if (result != PH4_OK) {
                assert(decoder.quarantined);
                break;
            }
            assert(consumed == part);
            at += consumed;
        }
        uint16_t opcode = (uint16_t)next_random();
        uint32_t length = next_random() % 300, capacity = next_random() % 261;
        memset(output, 0xa5, sizeof(output));
        int result = polaris_bt_h4_command(opcode, data, length, output, capacity);
        if (!opcode || length > 255 || capacity < length + 4) {
            assert(result == PH4_INVALID);
            for (uint32_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
        } else {
            assert(result == PH4_OK && output[0] == 1 && output[3] == length);
            assert(((uint16_t)output[1] | ((uint16_t)output[2] << 8)) == opcode);
            assert(!memcmp(output + 4, data, length));
        }
    }
    puts("50000 H4 stream and command trials passed");
    return 0;
}
