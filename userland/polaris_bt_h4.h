#ifndef POLARIS_BT_H4_H
#define POLARIS_BT_H4_H

#include <stdint.h>

enum polaris_bt_h4_result {
    PH4_OK = 0,
    PH4_INVALID = -1,
    PH4_PROTOCOL = -2,
    PH4_CALLBACK = -3,
    PH4_QUARANTINED = -4
};

struct polaris_bt_h4 {
    uint32_t used;
    uint32_t expected;
    uint32_t header_size;
    uint32_t max_acl;
    uint32_t ibs_enabled;
    uint32_t quarantined;
    uint8_t packet[4101];
};

struct polaris_bt_h4_sink {
    void *context;
    int (*packet)(void *, uint8_t, const uint8_t *borrowed_body, uint32_t);
    int (*control)(void *, uint8_t);
};

int polaris_bt_h4_init(struct polaris_bt_h4 *decoder, uint32_t max_acl,
    uint32_t ibs_enabled);
int polaris_bt_h4_receive(struct polaris_bt_h4 *decoder,
    const struct polaris_bt_h4_sink *sink, const uint8_t *data, uint32_t size,
    uint32_t *consumed);
int polaris_bt_h4_command(uint16_t opcode, const uint8_t *parameters,
    uint32_t parameter_size, uint8_t *output, uint32_t output_capacity);

#endif
