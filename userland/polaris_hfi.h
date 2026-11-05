#ifndef POLARIS_HFI_H
#define POLARIS_HFI_H

#include <stdint.h>

enum polaris_hfi_result {
    PHFI_OK = 0,
    PHFI_EMPTY = 1,
    PHFI_FULL = 2,
    PHFI_INVALID = -1,
    PHFI_PROTOCOL = -2,
    PHFI_UNRELATED = -3,
    PHFI_FIRMWARE_ERROR = -4,
    PHFI_TIMEOUT = -5,
    PHFI_QUARANTINED = -6,
    PHFI_IO = -7
};

struct polaris_hfi_ring {
    uint32_t *data;
    uint32_t capacity;
    uint32_t read_index;
    uint32_t write_index;
};

struct polaris_hfi_channel {
    uint32_t next_sequence;
    uint32_t quarantined;
};

struct polaris_hfi_transport {
    void *context;
    int (*send)(void *, const uint32_t *, uint32_t);
    int (*receive)(void *, uint32_t *, uint32_t, uint32_t *);
    uint64_t (*now_us)(void *);
    void (*pause_us)(void *, uint32_t);
    int (*faulted)(void *);
};

int polaris_hfi_command(uint32_t id, uint32_t sequence,
    const uint32_t *payload, uint32_t payload_words,
    uint32_t *output, uint32_t output_capacity);
int polaris_hfi_push(struct polaris_hfi_ring *ring,
    const uint32_t *message, uint32_t words);
int polaris_hfi_pop(struct polaris_hfi_ring *ring,
    uint32_t *output, uint32_t output_capacity, uint32_t *words);
int polaris_hfi_ack(uint32_t request_header,
    const uint32_t *response, uint32_t words,
    uint32_t *payload, uint32_t payload_capacity,
    uint32_t *payload_words, uint32_t *firmware_error);
int polaris_hfi_exchange(struct polaris_hfi_channel *channel,
    const struct polaris_hfi_transport *transport,
    uint32_t id, const uint32_t *payload, uint32_t payload_words,
    uint32_t *response_payload, uint32_t response_capacity,
    uint32_t *response_words, uint32_t *firmware_error, uint32_t timeout_us);

#endif
