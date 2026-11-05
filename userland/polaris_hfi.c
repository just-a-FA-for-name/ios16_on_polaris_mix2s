#include "polaris_hfi.h"

static uint32_t message_words(uint32_t header)
{
    return (header >> 8) & 255u;
}

static int valid_ring(const struct polaris_hfi_ring *ring)
{
    return ring && ring->data && ring->capacity >= 2 &&
        ring->capacity <= 65536 && ring->read_index < ring->capacity &&
        ring->write_index < ring->capacity;
}

int polaris_hfi_command(uint32_t id, uint32_t sequence,
    const uint32_t *payload, uint32_t payload_words,
    uint32_t *output, uint32_t output_capacity)
{
    if (id > 255 || sequence > 4095 || payload_words > 254 ||
        !output || output_capacity <= payload_words ||
        (payload_words && !payload)) return PHFI_INVALID;
    for (uint32_t i = payload_words; i > 0; --i) output[i] = payload[i - 1];
    output[0] = (sequence << 20) | ((payload_words + 1) << 8) | id;
    return PHFI_OK;
}

int polaris_hfi_push(struct polaris_hfi_ring *ring,
    const uint32_t *message, uint32_t words)
{
    if (!valid_ring(ring) || !message || !words || words > 255)
        return PHFI_INVALID;
    if (message_words(message[0]) != words) return PHFI_PROTOCOL;
    uint32_t used = (ring->write_index + ring->capacity -
        ring->read_index) % ring->capacity;
    if (words >= ring->capacity - used) return PHFI_FULL;
    uint32_t next = ring->write_index;
    for (uint32_t i = 0; i < words; ++i) {
        ring->data[next] = message[i];
        next = (next + 1) % ring->capacity;
    }
    ring->write_index = next;
    return PHFI_OK;
}

int polaris_hfi_pop(struct polaris_hfi_ring *ring,
    uint32_t *output, uint32_t output_capacity, uint32_t *words)
{
    if (!valid_ring(ring) || !output || !words) return PHFI_INVALID;
    *words = 0;
    uint32_t available = (ring->write_index + ring->capacity -
        ring->read_index) % ring->capacity;
    if (!available) return PHFI_EMPTY;
    uint32_t count = message_words(ring->data[ring->read_index]);
    if (!count || count > available) return PHFI_PROTOCOL;
    if (count > output_capacity) return PHFI_INVALID;
    uint32_t next = ring->read_index;
    for (uint32_t i = 0; i < count; ++i) {
        output[i] = ring->data[next];
        next = (next + 1) % ring->capacity;
    }
    ring->read_index = next;
    *words = count;
    return PHFI_OK;
}

int polaris_hfi_ack(uint32_t request_header,
    const uint32_t *response, uint32_t words,
    uint32_t *payload, uint32_t payload_capacity,
    uint32_t *payload_words, uint32_t *firmware_error)
{
    if (!response || !payload_words || !firmware_error ||
        words < 3 || words > 19 || !message_words(request_header) ||
        ((request_header >> 16) & 15u)) return PHFI_INVALID;
    *payload_words = 0;
    *firmware_error = 0;
    if (message_words(response[0]) != words ||
        (response[0] & 255u) != 126 ||
        ((response[0] >> 16) & 15u) != 2) return PHFI_PROTOCOL;
    if (response[1] != request_header) return PHFI_UNRELATED;
    if (response[2]) {
        *firmware_error = response[2];
        return PHFI_FIRMWARE_ERROR;
    }
    uint32_t count = words - 3;
    if (count > payload_capacity || (count && !payload)) return PHFI_INVALID;
    for (uint32_t i = 0; i < count; ++i) payload[i] = response[i + 3];
    *payload_words = count;
    return PHFI_OK;
}

int polaris_hfi_exchange(struct polaris_hfi_channel *channel,
    const struct polaris_hfi_transport *transport,
    uint32_t id, const uint32_t *payload, uint32_t payload_words,
    uint32_t *response_payload, uint32_t response_capacity,
    uint32_t *response_words, uint32_t *firmware_error, uint32_t timeout_us)
{
    if (!channel || !transport || !transport->send || !transport->receive ||
        !transport->now_us || !transport->pause_us || !transport->faulted ||
        !response_words || !firmware_error || timeout_us == 0 ||
        timeout_us > 1000000 || (response_capacity && !response_payload))
        return PHFI_INVALID;
    *response_words = 0;
    *firmware_error = 0;
    if (channel->quarantined) return PHFI_QUARANTINED;
    uint32_t command[255], response[19];
    int result = polaris_hfi_command(id, channel->next_sequence,
        payload, payload_words, command, 255);
    if (result) return result;
    void *context = transport->context;
    uint64_t start = transport->now_us(context), previous = start;
    if (start > UINT64_MAX - timeout_us) return PHFI_INVALID;
    uint64_t deadline = start + timeout_us;
    if (transport->faulted(context)) {
        channel->quarantined = 1;
        return PHFI_IO;
    }
    if (transport->send(context, command, payload_words + 1)) {
        channel->quarantined = 1;
        return PHFI_IO;
    }
    channel->next_sequence = (channel->next_sequence + 1) & 4095u;
    uint32_t attempts = timeout_us / 50 + 2;
    while (attempts--) {
        uint64_t now = transport->now_us(context);
        if (now < previous || transport->faulted(context)) {
            result = PHFI_IO;
            goto failed;
        }
        if (now >= deadline) break;
        previous = now;
        uint32_t count = 0;
        int received = transport->receive(context, response, 19, &count);
        now = transport->now_us(context);
        if (now < previous || transport->faulted(context)) {
            result = PHFI_IO;
            goto failed;
        }
        if (now >= deadline) break;
        previous = now;
        if (received == PHFI_OK) {
            result = polaris_hfi_ack(command[0], response, count,
                response_payload, response_capacity, response_words, firmware_error);
            if (result == PHFI_OK) return PHFI_OK;
            if (result != PHFI_UNRELATED) goto failed;
        } else if (received != PHFI_EMPTY) {
            result = PHFI_IO;
            goto failed;
        }
        uint64_t remaining = deadline - now;
        transport->pause_us(context, remaining < 50 ? (uint32_t)remaining : 50);
    }
    result = PHFI_TIMEOUT;
failed:
    channel->quarantined = 1;
    return result;
}
