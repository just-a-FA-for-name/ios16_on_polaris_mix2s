#include "polaris_mss.h"

#define PMSS_BASE UINT64_C(0x8e400000)
#define PMSS_END UINT64_C(0x95c00000)

static int valid_plan(const struct polaris_mdt_plan *plan)
{
    if (!plan || !plan->count || plan->count > 100 ||
        plan->boot_address != PMSS_BASE || !plan->span ||
        plan->span > PMSS_END - PMSS_BASE) return 0;
    uint64_t total = 0;
    for (uint32_t i = 0; i < plan->count; ++i) {
        const struct polaris_mdt_segment *segment = &plan->segments[i];
        if (!segment->memory_size || segment->file_size > segment->memory_size ||
            segment->destination < PMSS_BASE || segment->destination >= PMSS_END ||
            segment->memory_size > PMSS_END - segment->destination) return 0;
        total += segment->memory_size;
        if (total > UINT32_MAX || segment->code_length != total) return 0;
        for (uint32_t j = 0; j < i; ++j) {
            const struct polaris_mdt_segment *other = &plan->segments[j];
            if (segment->destination < other->destination + other->memory_size &&
                other->destination < segment->destination + segment->memory_size)
                return 0;
        }
    }
    return 1;
}

static int failed(struct polaris_mss_session *session, int result)
{
    session->state = PMSS_QUARANTINED;
    return result;
}

static int status(struct polaris_mss_session *session, uint32_t *value)
{
    const struct polaris_mss_io *io = session->io;
    if (io->read(io->context, 0x0c, value)) return failed(session, PMSS_IO);
    if (*value & 0x80000000u) {
        session->firmware_error = *value;
        return failed(session, PMSS_AUTH_ERROR);
    }
    return PMSS_OK;
}

static int wait_status(struct polaris_mss_session *session,
    uint32_t expected, uint32_t timeout_us)
{
    const struct polaris_mss_io *io = session->io;
    uint64_t start = io->now_us(io->context), previous = start;
    if (!timeout_us || timeout_us > 10000000 || start > UINT64_MAX - timeout_us)
        return failed(session, PMSS_INVALID);
    uint64_t deadline = start + timeout_us;
    uint32_t attempts = timeout_us / 50 + 2;
    while (attempts--) {
        uint32_t value;
        int result = status(session, &value);
        if (result) return result;
        uint64_t now = io->now_us(io->context);
        if (now < previous) return failed(session, PMSS_IO);
        if (now >= deadline) break;
        previous = now;
        if (value == expected) return PMSS_OK;
        if ((expected == 3 && value != 1 && value != 2) ||
            (expected == 4 && value != 3)) return failed(session, PMSS_NOT_READY);
        uint64_t remaining = deadline - now;
        io->pause_us(io->context, remaining < 50 ? (uint32_t)remaining : 50);
    }
    return failed(session, PMSS_TIMEOUT);
}

int polaris_mss_metadata(struct polaris_mss_session *session,
    const struct polaris_mss_io *io, const struct polaris_mdt_plan *plan,
    uint32_t metadata_address, uint32_t timeout_us)
{
    if (!session || session->state != PMSS_NEW || !io ||
        !io->read || !io->write || !io->barrier || !io->publish_segment ||
        !io->now_us || !io->pause_us || !metadata_address ||
        (metadata_address & 4095u) || !valid_plan(plan) ||
        !timeout_us || timeout_us > 10000000) return PMSS_INVALID;
    session->io = io;
    session->plan = plan;
    session->next_segment = 0;
    session->firmware_error = 0;
    uint32_t pbl, mba, length;
    if (io->read(io->context, 4, &pbl) ||
        io->read(io->context, 0x0c, &mba) ||
        io->read(io->context, 0x18, &length)) return failed(session, PMSS_IO);
    if (pbl != 1 || (mba != 1 && mba != 2) || length != 0)
        return failed(session, PMSS_NOT_READY);
    if (io->barrier(io->context) ||
        io->write(io->context, 0x18, 0) ||
        io->write(io->context, 0x10, metadata_address) ||
        io->barrier(io->context) ||
        io->write(io->context, 8, 1) ||
        io->barrier(io->context)) return failed(session, PMSS_IO);
    int result = wait_status(session, 3, timeout_us);
    if (!result) session->state = PMSS_METADATA_AUTHENTICATED;
    return result;
}

int polaris_mss_segment(struct polaris_mss_session *session, uint32_t index)
{
    if (!session || (session->state != PMSS_METADATA_AUTHENTICATED &&
        session->state != PMSS_LOADING) || !valid_plan(session->plan) ||
        index != session->next_segment || index >= session->plan->count)
        return PMSS_INVALID;
    const struct polaris_mss_io *io = session->io;
    const struct polaris_mdt_segment *segment = &session->plan->segments[index];
    uint32_t value, length, expected = index ? session->plan->segments[index - 1].code_length : 0;
    int result = status(session, &value);
    if (result) return result;
    if (value != 3) return failed(session, PMSS_NOT_READY);
    if (io->read(io->context, 0x18, &length)) return failed(session, PMSS_IO);
    if (length != expected) return failed(session, PMSS_NOT_READY);
    if (io->publish_segment(io->context, segment) || io->barrier(io->context))
        return failed(session, PMSS_IO);
    if (index == 0 &&
        (io->write(io->context, 0x14, (uint32_t)session->plan->boot_address) ||
         io->barrier(io->context) ||
         io->write(io->context, 8, 2) ||
         io->barrier(io->context))) return failed(session, PMSS_IO);
    if (io->write(io->context, 0x18, segment->code_length) ||
        io->barrier(io->context)) return failed(session, PMSS_IO);
    result = status(session, &value);
    if (result) return result;
    if (value != 3 && !(value == 4 && index + 1 == session->plan->count))
        return failed(session, PMSS_NOT_READY);
    session->next_segment++;
    session->state = PMSS_LOADING;
    return PMSS_OK;
}

int polaris_mss_finish(struct polaris_mss_session *session, uint32_t timeout_us)
{
    if (!session || session->state != PMSS_LOADING ||
        !valid_plan(session->plan) || session->next_segment != session->plan->count ||
        !timeout_us || timeout_us > 10000000) return PMSS_INVALID;
    int result = wait_status(session, 4, timeout_us);
    if (!result) session->state = PMSS_AUTHENTICATED;
    return result;
}
