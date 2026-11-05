#ifndef POLARIS_MSS_H
#define POLARIS_MSS_H

#include "polaris_mdt.h"

enum polaris_mss_state {
    PMSS_NEW,
    PMSS_METADATA_AUTHENTICATED,
    PMSS_LOADING,
    PMSS_AUTHENTICATED,
    PMSS_QUARANTINED
};

enum polaris_mss_result {
    PMSS_OK = 0,
    PMSS_INVALID = -1,
    PMSS_IO = -2,
    PMSS_TIMEOUT = -3,
    PMSS_AUTH_ERROR = -4,
    PMSS_NOT_READY = -5
};

struct polaris_mss_io {
    void *context;
    int (*read)(void *, uint32_t, uint32_t *);
    int (*write)(void *, uint32_t, uint32_t);
    int (*barrier)(void *);
    int (*publish_segment)(void *, const struct polaris_mdt_segment *);
    uint64_t (*now_us)(void *);
    void (*pause_us)(void *, uint32_t);
};

struct polaris_mss_session {
    uint32_t state;
    uint32_t next_segment;
    uint32_t firmware_error;
    const struct polaris_mdt_plan *plan;
    const struct polaris_mss_io *io;
};

int polaris_mss_metadata(struct polaris_mss_session *session,
    const struct polaris_mss_io *io, const struct polaris_mdt_plan *plan,
    uint32_t metadata_address, uint32_t timeout_us);
int polaris_mss_segment(struct polaris_mss_session *session, uint32_t index);
int polaris_mss_finish(struct polaris_mss_session *session, uint32_t timeout_us);

#endif
