#pragma once

#include <stdint.h>

#define MSYS_MIPC_MAGIC "MSY1"
#define MSYS_MIPC_HEADER_LEN 40
#define MSYS_MIPC_MAX_PAYLOAD (256u * 1024u)

enum msys_mipc_type {
    MSYS_MIPC_HELLO = 1,
    MSYS_MIPC_WELCOME = 2,
    MSYS_MIPC_READY = 3,
    MSYS_MIPC_CALL = 10,
    MSYS_MIPC_RETURN = 11,
    MSYS_MIPC_ERROR = 12,
    MSYS_MIPC_CANCEL = 13,
    MSYS_MIPC_SUBSCRIBE = 20,
    MSYS_MIPC_UNSUBSCRIBE = 21,
    MSYS_MIPC_EVENT = 22,
    MSYS_MIPC_SHUTDOWN = 30
};

struct msys_mipc_header {
    char magic[4];
    uint8_t major;
    uint8_t minor;
    uint16_t header_len;
    uint16_t type;
    uint16_t flags;
    uint32_t payload_len;
    uint64_t request_id;
    uint64_t object_id;
    uint16_t fd_count;
    uint16_t reserved16;
    uint32_t reserved32;
};
