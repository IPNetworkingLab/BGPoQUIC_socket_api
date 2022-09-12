//
// Created by thomas on 15/06/22.
//

#ifndef PLUGINIZED_BIRD_MSQUIC_SOCKET_API_H
#define PLUGINIZED_BIRD_MSQUIC_SOCKET_API_H

#include <sys/socket.h>
#include <msquic.h>

#include "common/uthash.h"
#include "common/util_queue.h"
#include "common/util_ref.h"
#include "common/util_data_buffer.h"
#include "common/util_common_sock.h"
#include "quic_platform.h"
#include "quic_platform_posix.h"

struct msquic_socket {
    struct common_sock sk;

    _Atomic uint32_t flags;


    QUIC_ADDR local_address;
    int must_bind;
    QUIC_ADDR remote_address;

    struct sh_ref *configuration;
    HQUIC listener;
    HQUIC connection;
    HQUIC stream;

    QUIC_TLS_SECRETS secrets;

    /* todo put underlying stream sockets for a connection */

    struct {
        CXPLAT_EVENT r_evt;
        const uint8_t *buf;
        uint32_t buf_length;
    };

    CXPLAT_EVENT w_evt;
    //struct q_buffer wbuf;
    //struct q_buffer rbuf;

    struct q_queue pdt_conn;
};



#endif //PLUGINIZED_BIRD_MSQUIC_SOCKET_API_H
