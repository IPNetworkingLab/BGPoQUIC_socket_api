//
// Created by thomas on 26/09/22.
//

#ifndef QUIC_SOCK_QUIC_SOCK_H
#define QUIC_SOCK_QUIC_SOCK_H

#include "msquic_api/msquic_sock.h"
#include "picoquic/picoquic_sock.h"

#include "common/util_common_sock.h"

union quic_sock {
    struct common_sock common;
    struct msquic_socket msquic;
    struct picoquic_socket picoquic;
};

#endif //QUIC_SOCK_QUIC_SOCK_H
