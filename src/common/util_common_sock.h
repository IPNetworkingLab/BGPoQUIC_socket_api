//
// Created by thomas on 29/09/22.
//

#ifndef QUIC_SOCK_UTIL_COMMON_SOCK_H
#define QUIC_SOCK_UTIL_COMMON_SOCK_H

#include <sys/socket.h>
#include "uthash.h"

#define IS_SET(X, FLAG) ((X) & (FLAG))
#define SET_FLAG(X, FLAG) X |= FLAG
#define UNSET_FLAG(X, FLAG) X &= ~(FLAG)

#define CONNECTED (1U)
#define LISTEN (1U << 1)
#define HAS_PENDING_CONN (1U << 2)
#define HAS_PENDING_STREAM (1U << 3)
#define SOCK_QUIC_STREAM (1U << 4)
#define SOCK_QUIC_LISTENER (1U << 5)
#define SOCK_QUIC_CONNECTION (1U << 6)
#define SOCK_QUIC_SOCKET (1U << 7)
#define SOCK_STOP (1U << 8)
#define CONNECTION_INITIATED (1U << 9)
#define STREAMED (1U << 10)
#define CLOSED (1U << 11)
#define RX_BUFFER_FULL (1U << 12)
#define CLIENT_SIDE_CLOSED (1U << 13)
#define SHOULD_EXPOSE_SECRETS (1U << 14)
#define SECRETS_EXPOSED (1U << 15)


#define get_sock_size(sock) ((sock)->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) )

#define POWER_2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))
#define MIN(x, y) ({ __typeof__ (x) _x = (x); \
       __typeof__ (y) _y = (y); \
     _x < _y ? _x : _y; })

#define unused__(x) ((void) (x))

enum sock_type {
    SOCK_TYPE_UNK = 0,
    SOCK_TYPE_MSQUIC,
    SOCK_TYPE_PICOQUIC
};

struct common_sock {
    struct UT_hash_handle hh;
    int sockfd;
    enum sock_type type;
};

unsigned int iface_name_to_idx(const char *dev_name);

unsigned int ifidx_from_addr(const struct sockaddr *addr, char *dev_name, size_t *dev_name_len);

int iface_from_ipv6_link_local(struct sockaddr *addr, char *dev_name, size_t *dev_name_len);

int stick_this_thread_to_core(long core_id);

unsigned long get_affinity(int pid, unsigned long *core_array, size_t core_array_len) ;

#endif //QUIC_SOCK_UTIL_COMMON_SOCK_H
