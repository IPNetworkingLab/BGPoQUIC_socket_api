//
// Created by thomas on 5/07/22.
//

#ifndef QUIC_SOCK_UTIL_SOCK_MGR_H
#define QUIC_SOCK_UTIL_SOCK_MGR_H

#include "util_common_sock.h"

// default value of ulimit -n
#define MAX_SOCKFD 1024

struct sock_table {
    int len;
    struct common_sock **socks;
};

void init_sock_table(struct sock_table *socks);

struct common_sock *get_sock(struct sock_table *socks, int sockfd);

int add_sock(struct sock_table *socks, struct common_sock *sock);

void del_sock(struct sock_table *socks, struct common_sock *sock);

#endif //QUIC_SOCK_UTIL_SOCK_MGR_H
