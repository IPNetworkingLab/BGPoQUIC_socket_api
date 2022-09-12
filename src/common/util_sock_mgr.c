//
// Created by thomas on 5/07/22.
//

#include <stdio.h>

#include "util_sock_mgr.h"
#include "uthash.h"


void init_sock_table(struct sock_table *socks) {
    memset(socks->socks, 0, socks->len * sizeof(*socks->socks));
}


struct common_sock *get_sock(struct sock_table *socks, int sockfd) {
    if (sockfd > socks->len) return NULL;
    return socks->socks[sockfd];
}

int add_sock(struct sock_table *socks, struct common_sock *sock) {
    /* array size check */
    if (sock->sockfd > socks->len) return -1;
    /* check if another socket is already stored */
    if (socks->socks[sock->sockfd]) return -1;

    socks->socks[sock->sockfd] = sock;
    return 0;
}

void del_sock(struct sock_table *socks, struct common_sock *sock) {
    if (sock->sockfd > socks->len) return;
    socks->socks[sock->sockfd] = NULL;
}
