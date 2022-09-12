//
// Created by thomas on 25/10/22.
//

#ifndef QUIC_SOCK_COMMON_NDP_H
#define QUIC_SOCK_COMMON_NDP_H


static inline const char *addr_to_str(struct sockaddr *addr, char *buf, size_t buf_len) {
    void *inx_addr;

    switch (addr->sa_family) {
        case AF_INET:
            inx_addr = &((struct sockaddr_in *) addr)->sin_addr;
            break;
        case AF_INET6:
            inx_addr = &((struct sockaddr_in6 *) addr)->sin6_addr;
            break;
        default:
            return NULL;
    }

    return inet_ntop(addr->sa_family, inx_addr, buf, buf_len);
}

static inline int get_port(struct sockaddr *addr) {
    in_port_t n_port;

    switch (addr->sa_family) {
        case AF_INET:
            n_port = ((struct sockaddr_in *) addr)->sin_port;
            break;
        case AF_INET6:
            n_port = ((struct sockaddr_in6 *) addr)->sin6_port;
            break;
        default:
            return -1;
    }

    return ntohs(n_port);
}


#endif //QUIC_SOCK_COMMON_NDP_H
