//
// Created by thomas on 1/03/23.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <poll.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include "quic_sock/picoquic_sock_api.h"

#define PER_PATH_SEND 10485760

int main(int argc, const char *argv[]) {
    char buf_space[sizeof(struct tls_config) + sizeof(struct alpn_buffer)];
    char str_addr[INET6_ADDRSTRLEN];
    struct sockaddr_in listen_addr;
    struct tls_config *tls_config;
    struct sockaddr_in addr;
    socklen_t addr_len;
    struct pollfd fds[1];
    ssize_t r_buf_recv;
    size_t total_recv;
    char r_buf[8192];
    char *end_ptr;
    int sk_listen;
    int sk_stream;
    int sk_conn;
    long port;
    int err;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s CERT_FILE KEY_FILE PORT\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (picoquic_init("conn migration") != 0) {
        fprintf(stderr, "picoquic_init failed\n");
        return EXIT_FAILURE;
    }

    memset(buf_space, 0, sizeof(buf_space));
    tls_config = (struct tls_config *) buf_space;
    port = strtol(argv[3], &end_ptr, 10);
    if (*end_ptr != 0) {
        fprintf(stderr, "Failed to parse port '%s'\n", argv[3]);
        return EXIT_FAILURE;
    } else if (port <= 0 || port >= UINT16_MAX) {
        fprintf(stderr, "Invalid port: condition not met (0 < port (%ld) < 65536)\n", port);
        return EXIT_FAILURE;
    }

    listen_addr = (struct sockaddr_in) {
            .sin_family = AF_INET,
            .sin_port = htons((uint16_t) port),
            .sin_addr = INADDR_ANY,
    };

    if ((sk_listen = picoquic_socket()) < 0) {
        fprintf(stderr, "Picoquic_socket failed\n");
        return EXIT_FAILURE;
    }

    if (picoquic_bind(sk_listen, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) != 0) {
        fprintf(stderr, "picoquic_bind failed\n");
        return EXIT_FAILURE;
    }

    tls_config->nb_alpn = 1;
    tls_config->certificate_file = argv[1];
    tls_config->private_key_file = argv[2];
    tls_config->alpn[0] = (struct alpn_buffer) {
            .alpn_size = 9,
            .alpn_name = "migration",
    };

    if (picoquic_listen(sk_listen, tls_config) != 0) {
        fprintf(stderr, "picoquic_listen failed\n");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Server listening on %ld\n", port);

    fds[0].events = POLLIN;
    fds[0].fd = sk_listen;


    if ((err = poll(fds, 1, -1)) == -1) {
        perror("poll");
        fprintf(stderr, "Got a poll error.\n");
        return EXIT_FAILURE;
    } else if (err == 0) {
        // Got a timeout, currently not handled
    }

    fds[0].fd = sk_listen;
    fds[0].events = POLLIN;

    if ((err = poll(fds, 1, -1)) == -1) {
        perror("poll");
        fprintf(stderr, "Got a poll error.\n");
        return EXIT_FAILURE;
    } else if (err == 0) {
        // Got a timeout, currently not handled
    }

    addr_len = sizeof(addr);
    if (fds[0].revents & POLLIN) {
        sk_conn = picoquic_accept(sk_listen, (struct sockaddr *) &addr, &addr_len);
        if (sk_conn < 0) {
            fprintf(stderr, "Failed to accept QUIC connection\n");
            return EXIT_FAILURE;
        }
        memset(str_addr, 0, sizeof(str_addr));
        if (!inet_ntop(AF_INET, &addr.sin_addr, str_addr, sizeof(str_addr))) {
            fprintf(stderr, "inet_ntop failed: %s", strerror(errno));
        }
        fprintf(stderr, "Incoming connection from %s:%hu\n", str_addr, ntohs(addr.sin_port));
        /*recv = picoquic_read(sk, buf, sizeof(buf));*/
    } else {
        fprintf(stderr, "Unexpected event !\n");
        return EXIT_FAILURE;
    }

    fds[0].fd = sk_conn;
    fds[0].events = POLLIN;
    if ((err = poll(fds, 1, -1)) == -1) {
        perror("poll");
        fprintf(stderr, "Got a poll error.\n");
        return EXIT_FAILURE;
    } else if (err == 0) {
        // Got a timeout, currently not handled
    }

    if ((sk_stream = picoquic_accept_stream(sk_conn, (struct sockaddr *) &addr, &addr_len)) < 0) {
        fprintf(stderr, "Failed to accept stream !\n");
        return EXIT_FAILURE;
    }

    /* switch to sk_stream to check if there is incoming date on the stream */
    fds[0] = (struct pollfd) {
            .fd = sk_stream,
            .events = POLLIN
    };

    total_recv = 0;
    while (1) {
        switch (poll(fds, sizeof(fds) / sizeof(fds[0]), -1)) {
            case -1:
                fprintf(stderr, "Got poll error\n");
                break;
            case 0:
                fprintf(stderr, "[Bug] Got poll timout while no timeout set!\n");
                break;
            default:
                break;
        }

        r_buf_recv = picoquic_read(sk_stream, r_buf, sizeof(r_buf));
        if (r_buf_recv == 0) {
            break;
        }

        total_recv += r_buf_recv;
        if (total_recv % PER_PATH_SEND == 0) {
            fprintf(stderr, "%dB received, sending confirmation...\n", PER_PATH_SEND);
            if (picoquic_write(sk_stream, "ok", 2) != 2) {
                fprintf(stderr, "Failed to send confirmation\n");
                return EXIT_FAILURE;
            }
        }
    }

    picoquic_s_close(sk_stream);
    picoquic_s_close(sk_conn);
    picoquic_s_close(sk_listen);
    return EXIT_SUCCESS;
}