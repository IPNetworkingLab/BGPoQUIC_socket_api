//
// Created by thomas on 1/03/23.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <assert.h>
#include "quic_sock/picoquic_sock_api.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void fill_rnd_buffer(char *buf, size_t buf_len) {
    static const char rnd_buf[] = "0123456789abcdef";
    int offset;
    int to_cpy_len;

    offset = 0;
    while (buf_len > 0) {
        to_cpy_len = MIN(sizeof(rnd_buf) - 1, buf_len);
        memcpy(buf + offset, rnd_buf, to_cpy_len);
        buf_len -= to_cpy_len;
        offset += to_cpy_len;
    }
}


static void wait_confirmation(int sk_stream) {
    struct pollfd fds[1];
    char mini_buf[5];
    ssize_t nb_recv;
    int err;

    fds[0].events = POLLIN;
    fds[0].fd = sk_stream;
    while (1) {
        if ((err = poll(fds, 1, -1)) == -1) {
            fprintf(stderr, "poll failed: %s\n", strerror(errno));
            abort();
        } else if (err != 0) {
            break;
        }
    }

    nb_recv = picoquic_read(sk_stream, mini_buf, sizeof(mini_buf));
    if (nb_recv != 2 || strncmp(mini_buf, "ok", 2) != 0) {
        fprintf(stderr, "Invalid server state\n");
        abort();
    }
}

int main(int argc, const char *argv[]) {
    char buf_space[sizeof(struct tls_config) + sizeof(struct alpn_buffer)];
    struct tls_config *tls_config;
    struct sockaddr_in alt_local_addr;
    struct sockaddr_in addrs[2];
    int auto_conn_migration;
    struct pollfd fds[1];
    size_t written;
    char *end_ptr;
    int sk_stream;
    int sk_conn;
    long port;
    int err;
    int i;

    memset(buf_space, 0, sizeof(buf_space));
    tls_config = (struct tls_config *) buf_space;

    if (argc != 7 && argc != 8) {
        fprintf(stderr, "%s FIRST_SRV_IPV4_ADDR SECOND_SRV_IPV4_ADDR PORT "
                        "CLIENT_CERT KEY_CERT ALT_LOCAL_ADDR [AUTO_CONN_MIG]\n", argv[0]);
        return EXIT_FAILURE;
    }

    auto_conn_migration = argc == 8 ? 1 : 0;

    /* Initialize QUIC context */
    if (picoquic_init("conn migration") != 0) {
        fprintf(stderr, "picoquic_init failed\n");
        return EXIT_FAILURE;
    }

    /* get port */
    port = strtol(argv[3], &end_ptr, 10);
    if (*end_ptr != 0) {
        fprintf(stderr, "Unable to convert port to integer\n");
        return EXIT_FAILURE;
    } else if (port > UINT16_MAX || port <= 0) {
        fprintf(stderr, "Invalid port %ld (0 < port < 65536)!", port);
        return EXIT_FAILURE;
    }

    for (i = 0; i < 2; i++) {
        addrs[i] = (struct sockaddr_in) {
                .sin_family = AF_INET,
                .sin_port = htons((uint16_t) port),
        };
        if (!inet_pton(AF_INET, argv[i + 1], &addrs[i].sin_addr)) {
            perror("inet_pton");
            return EXIT_FAILURE;
        }
    }
    alt_local_addr = (struct sockaddr_in) {
            .sin_family = AF_INET,
            .sin_port = 0, /* reuse the one of the current path */
    };

    if (!inet_pton(AF_INET, argv[6], &alt_local_addr.sin_addr)) {
        perror("inet_pton");
        return EXIT_FAILURE;
    }

    tls_config->insecure = 0;
    tls_config->certificate_file = argv[4];
    tls_config->private_key_file = argv[5];
    tls_config->nb_alpn = 1;
    tls_config->alpn[0] = (struct alpn_buffer) {
            .alpn_name = "migration",
            .alpn_size = 9,
    };

    if ((sk_conn = picoquic_socket()) < 0) {
        fprintf(stderr, "Picoquic_socket failed;\n");
        return EXIT_FAILURE;
    }

    /* 1. Connect to first addr */
    if (picoquic_connect(sk_conn, (struct sockaddr *) &addrs[0],
                         sizeof(addrs[0]), tls_config) < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "picoquic connect failed\n");
        picoquic_s_close(sk_conn);
        return EXIT_FAILURE;
    }

    if (auto_conn_migration) {
        fprintf(stderr, "Setting auto fallback.\n");
        if (picoquic_set_fallback_address(sk_conn, (struct sockaddr *) &alt_local_addr,
                                      (struct sockaddr *) &addrs[1]) != 0) {
            fprintf(stderr, "Failed to set fallback address");
        }
    }

    fds[0].events = POLLOUT;
    fds[0].fd = sk_conn;
    while (1) {
        if ((err = poll(fds, 1, -1)) == -1) {
            fprintf(stderr, "poll failed: %s\n", strerror(errno));
            return EXIT_FAILURE;
        } else if (err != 0) {
            break;
        }
    }

    /* 2. create new stream */
    if ((sk_stream = picoquic_open_stream(sk_conn)) < 0) {
        fprintf(stderr, "Failed to create stream\n");
        return EXIT_FAILURE;
    }

    /* send 10MiB on first path */
#define BUF_SIZ 10485760
    char *large_buf = malloc(BUF_SIZ);
    if (!large_buf) {
        perror("malloc");
        return EXIT_FAILURE;
    }
    fill_rnd_buffer(large_buf, BUF_SIZ);

    /* 3. Send on the first path */
    written = picoquic_write(sk_stream, large_buf, BUF_SIZ);
    assert(written == BUF_SIZ);

    /* 4. Wait confirmation from server
     * then migrate to the second path if
     * auto_conn_migration is not requested */
    wait_confirmation(sk_stream);

    if (!auto_conn_migration) {
        if (picoquic_prepare_connection_migration(sk_conn, (struct sockaddr *) &alt_local_addr,
                                                  (struct sockaddr *) &addrs[1]) != 0) {
            fprintf(stderr, "Connection migration failed\n");
            return EXIT_FAILURE;
        } else {
            fprintf(stderr, "Migrating to the other address\n");
        }
    }

    /* 5. Resend 10MiB on the second path */
    written = picoquic_write(sk_stream, large_buf, BUF_SIZ);
    assert(written == BUF_SIZ);

    /* 6. wait final confirmation then close */
    wait_confirmation(sk_stream);

    free(large_buf);
    picoquic_s_close(sk_stream);
    picoquic_s_close(sk_conn);
    return EXIT_SUCCESS;
}
