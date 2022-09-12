#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "quic_sock/picoquic_sock_api.h"

int main(int argc, const char *argv[]) {
    int err = 0, sk_conn = -1;
    int sk_stream;
    const char *key_log_file;

    const char hello[] = "Hello My QUIC neighbor!";
    char dumb_buf[5];

    if (argc != 5) {
        fprintf(stderr, "Usage %s CERT_FILE_PATH KEY_FILE_PATH LOCAL_ADDR REMOTE_ADDR\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Initialize QUIC context */
    err = picoquic_init("NDP");

    if (err != 0) {
        fprintf(stderr, "Failed to initialize picoquic socket API\n");
        return EXIT_FAILURE;
    }

    /* Get QUIC main socket */
    if ((err = picoquic_socket()) >= 0) {
        sk_conn = err;
    } else {
        fprintf(stderr, "Failed to create a QUIC socket.\n");
        return EXIT_FAILURE;
    }

    /* Bind to main QUIC sk to IN6ADDR_ANY */
    struct sockaddr_in6 local_addr = {
            .sin6_family = AF_INET6,
            //.sin6_port = htons(4443),
    };
    inet_pton(AF_INET6, argv[3], (struct in6_addr *) &local_addr.sin6_addr);

    if ((err = picoquic_bind(sk_conn, (struct sockaddr *) &local_addr, sizeof(local_addr))) < 0) {
        fprintf(stderr, "Failed to create to bind the main QUIC socket.\n");
        picoquic_s_close(sk_conn);
        return EXIT_FAILURE;
    }

    /* Create TLS configuration */
    struct tls_config *tls_cfg;
    char buf_tls_cfg[sizeof(*tls_cfg) + sizeof(struct alpn_buffer)];
    memset(buf_tls_cfg, 0, sizeof(buf_tls_cfg));
    tls_cfg = (struct tls_config *) buf_tls_cfg;

    tls_cfg->insecure = 0;
    if ((key_log_file = getenv("SSLKEYLOGFILE")) != NULL) {
        tls_cfg->secret_log_file = key_log_file;
    } else {
        tls_cfg->secret_log_file = NULL;
    }
    tls_cfg->private_key_file = argv[2];
    tls_cfg->certificate_file = argv[1];
    tls_cfg->nb_alpn = 1;
    tls_cfg->alpn[0] = (struct alpn_buffer) {
            .alpn_size = 4,
            .alpn_name = "test"
    };
    //tls_cfg->qlog_dir = "/tmp/qlog_client";

    /* Attempts connection to peer */
    struct sockaddr_in6 remote_addr = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(4443),
    };
    inet_pton(AF_INET6, argv[4], (struct in6_addr *) &remote_addr.sin6_addr);

    if ((err = picoquic_connect(sk_conn, (struct sockaddr *) &remote_addr, sizeof(remote_addr), tls_cfg)) < 0 &&
        errno != EINPROGRESS) {
        fprintf(stderr, "Failed to connect with the main QUIC socket.\n");
        picoquic_s_close(sk_conn);
        return EXIT_FAILURE;
    }

    struct pollfd fds[1];
    fds[0].events = POLLOUT;
    fds[0].fd = sk_conn;

    while (1) {
        if ((err = poll(fds, 1, -1)) == -1) {
            perror("poll");
            fprintf(stderr, "Got a poll error.\n");
            continue;
        } else if (err == 0) {
            // Got a timeout, currently not handled
        }
        break;
    }

    fprintf(stderr, "Connection with server %s succeeded!\n", argv[3]);

    if ((sk_stream = picoquic_open_stream(sk_conn)) < 0) {
        fprintf(stderr, "Failed to create stream\n");
    }

    assert(picoquic_write(sk_stream, hello, sizeof(hello)) == sizeof(hello));

    /* wait that server receives the data & closes the connection */
    fds->fd = sk_stream;
    fds->events = POLLIN;
    switch (poll(fds, 1, -1)) {
        case 0:
            fprintf(stderr, "[BUG] Got Timeout while no timeout is set");
            return EXIT_FAILURE;
        case -1:
            perror("Poll error");
            return EXIT_FAILURE;
        default:
            break;
    }
    assert(picoquic_read(sk_stream, dumb_buf, sizeof(dumb_buf)) == 0);

    /* Cleanup */
    if (picoquic_s_close(sk_stream) < 0) {
        fprintf(stderr, "Failed to close the QUIC stream socket.\n");
    }

    /* Cleanup */
    if (picoquic_s_close(sk_conn) < 0) {
        fprintf(stderr, "Failed to close the QUIC connection socket.\n");
    }

    return EXIT_SUCCESS;
}
