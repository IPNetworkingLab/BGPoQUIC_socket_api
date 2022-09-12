#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <arpa/inet.h>

#include "quic_sock/picoquic_sock_api.h"
#include "common_ndp.h"

int main(int argc, const char *argv[]) {
    int err = 0, sk_listen = -1, stream = -1;
    int sk_conn;
    struct sockaddr_storage addr;
    int sk_stream;
    socklen_t addr_len;
    char str_ip[INET6_ADDRSTRLEN];
    char r_buf[2048];
    ssize_t r_buf_recv;
    struct pollfd fds[1];

    addr_len = sizeof(addr);

    if (argc != 3) {
        fprintf(stderr, "Usage %s CERT_FILE_PATH KEY_FILE_PATH\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Initialize QUIC context */
    err = picoquic_init("NDP");

    /* Get QUIC main socket */
    if ((err = picoquic_socket()) >= 0) {
        sk_listen = err;
    } else {
        fprintf(stderr, "Failed to create a QUIC socket.\n");
        return EXIT_FAILURE;
    }

    /* Bind to main QUIC sk to IN6ADDR_ANY */
    struct sockaddr_in6 local_addr = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(4443),
            .sin6_addr = IN6ADDR_ANY_INIT,
    };

    if ((err = picoquic_bind(sk_listen, (struct sockaddr *) &local_addr, sizeof(local_addr))) < 0) {
        fprintf(stderr, "Failed to create to bind the main QUIC socket to IN6ADDR_ANY.\n");
        picoquic_s_close(sk_listen);
        return EXIT_FAILURE;
    }

    /* Create TLS configuration to listen for connections */
    struct tls_config *tls_cfg;
    char buf_tls_cfg[sizeof(*tls_cfg) + sizeof(struct alpn_buffer)];
    memset(buf_tls_cfg, 0, sizeof(buf_tls_cfg));
    tls_cfg = (struct tls_config *) buf_tls_cfg;

    tls_cfg->insecure = 0;
    tls_cfg->secret_log_file = NULL; // let the client ask for the keys
    tls_cfg->private_key_file = argv[2];
    tls_cfg->certificate_file = argv[1];
    tls_cfg->nb_alpn = 1;
    tls_cfg->alpn[0] = (struct alpn_buffer) {
            .alpn_size = 4,
            .alpn_name = "test"
    };
    //tls_cfg->qlog_dir = "/tmp/qlog_server";

    /* Listen for connection attempt */
    if ((err = picoquic_listen(sk_listen, tls_cfg)) < 0) {
        fprintf(stderr, "Failed to listen for connections on the QUIC socket.\n");
        picoquic_s_close(sk_listen);
        return EXIT_FAILURE;
    }

    /* Get stream-specific socket */
    /*if ((err = picoquic_open_stream(sk)) >= 0) {
	stream = err;
    } else {
	fprintf(stderr, "Failed to create a QUIC stream socket.\n");
	return EXIT_FAILURE;
    }*/


    fds[0].events = POLLIN;
    fds[0].fd = sk_listen;


    if ((err = poll(fds, 1, -1)) == -1) {
        perror("poll");
        fprintf(stderr, "Got a poll error.\n");
        return EXIT_FAILURE;
    } else if (err == 0) {
        // Got a timeout, currently not handled
    }

    if (fds[0].revents & POLLIN) {
        sk_conn = picoquic_accept(sk_listen, (struct sockaddr *) &addr, &addr_len);
        if (sk_conn < 0) {
            fprintf(stderr, "Failed to accept QUIC connection\n");
            return EXIT_FAILURE;
        }
        /*recv = picoquic_read(sk, buf, sizeof(buf));*/
    }

    fprintf(stderr, "Incoming connection from %s port %d \n",
            addr_to_str((struct sockaddr *) &addr, str_ip, sizeof(str_ip)),
            get_port((struct sockaddr *) &addr));

    /* switch to sk_conn to check if there is incoming new stream */
    fds[0] = (struct pollfd) {
            .fd = sk_conn,
            .events = POLLIN
    };

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

    while (1) {
        switch (poll(fds, sizeof(fds) /sizeof (fds[0]), -1)) {
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

        /* make sure string is ended ! */
        r_buf[r_buf_recv] = 0;
        printf("Stream Data: %s\n", r_buf);
        break;
    }


    fprintf(stderr, "closing connection\n");

    picoquic_s_close(sk_stream);
    picoquic_s_close(sk_conn);
    /* Cleanup */
    if (picoquic_s_close(sk_listen) < 0) {
        fprintf(stderr, "Failed to close the QUIC socket.\n");
    }

    /* todo close other sockets */

    return EXIT_SUCCESS;
}
