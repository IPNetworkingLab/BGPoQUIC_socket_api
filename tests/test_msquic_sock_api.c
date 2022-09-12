//
// Created by thomas on 12/07/22.
//

#include "test_main.h"
#include "common/util_data_buffer.h"
#include "test_quic_sock_api_common.h"
#include <quic_sock/msquic_sock_api.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

static pid_t echo_server;
static pid_t echo_client = -1;

static char tls_key[PATH_MAX];
static char tls_cert[PATH_MAX];

static struct tmp_file_info tmp_file_info = (struct tmp_file_info) {
        .tmp_path_file = "/tmp/rnd_bufXXXXXX",
};

static inline int msquic_write_full(int fd, void *buf, size_t buf_len) {
    ssize_t bytes_written;
    size_t offset;
    char *buf_c;

    buf_c = buf;
    offset = 0;
    while (buf_len > 0) {
        bytes_written = msquic_write(fd, buf_c + offset, buf_len);
        if (bytes_written == 0) return -1;
        buf_len -= bytes_written;
        offset += bytes_written;
    }
    return 0;
}

static int setup(void) {
    /* launch quic echo server */
    int bytes;
    char echo_server_file[PATH_MAX];

    if (!test_directory) return -1;


    bytes = snprintf(tls_cert, sizeof(tls_cert), "%s/certs/%s", certs_dir, cert_name);
    if (bytes == sizeof(tls_cert)) {
        fprintf(stderr, "output truncated\n");
        return -1;
    }

    bytes = snprintf(tls_key, sizeof(tls_key), "%s/certs/%s", certs_dir, pkey_name);
    if (bytes == sizeof(tls_key)) {
        fprintf(stderr, "output truncated\n");
        return -1;
    }
    bytes = snprintf(echo_server_file, sizeof(echo_server_file), "%s/echo_server.py", test_directory);
    if (bytes == sizeof(echo_server_file)) {
        fprintf(stderr, "output truncated\n");
        return -1;
    }

    /* spawn quic server */
    const char *srv_args[] = {
            python_interpreter, echo_server_file,
            "-p", QUIC_REMOTE_SERVER_PORT, "-l", "127.0.0.1", "-l", "::1",
            "-k", tls_key, "-c", tls_cert, "-a", ALPN_STR, NULL
    };

    if ((echo_server = spawn_child(python_interpreter, srv_args, NULL)) == -1) {
        perror("spawn_child");
        return -1;
    }

    if (create_tmp_file(&tmp_file_info, MB_RANDOM_SIZE) != 0) {
        return -1;
    }


    return msquic_init("Test_APP");
}

static int teardown(void) {
    munmap(tmp_file_info.mmap_tmp_file, tmp_file_info.file_size);
    close(tmp_file_info.tmp_file_fd);
    /* call unlink now to delete when it will be closed */
    unlink(tmp_file_info.tmp_path_file);

    if (graceful_kill(echo_server) != 0) {
        return -1;
    }

    if (echo_client > 0) {
        if (graceful_kill(echo_client) != 0) {
            return -1;
        }
    }

    return 0;
}

static void test_simple_quic_client(void) {
    const char hello[] = "Hello World!";
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    char revc_hello[256];
    const char *err_msg;
    struct pollfd pfds;
    int stream_sfd;
    size_t bytes;
    int status;

    local_addr_len = sizeof(local_addr);
    status = get_localhost_addr((struct sockaddr *) &local_addr, &local_addr_len, &err_msg, QUIC_REMOTE_SERVER_PORT, 0);
    if (status != 0) {
        CU_FAIL_FATAL("get_localhost_addr failed");
    }

    const int sfd = msquic_socket();
    CU_ASSERT_FATAL(sfd >= 0);

    /* establish connection, take the first address */
    status = msquic_connect(sfd, (struct sockaddr *) &local_addr, local_addr_len, get_tls_config());
    /* for now all function are non-blocking  */
    CU_ASSERT_EQUAL_FATAL(errno, EINPROGRESS);
    CU_ASSERT_EQUAL_FATAL(status, -1);

    memset(&pfds, 0, sizeof(pfds));

    /* this is a non-blocking socket ! Should use poll to check if it is connected */

    pfds = (struct pollfd) {
            .fd = sfd,
            .events = POLLIN,
    };

    status = poll(&pfds, 1, CONNECT_TIMEOUT_MS);

    switch (status) {
        case -1: CU_FAIL("poll call failed");
            break;
        case 0:
            /* timeout */
        CU_FAIL_FATAL("Connection failed");
            break;
        default:
            /* connected ! */
            break;
    }

    /* this should be directly available */
    stream_sfd = msquic_open_stream(sfd);

    CU_ASSERT_FATAL(stream_sfd >= 0);

    bytes = msquic_write(stream_sfd, hello, sizeof(hello));

    CU_ASSERT_EQUAL(bytes, sizeof(hello));

    pfds = (struct pollfd) {
            .fd = stream_sfd,
            .events = POLLIN,
            .revents = 0,
    };

    memset(revc_hello, 0, sizeof(hello));

    status = poll(&pfds, 1, STREAM_RECV_TIMEOUT_MS);
    switch (status) {
        case -1: CU_FAIL("poll call err");
            break;
        case 0: CU_FAIL("Timeout stream receive");
            break;
        default:
            break;
    }

    /* simple server should echo back the string */
    bytes = msquic_read(stream_sfd, revc_hello, sizeof(revc_hello));
    CU_ASSERT_EQUAL(bytes, sizeof(hello));

    CU_ASSERT_EQUAL(strncmp(hello, revc_hello, sizeof(hello)), 0);


    CU_ASSERT_EQUAL(msquic_close(stream_sfd), 0);
    CU_ASSERT_EQUAL(msquic_close(sfd), 0);
}

static void test_large_transfer(void) {
    void *rnd_buf;
    int cfd;
    int stream_fd;
    int status;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    const char *err_msg;
    struct pollfd pfds[1];
    char recv_buf[16384];

#define pollfd_size(pfd) (sizeof(pfd)/sizeof((pfd)[0]))

    rnd_buf = tmp_file_info.mmap_tmp_file;

    local_addr_len = sizeof(local_addr);
    if (get_localhost_addr((struct sockaddr *) &local_addr, &local_addr_len, &err_msg, QUIC_REMOTE_SERVER_PORT, 0) != 0) {
        CU_FAIL_FATAL("get_localhost_addr failed");
    }

    cfd = msquic_socket();
    CU_ASSERT_FATAL(cfd >= 0);

    status = msquic_connect(cfd, (struct sockaddr *) &local_addr, local_addr_len, get_tls_config());
    CU_ASSERT_EQUAL_FATAL(errno, EINPROGRESS);
    CU_ASSERT_EQUAL_FATAL(status, -1);

    pfds[0] = (struct pollfd) {
            .fd = cfd,
            .events = POLLIN,
    };

    status = poll(pfds, pollfd_size(pfds), CONNECT_TIMEOUT_MS);
    switch (status) {
        case -1: CU_FAIL_FATAL("POLL failed");
            break;
        case 0: CU_FAIL_FATAL("Connection timeout !");
            break;
        default:
            break;
    }
    /* socket is connected ! */
    stream_fd = msquic_open_stream(cfd);
    CU_ASSERT_FATAL(stream_fd >= 0);

    size_t remaining_send = MB_RANDOM_SIZE;
    size_t offset_send = 0;
    size_t offset_read = 0;
    size_t bytes_sent;
    size_t bytes_recv;
    int nb_timeout = 0;
#define TIMEOUT_THRESHOLD 4

    while (remaining_send > 0 && nb_timeout < TIMEOUT_THRESHOLD) {
        pfds[0] = (struct pollfd) {
                .fd = stream_fd,
                .events = POLLIN,
        };

        /* first write data */
        bytes_sent = msquic_write(stream_fd, rnd_buf + offset_send, 8192);
        CU_ASSERT_FATAL(bytes_sent >= 0);
        remaining_send -= bytes_sent;

        /* poll and recv data */

        status = poll(pfds, pollfd_size(pfds), STREAM_RECV_TIMEOUT_MS);
        switch (status) {
            case -1: CU_FAIL_FATAL("poll call fails");
                break;
            case 0:
                nb_timeout += 1;
                break;
            default:
                nb_timeout = 0;
                bytes_recv = msquic_read(stream_fd, recv_buf, sizeof(recv_buf));
                CU_ASSERT_FATAL(bytes_recv >= 0);
                CU_ASSERT_EQUAL(memcmp(rnd_buf + offset_read, recv_buf, bytes_recv), 0);
                offset_read += bytes_recv;
        }

        offset_send += bytes_sent;

    }

    if (nb_timeout >= TIMEOUT_THRESHOLD) {
        CU_FAIL_FATAL("IO loop terminated due to timeout ! It is possible that not all data is received");
    }

    msquic_close(stream_fd);
    msquic_close(cfd);
}


static void test_server_large_transfer(void) {
    char echo_client_file[PATH_MAX];
    char output_file[PATH_MAX];
    size_t bytes;
    int ret;
    int quic_srv_fd;
    int quic_conn_fd;
    int quic_stream_fd;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    socklen_t local_addr_len;
    socklen_t remote_addr_len;
    const char *err_msg;
    struct tls_config *tls_config;
    char buf_tls_config[sizeof(*tls_config) + sizeof(struct alpn_buffer)];
    static const unsigned char alpn[] = ALPN_STR;
    struct pollfd pfds[1];

    memset(buf_tls_config, 0, sizeof(buf_tls_config));
    tls_config = (struct tls_config *) buf_tls_config;

    bytes = snprintf(echo_client_file, sizeof(echo_client_file),
                     "%s/simple_client.py", test_directory);
    if (bytes == sizeof(echo_client_file)) {
        CU_FAIL_FATAL("output truncated");
    }

    local_addr_len = sizeof(local_addr);
    if (get_localhost_addr((struct sockaddr *) &local_addr, &local_addr_len, &err_msg, TEST_QUIC_SERVER_PORT, 1) != 0) {
        CU_FAIL_FATAL("Unable to get address for localhost");
    }

    /* first launch quic server */
    quic_srv_fd = msquic_socket();
    CU_ASSERT_FATAL(quic_srv_fd >= 0);

    ret = msquic_bind(quic_srv_fd, (struct sockaddr *) &local_addr, local_addr_len);
    CU_ASSERT_EQUAL_FATAL(ret, 0);

    tls_config->certificate_file = tls_cert;
    tls_config->private_key_file = tls_key;
    tls_config->insecure = 1;
    tls_config->secret_log_file = NULL;
    tls_config->nb_alpn = 1;
    tls_config->alpn[0] = (struct alpn_buffer) {
            .alpn_name = alpn,
            .alpn_size = ALPN_STR_SIZE,
    };

    ret = msquic_listen(quic_srv_fd, tls_config);
    CU_ASSERT_EQUAL_FATAL(ret, 0);

    /* outfile */

    bytes = snprintf(output_file, sizeof(output_file), "%s.out", tmp_file_info.tmp_path_file);
    if (bytes >= sizeof(output_file)) {
        CU_FAIL_FATAL("Output truncated");
    }

    const char *client_args[] = {
            python_interpreter, echo_client_file,
            "-p", TEST_QUIC_SERVER_PORT,
            "--host", "::1", "-a", ALPN_STR,
            "-i", tmp_file_info.tmp_path_file,
            "-o", output_file, NULL
    };

    /* then spawn quic client */
    if (((echo_client = spawn_child(python_interpreter, client_args, NULL))) == -1) {
        perror("spwan_child");
        CU_FAIL_FATAL("Cannot launch python client")
    }

    remote_addr_len = sizeof(remote_addr);

    /* poll quic server for incoming connection */
    pfds[0] = (typeof(*pfds)) {
            .events = POLL_IN,
            .fd = quic_srv_fd,
    };
    ret = poll(pfds, pollfd_size(pfds), TIMEOUT_THRESHOLD * 1000);
    switch (ret) {
        case -1: CU_FAIL_FATAL("POLL error");
        case 0: CU_FAIL_FATAL("Poll timeout");
        default:
            break;
    }

    quic_conn_fd = msquic_accept(quic_srv_fd, (struct sockaddr *) &remote_addr, &remote_addr_len);
    CU_ASSERT_FATAL(quic_conn_fd >= 0);

    /* accept stream */
    pfds[0] = (typeof(*pfds)) {
            .events = POLL_IN,
            .fd = quic_conn_fd,
    };
    ret = poll(pfds, pollfd_size(pfds), TIMEOUT_THRESHOLD * 1000);
    switch (ret) {
        case -1: CU_FAIL_FATAL("Poll error");
        case 0: CU_FAIL_FATAL("Poll timeout");
        default:
            break;
    }

    quic_stream_fd = msquic_accept_stream(quic_conn_fd);
    CU_ASSERT_FATAL(quic_stream_fd >= 0);

    /* now we read and write back data to the stream */
    char buf[8192];
    ssize_t bytes_read;
    int finished = 0;

    pfds[0] = (typeof(*pfds)) {
            .events = POLL_IN,
            .fd = quic_stream_fd,
    };
    size_t pfds_size = pollfd_size(pfds);

    while (!finished) {
        ret = poll(pfds, pfds_size, TIMEOUT_THRESHOLD * 1000);
        switch (ret) {
            case -1: CU_FAIL_FATAL("Poll error");
            case 0: CU_FAIL_FATAL("Poll timeout");
            default:
                break;
        }

        bytes_read = msquic_read(quic_stream_fd, buf, sizeof(buf));
        CU_ASSERT_FATAL(bytes_read >= 0);
        if (bytes_read == 0) {
            finished = 1;
        } else { /* todo handle read write bytes not the same */
            ret = msquic_write_full(quic_stream_fd, buf, bytes_read);
            CU_ASSERT_EQUAL_FATAL(ret, 0);
        }
    }

    msquic_close(quic_stream_fd);
    msquic_close(quic_conn_fd);
    msquic_close(quic_srv_fd);

    /* client should automatically end itself */
    int ret_child;
    ret = waitpid(echo_client, &ret_child, 0);

    if (ret != echo_client) {
        CU_FAIL("waitpid error");
    } else {
        echo_client = -1;
    }

}

static CU_ErrorCode test_sock_api_init(CU_pSuite suite, const char **err_msg) {
    if ((NULL == CU_add_test(suite, "simple QUIC client", test_simple_quic_client)) ||
        (NULL == CU_add_test(suite, "client large transfer", test_large_transfer)) ||
        (NULL == CU_add_test(suite, "server large transfer", test_server_large_transfer))) {
        *err_msg = CU_get_error_msg();
        return CU_get_error();
    }

    return CUE_SUCCESS;
}


const struct suite test_msquic_sock_api_suite = {
        .suite_name = "MSQUIC Socket API",
        .setup = setup,
        .teardown = teardown,
        .fn_add = test_sock_api_init
};
