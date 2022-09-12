//
// Created by thomas on 12/07/22.
//

#include "test_picoquic_sock_api.h"
#include "test_main.h"

#include "test_quic_sock_api_common.h"
#include <quic_sock/picoquic_sock_api.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>

static pid_t echo_server;
static pid_t echo_client = -1;

static char tls_key[PATH_MAX];
static char tls_cert[PATH_MAX];

static struct tmp_file_info tmp_file_info = (struct tmp_file_info) {
        .tmp_path_file = "/tmp/rnd_bufXXXXXX",
};


static void print_addr(struct sockaddr *s_addr) {
    char buf[INET6_ADDRSTRLEN];
    const char *str_addr;
    uint16_t port;

    switch (s_addr->sa_family) {
        case AF_INET:
            str_addr = inet_ntop(s_addr->sa_family, &((struct sockaddr_in *) s_addr)->sin_addr,
                                 buf, sizeof(buf));
            port = htons(((struct sockaddr_in *) s_addr)->sin_port);
            break;
        case AF_INET6:
            str_addr = inet_ntop(s_addr->sa_family, &((struct sockaddr_in6 *) s_addr)->sin6_addr,
                                 buf, sizeof(buf));
            port = htons(((struct sockaddr_in6 *) s_addr)->sin6_port);
            break;
    }

    if (!str_addr) return;
    printf("%s:%d\n", buf, port);
}

static void print_local_addr(int sfd) {
    struct sockaddr_storage s_addr;
    unsigned int len;

    len = sizeof(s_addr);

    if (picoquic_getsockname(sfd, (struct sockaddr *)&s_addr, &len, NULL) != 0) {
        fprintf(stderr, "getsockname failed\n");
        return;
    }

    print_addr((struct sockaddr *) &s_addr);
}

static inline int picoquic_read_poll_full(int fd, void *buf, size_t buf_len) {
    size_t bytes_read;
    ssize_t curr_bytes_read;
    struct pollfd pfd[1];

    int err;

    pfd[0] = (struct pollfd) {
        .fd = fd,
        .events = POLL_IN,
    };

    bytes_read = 0;
    while (bytes_read < buf_len) {
        err = poll(pfd, sizeof (pfd)/sizeof(pfd[0]), STREAM_RECV_TIMEOUT_MS);

        switch (err) {
            case -1:
                CU_FAIL_FATAL("Poll failed");
                return -1;
            case 0:
                CU_FAIL_FATAL("Poll timeout");
                return -1;
            default:
                break;
        }

        curr_bytes_read = picoquic_read(fd, buf + bytes_read, buf_len - bytes_read);
        if (curr_bytes_read <= 0) {
            return -1;
        }

        bytes_read += curr_bytes_read;
    }

    return 0;
}


static inline int picoquic_write_full(int fd, void *buf, size_t buf_len) {
    ssize_t bytes_written;
    size_t offset;
    char *buf_c;

    buf_c = buf;
    offset = 0;
    while (buf_len > 0) {
        bytes_written = picoquic_write(fd, buf_c + offset, buf_len);
        if (bytes_written == 0) return -1;
        buf_len -= bytes_written;
        offset += bytes_written;
    }
    return 0;
}


static int setup(void) {
    /* launch quic echo server */
    int bytes;
    int ret_val;
    char echo_server_file[PATH_MAX];
    char root_ca[PATH_MAX];

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


    ret_val = picoquic_init("Test_APP");

    // set root CA
    memset(root_ca,0,sizeof(root_ca));
    bytes = snprintf(root_ca, sizeof(tls_key), "%s/certs/%s", certs_dir, root_ca_name);
    if (bytes == sizeof(root_ca)) {
        fprintf(stderr, "output truncated\n");
        return -1;
    }
    picoquic_set_default_root_ca_path(root_ca);

    return ret_val;
}

static int teardown(void) {
    munmap(tmp_file_info.mmap_tmp_file, tmp_file_info.file_size);
    close(tmp_file_info.tmp_file_fd);
    /* call unlink now to delete when it will be closed */
    unlink(tmp_file_info.tmp_path_file);

    picoquic_finished();

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
    struct tls_config *master_tls_config;
    const char hello[] = "Hello World!";
    struct sockaddr_storage local_addr;
    char pem_server_cert[PATH_MAX];
    size_t pem_server_cert_len;
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

    const int sfd = picoquic_socket();
    CU_ASSERT_FATAL(sfd >= 0);

    /* establish connection, take the first address */
    master_tls_config = get_tls_config();
    master_tls_config->sni = server_sni;
    status = picoquic_connect(sfd, (struct sockaddr *) &local_addr, local_addr_len, master_tls_config);
    /* for now, all functions are non-blocking  */
    CU_ASSERT_EQUAL_FATAL(errno, EINPROGRESS);
    CU_ASSERT_EQUAL_FATAL(status, -1);

    memset(&pfds, 0, sizeof(pfds));

    /* this is a non-blocking socket ! Should use poll to check if it is connected */

    pfds = (struct pollfd) {
            .fd = sfd,
            .events = POLLOUT,
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

    /* connection opened, we should be able to retrieve the server certificate */
    if ((pem_server_cert_len = picoquic_get_remote_certificate(sfd, pem_server_cert, sizeof(pem_server_cert))) <= 0) {
        CU_FAIL("Unable to retrieve server certificate");
    } else {
        FILE *pem_cert = fopen("/tmp/test.pem", "w");
        size_t tot_written = 0;
        size_t curr_write;
        if (!pem_cert) {
            CU_FAIL_FATAL("unable to open file in write mode");
        }
        while (tot_written < pem_server_cert_len) {
            curr_write = fwrite(pem_server_cert + tot_written, 1, pem_server_cert_len-tot_written, pem_cert);
            if (ferror(pem_cert)) {
                CU_FAIL_FATAL("fwrite failed");
            }
            tot_written += curr_write;
        }
        fclose(pem_cert);
    }

    /* this should be directly available */
    stream_sfd = picoquic_open_stream(sfd);

    CU_ASSERT_FATAL(stream_sfd >= 0);

    bytes = picoquic_write(stream_sfd, hello, sizeof(hello));

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
    bytes = picoquic_read(stream_sfd, revc_hello, sizeof(revc_hello));
    CU_ASSERT_EQUAL(bytes, sizeof(hello));

    CU_ASSERT_EQUAL(strncmp(hello, revc_hello, sizeof(hello)), 0);


    CU_ASSERT_EQUAL(picoquic_s_close(stream_sfd), 0);
    CU_ASSERT_EQUAL(picoquic_s_close(sfd), 0);
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

    cfd = picoquic_socket();
    CU_ASSERT_FATAL(cfd >= 0);

    status = picoquic_connect(cfd, (struct sockaddr *) &local_addr, local_addr_len, get_tls_config());
    CU_ASSERT_EQUAL_FATAL(errno, EINPROGRESS);
    CU_ASSERT_EQUAL_FATAL(status, -1);

    pfds[0] = (struct pollfd) {
            .fd = cfd,
            .events = POLLOUT,
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
    stream_fd = picoquic_open_stream(cfd);
    CU_ASSERT_FATAL(stream_fd >= 0);

    size_t remaining_send = MB_RANDOM_SIZE;
    size_t offset_send = 0;
    size_t offset_read = 0;
    size_t bytes_sent;
#define TIMEOUT_THRESHOLD 4

    while (remaining_send > 0) {
        /* first write data */
        bytes_sent = picoquic_write(stream_fd, rnd_buf + offset_send, sizeof(recv_buf));
        CU_ASSERT_FATAL(bytes_sent >= 0);
        remaining_send -= bytes_sent;

        /* then full read */
        if (picoquic_read_poll_full(stream_fd, recv_buf, bytes_sent) != 0) {
            CU_FAIL_FATAL("read full err");
        }
        CU_ASSERT_EQUAL(memcmp(rnd_buf + offset_read, recv_buf, bytes_sent), 0);
        offset_read += bytes_sent;
        offset_send += bytes_sent;
    }

    CU_ASSERT_EQUAL(offset_read, offset_send);
    picoquic_s_close(stream_fd);
    picoquic_s_close(cfd);
}


static void test_server_large_transfer(void) {
    char echo_client_file[PATH_MAX];
    char client_cert_path[PATH_MAX];
    char client_pkey_path[PATH_MAX];
    char output_file[PATH_MAX];
    const char *cert_opt;
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
    char pem_server_cert[2048];
    size_t pem_server_cert_len;

    memset(buf_tls_config, 0, sizeof(buf_tls_config));
    tls_config = (struct tls_config *) buf_tls_config;

    bytes = snprintf(echo_client_file, sizeof(echo_client_file),
                     "%s/go_client/go_simple_client", test_directory);
    if (bytes == sizeof(echo_client_file)) {
        CU_FAIL_FATAL("output truncated");
    }

    local_addr_len = sizeof(local_addr);
    if (get_localhost_addr((struct sockaddr *) &local_addr, &local_addr_len, &err_msg, TEST_QUIC_SERVER_PORT, 1) != 0) {
        CU_FAIL_FATAL("Unable to get address for localhost");
    }

    /* first launch quic server */
    quic_srv_fd = picoquic_socket();
    CU_ASSERT_FATAL(quic_srv_fd >= 0);

    ret = picoquic_bind(quic_srv_fd, (struct sockaddr *) &local_addr, local_addr_len);
    CU_ASSERT_EQUAL_FATAL(ret, 0);

    tls_config->certificate_file = tls_cert;
    tls_config->private_key_file = tls_key;
    tls_config->insecure = 1;
    tls_config->require_client_authentication = 1;
    tls_config->secret_log_file = NULL;

    tls_config->nb_alpn = 1;
    tls_config->alpn[0] = (struct alpn_buffer) {
            .alpn_name = alpn,
            .alpn_size = ALPN_STR_SIZE,
    };

    ret = picoquic_listen(quic_srv_fd, tls_config);
    CU_ASSERT_EQUAL_FATAL(ret, 0);

    /* outfile */

    bytes = snprintf(output_file, sizeof(output_file), "%s.out", tmp_file_info.tmp_path_file);
    if (bytes >= sizeof(output_file)) {
        CU_FAIL_FATAL("Output truncated");
    }

    /* little hack: terminate array early if client cert not provided */
    cert_opt = client_cert_name ? "-c": NULL;
    if (cert_opt) {
        bytes = snprintf(client_cert_path, sizeof(client_cert_path), "%s/certs/%s", certs_dir, client_cert_name);
        if (bytes >= sizeof(client_cert_path)) {
            CU_FAIL_FATAL("Output truncated");
        }
        bytes = snprintf(client_pkey_path, sizeof(client_pkey_path), "%s/certs/%s", certs_dir, client_pkey_name);
        if (bytes >= sizeof(client_pkey_path)) {
            CU_FAIL_FATAL("Output truncated");
        }
    }
    const char *client_args[] = {
            /*python_interpreter,*/ echo_client_file,
            "-p", TEST_QUIC_SERVER_PORT,
            "--host", "::1", "-a", ALPN_STR,
            "-i", tmp_file_info.tmp_path_file,
            "-o", output_file, cert_opt, client_cert_path,
            "-k", client_pkey_path, NULL
    };

    /* then spawn quic client */
    if (((echo_client = spawn_child(/*python_interpreter*/ echo_client_file, client_args, NULL))) == -1) {
        perror("spwan_child");
        CU_FAIL_FATAL("Cannot launch python client")
    }

    remote_addr_len = sizeof(remote_addr);

    /* poll quic server for incoming connection */
    pfds[0] = (typeof(*pfds)) {
            .events = POLLIN,
            .fd = quic_srv_fd,
    };
    ret = poll(pfds, pollfd_size(pfds), TIMEOUT_THRESHOLD * 1000);
    switch (ret) {
        case -1: CU_FAIL_FATAL("POLL error");
        case 0: CU_FAIL_FATAL("Poll timeout");
        default:
            break;
    }

    quic_conn_fd = picoquic_accept(quic_srv_fd, (struct sockaddr *) &remote_addr, &remote_addr_len);
    CU_ASSERT_FATAL(quic_conn_fd >= 0);

    /* client certificate should be available now ! */
    if ((pem_server_cert_len = picoquic_get_remote_certificate(quic_conn_fd, pem_server_cert, sizeof(pem_server_cert))) <= 0) {
        CU_FAIL("Unable to retrieve server certificate");
    } else {
        FILE *pem_cert = fopen("/tmp/test_client.pem", "w");
        size_t tot_written = 0;
        size_t curr_write;
        if (!pem_cert) {
            CU_FAIL_FATAL("unable to open file in write mode");
        }
        while (tot_written < pem_server_cert_len) {
            curr_write = fwrite(pem_server_cert + tot_written, 1, pem_server_cert_len-tot_written, pem_cert);
            if (ferror(pem_cert)) {
                CU_FAIL_FATAL("fwrite failed");
            }
            tot_written += curr_write;
        }
        fclose(pem_cert);
    }

    /* accept stream */
    pfds[0] = (typeof(*pfds)) {
            .events = POLLIN,
            .fd = quic_conn_fd,
    };
    ret = poll(pfds, pollfd_size(pfds), TIMEOUT_THRESHOLD * 1000); // 40s timeout
    switch (ret) {
        case -1: CU_FAIL_FATAL("Poll error");
        case 0: CU_FAIL_FATAL("Poll timeout");
        default:
            break;
    }

    quic_stream_fd = picoquic_accept_stream(quic_conn_fd, (struct sockaddr *) &remote_addr, &remote_addr_len);
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

    unsigned long tot_read = 0;

    while (!finished) {
        ret = poll(pfds, pfds_size, (10* TIMEOUT_THRESHOLD) * 1000);
        switch (ret) {
            case -1: CU_FAIL_FATAL("Poll error");
            case 0: CU_FAIL_FATAL("Poll timeout");
            default:
                break;
        }

        bytes_read = picoquic_read(quic_stream_fd, buf, sizeof(buf));
        CU_ASSERT_FATAL(bytes_read >= 0);
        if (bytes_read == 0) {
            finished = 1;
        } else { /* todo handle read write bytes not the same */
            tot_read += bytes_read;
            ret = picoquic_write_full(quic_stream_fd, buf, bytes_read);
            CU_ASSERT_EQUAL_FATAL(ret, 0);
        }
    }

    picoquic_s_close(quic_stream_fd);
    picoquic_s_close(quic_conn_fd);
    picoquic_s_close(quic_srv_fd);

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


const struct suite test_picoquic_sock_api_suite = {
        .suite_name = "Picoquic Socket API",
        .setup = setup,
        .teardown = teardown,
        .fn_add = test_sock_api_init
};

