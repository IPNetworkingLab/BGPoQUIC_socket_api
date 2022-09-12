//
// Created by thomas on 6/10/22.
//

#ifndef QUIC_SOCK_TEST_QUIC_SOCK_API_COMMON_H
#define QUIC_SOCK_TEST_QUIC_SOCK_API_COMMON_H


#include <stddef.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "quic_sock/sock_api_common.h"

struct tmp_file_info {
    int tmp_file_fd;
    void *mmap_tmp_file;
    size_t file_size;
    char tmp_path_file[50];
};

#define CONNECT_TIMEOUT_MS 10000
#define STREAM_RECV_TIMEOUT_MS 2000

#define MB_RANDOM_SIZE 104857600

#define QUIC_REMOTE_SERVER_PORT "12345"
#define TEST_QUIC_SERVER_PORT "54321"
#define ALPN_STR "echo-service"
#define ALPN_STR_SIZE (sizeof(ALPN_STR) - 1)

int create_tmp_file(struct tmp_file_info *tmp_info, size_t size);

pid_t spawn_child(const char *path, const char *args[], char* const* envp);

int graceful_kill(pid_t pid);

int get_localhost_addr(struct sockaddr *addr, socklen_t *addr_len,
                       const char **err_msg, const char *port, int force_v6);

struct tls_config *get_tls_config(void);

#endif //QUIC_SOCK_TEST_QUIC_SOCK_API_COMMON_H
