//
// Created by thomas on 6/10/22.
//

#include "test_quic_sock_api_common.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <CUnit/CUnit.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include "quic_sock/sock_api_common.h"

int create_tmp_file(struct tmp_file_info *tmp_info, size_t size) {
    int rnd_fd;
    int tmp_fd;
    void *tmp_file_addr;
    size_t offset;
    ssize_t bytes_read;


    tmp_fd = mkstemp(tmp_info->tmp_path_file);

    if (tmp_fd == -1) {
        perror("mkstemp");
        return -1;
    }

    if (ftruncate(tmp_fd, size) == -1) {
        perror("ftruncate");
        return -1;
    }

    lseek(tmp_fd, 0, SEEK_SET);


    /* open /dev/urandom */
    rnd_fd = open("/dev/urandom", O_RDONLY);
    if (rnd_fd < 0) {
        CU_FAIL_FATAL("Unable to open /dev/urandom");
    }

    tmp_file_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, tmp_fd, 0);
    if (tmp_file_addr == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    offset = 0;
    while (size > 0) {
        bytes_read = read(rnd_fd, tmp_file_addr + offset, size);
        if (bytes_read <= 0) {
            perror("read");
            return -1;
        }
        size -= bytes_read;
        offset += bytes_read;
    }

    if (msync(tmp_file_addr, offset, MS_SYNC) != 0) {
        perror("msync");
        return -1;
    }

    tmp_info->tmp_file_fd = tmp_fd;
    tmp_info->mmap_tmp_file = tmp_file_addr;
    tmp_info->file_size = size;
    close(rnd_fd);
    return 0;
}


pid_t spawn_child(const char *path, const char *args[], char* const* envp) {
    pid_t child_pid;
    int ret;
    int r_val;
    child_pid = fork();

    switch (child_pid) {
        case -1:
            perror("fork");
            break;
        case 0:
            /* child */
            ret = execve(path, (char * const *) args, envp);
            if (ret == -1) {
                perror("execle");
                return -1;
            }
            break;
        default:
            /* parent */
            break;
    }


    /* sleep to wait python starts */
    sleep(2);
    ret = waitpid(child_pid, &r_val, WNOHANG);

    if (ret == -1) {
        perror("waitpid");
        return -1;
    }

    if (ret != 0) {
        /* child has exited ! */
        fprintf(stderr, "Child exited !\n");
        return -1;
    }

    return child_pid;
}


int graceful_kill(pid_t pid) {
    int w;
    int wstatus;
    int cnt = 0;
#define poll_ms 200
#define timeout_ms 10000

    /*
     * parent
     */

    if (kill(pid, SIGINT) == -1) {
        perror("kill");
        return -1;
    }

    do {
        /*
         * Do not want to rely on signals as that could modify
         * the behavior of the invoking application.
         */
        w = waitpid(pid, &wstatus, WNOHANG);
        if (w == -1) {
            perror("waitpid");
            return -1;
        }

        usleep(poll_ms * 1000);

        if (w) {
            if (WIFEXITED(wstatus)) {
                goto kill_ok;
            }
        }
    } while (cnt++ < (timeout_ms / poll_ms));

    /* sigkill as we failed to gracefully kill the process within timeout_ms */
    if (kill(pid, SIGKILL) != 0) {
        perror("kill");
        return -1;
    }

    if (waitpid(pid, &wstatus, 0)) {
        perror("wait pid");
        return -1;
    }

    kill_ok:
    return 0;
}

int get_localhost_addr(struct sockaddr *addr, socklen_t *addr_len,
                              const char **err_msg, const char *port, int force_v6) {
    struct addrinfo *result;
    struct addrinfo *curr;
    struct addrinfo hints;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM; // udp
    hints.ai_flags = AI_ADDRCONFIG;

    status = getaddrinfo("localhost", port, &hints, &result);
    if (status != 0) {
        if (err_msg) *err_msg = gai_strerror(status);
        return -1;
    }

    curr = result;
    while (curr && force_v6 && curr->ai_family != AF_INET6) {
        curr = curr->ai_next;
    }

    if (!curr) {
        if (err_msg) *err_msg = "No address for localhost";
        return -1;
    }

    if (curr->ai_addrlen > *addr_len) {
        if (err_msg) *err_msg = "addr length too small";
        return -1;
    }

    memcpy(addr, curr->ai_addr, curr->ai_addrlen);
    *addr_len = curr->ai_addrlen;

    freeaddrinfo(result);

    return 0;
}


struct tls_config *get_tls_config(void) {
    static char tls_buf[sizeof(struct tls_config) + sizeof(struct alpn_buffer)];
    static struct tls_config *tls_config = NULL;
    static const unsigned char alpn[] = ALPN_STR;

    if (tls_config) return tls_config;
    memset(tls_buf, 0, sizeof(tls_buf));
    tls_config = (struct tls_config *) tls_buf;

    tls_config->nb_alpn = 1;
    tls_config->certificate_file = NULL;
    tls_config->private_key_file = NULL;
    tls_config->alpn[0].alpn_name = alpn;
    tls_config->alpn[0].alpn_size = ALPN_STR_SIZE;
    tls_config->insecure = 1;
    tls_config->secret_log_file = NULL;


    return tls_config;
}