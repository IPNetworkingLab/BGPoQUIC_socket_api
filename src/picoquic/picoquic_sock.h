//
// Created by thomas on 26/09/22.
//

#ifndef QUIC_SOCK_PICOQUIC_SOCK_H
#define QUIC_SOCK_PICOQUIC_SOCK_H

#include "common/util_common_sock.h"
#include "common/util_data_buffer.h"
#include "common/util_queue.h"
#include "common/util_wait_queue.h"
#include <picoquic.h>
#include <semaphore.h>

#include <event2/event.h>

#define IS_PICOQUIC_SOCK(s) ((s) && ((s)->sk.type == SOCK_TYPE_PICOQUIC))

#define next_stream_id(s) (((s)->stream_id_cnt * 2) + (s)->conn_type)

enum quic_conn_type {
    QUIC_CLIENT = 0,
    QUIC_SERVER = 1,
};

struct write_pquic_strm {
    struct sockaddr_storage local_addr;
    struct sockaddr_storage peer_addr;
    int if_index;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t *last_cnx;
    size_t send_msg_size;

    uint64_t send_time;

    size_t msg_len;
    unsigned char data[0];
};


struct picoquic_master_socket {
    int udp_sock;
    int must_disable_gso;

    struct event *read_fd_evt;
    struct event *write_fd_evt;
    struct event *poll_write_evt;

    _Atomic int closed;

    unsigned int bind_port;

    picoquic_quic_t *quic_ctx;
    struct picoquic_socket *conn_ctx;

    unsigned char *r_buf;
    size_t r_buf_len;
    //struct q_queue pending_msg;

    pthread_mutex_t picoquic_master_lock;
};

struct picoquic_fallback_addr {
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    unsigned int local_iface_id;
    int has_migrated;
};

struct picoquic_socket {
    struct common_sock sk;
    _Atomic uint32_t flags;

    struct picoquic_master_socket *master;

    struct sockaddr_storage local_addr;
    size_t local_addr_len;
    struct sockaddr_storage remote_addr;
    size_t remote_addr_len;

    /* used for connection socks */
    picoquic_cnx_t *quic_cnx_ctx;
    uint64_t stream_id_cnt;
    enum quic_conn_type conn_type;
    struct q_queue pending_new_stream;
    struct q_queue sk_streams; /**< sk_stream sockets related to this conn */
    struct picoquic_socket *wake_fd_on_connect;
    struct {
        void *pem_cert;
        unsigned int pem_cert_length;
    };
    struct picoquic_fallback_addr fallback;

    /* used for listen socks */
    struct q_queue pending_new_conn;
    pthread_mutex_t signal_conn;

    /* used for stream socks*/
    struct wait_queue pending_recv_data;
    int signaled;
    pthread_mutex_t signal_lock;
    // struct q_queue pending_send_data;

    uint64_t stream_id;
    struct picoquic_socket *sk_conn;


};

#endif //QUIC_SOCK_PICOQUIC_SOCK_H
