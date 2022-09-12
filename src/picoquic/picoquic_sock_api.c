//
// Created by thomas on 26/09/22.
//
#define _GNU_SOURCE

#include <quic_sock/picoquic_sock_api.h>
#include <stdio.h>
#include "picoquic.h"
#include "picoquic_sock.h"
#include "common/util_sock_mgr.h"
#include "picoquic_utils.h"
#include "common/util_eventfd.h"
#include "picoquic_set_binlog.h"
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <picoquic_packet_loop.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <pthread.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <vpoll.h>
#include <fduserdata.h>
#include <linux/limits.h>
#include <unistd.h>


struct event_loop_arg {
    struct event_base *eb;
    int flags;
    long set_core_id;
};

struct read_strm_data {
    size_t length;
    size_t offset;
    unsigned char *data;
};

static char root_ca_path_[PATH_MAX];
static char *root_ca_path;

/* value inspired from /proc/sys/net/ipv4/tcp_rmem */
#define BUF_RMEM 1048576

#define IO_QUIC_CORE_ID "IO_QUIC_CORE_ID"

/* from picoquic, if GSO is enabled, they allocate a 65Kb buffer */
#define BUF_WMEM 65536

static pthread_t io_thrd;
static int thrd_finished;
static struct event_base *ev_base;

static char sock_table_room[sizeof(struct sock_table) + (MAX_SOCKFD * sizeof(struct common_sock *))];

static struct sock_table *socks__ = NULL;
#define ALL_SOCKS socks__

static inline int picoquic_getsockname__(int fd, struct sockaddr *addr, socklen_t *restrict len,
                                         void get_addr_fn(struct st_picoquic_cnx_t *, struct sockaddr **),
                                         unsigned long *ifindex);

static int picoquic_remote_getsockname(int fd, struct sockaddr *addr, socklen_t *restrict len);

static int intern_master_io_buf(struct picoquic_master_socket *sock, size_t r_len);

void picoquic_event_cb(evutil_socket_t sfd, short evts, void *arg);

void thread_write_on(struct picoquic_master_socket *master);

static inline int create_udp_sock(int af, uint16_t port, const char *bind_dev, size_t bind_dev_len);

static int server_callback(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx);

static int picoquic_do_conn_migration(struct picoquic_socket *sk);

static inline void trigger_poll_write(struct picoquic_master_socket *master) {
    static struct timeval now = {
            .tv_sec = 0,
            .tv_usec = 0
    };
    // evtimer_add(master->poll_write_evt, &now);

    event_active(master->poll_write_evt, EV_TIMEOUT, 0);
}

static inline void reschedule_write_event(struct picoquic_master_socket *master, int64_t wake_time) {
    struct timeval tv;

    if (master->closed) return;

    if (wake_time <= 0) {
        trigger_poll_write(master);
        return;
    }

    if (wake_time > 10000000) {
        tv.tv_sec = (long) 10;
        tv.tv_usec = 0;
    } else {
        tv.tv_sec = (long) (wake_time / 1000000);
        tv.tv_usec = (long) (wake_time % 1000000);
    }

    evtimer_add(master->poll_write_evt, &tv);
}

static struct picoquic_socket *intern_picoquic_socket__(void) {
    struct picoquic_socket *sock;
    int eventfd;
    sock = NULL;

    sock = calloc(sizeof(*sock), 1);
    if (!sock) {
        goto err;
    }

    // eventfd = eventfd_new();
    eventfd = vpoll_create(0, FD_CLOEXEC);

    if (eventfd < 0) {
        goto err;
    }

    sock->sk.sockfd = eventfd;
    sock->sk.type = SOCK_TYPE_PICOQUIC;

    if (add_sock(ALL_SOCKS, (struct common_sock *) sock) != 0) {
        goto err;
    }

    return sock;

    err:
    if (sock) free(sock);
    return NULL;
}

static int iter_sk_stream_close(void *arg) {
    struct picoquic_socket **sk_stream_ptr;
    struct picoquic_socket *sk_stream;
    sk_stream_ptr = arg;
    sk_stream = *sk_stream_ptr;

    SET_FLAG(sk_stream->flags, SOCK_STOP);
    /* "unblock" read */
    vpoll_ctl(sk_stream->sk.sockfd, VPOLL_CTL_ADDEVENTS, EPOLLIN | EPOLLHUP);
    // eventfd_post(sk_stream->sk.sockfd, 1);

    /* 0 means continue the execution */
    return 0;
}

static inline void signal_data(struct picoquic_socket *sk_stream) {
    pthread_mutex_lock(&sk_stream->signal_lock);
    if (!sk_stream->signaled && wait_queue_has_data(&sk_stream->pending_recv_data)) {
        sk_stream->signaled = 1;
        vpoll_ctl(sk_stream->sk.sockfd, VPOLL_CTL_ADDEVENTS, EPOLLIN);
        //eventfd_post(sk_stream->sk.sockfd, 1);
    }
    pthread_mutex_unlock(&sk_stream->signal_lock);
}

static inline void unsignal_data(struct picoquic_socket *sk_stream) {
    uint64_t counter;
    pthread_mutex_lock(&sk_stream->signal_lock);
    if (sk_stream->signaled && !wait_queue_has_data(&sk_stream->pending_recv_data)) {
        sk_stream->signaled = 0;
        vpoll_ctl(sk_stream->sk.sockfd, VPOLL_CTL_DELEVENTS, EPOLLIN);
        //eventfd_wait(sk_stream->sk.sockfd, 1, &counter);
        //assert(counter == 0);
    }
    pthread_mutex_unlock(&sk_stream->signal_lock);
}

static inline void on_cert_verification(struct picoquic_socket *sk, void *cert_data, unsigned int length) {
    assert(sk != NULL);
    assert(sk->pem_cert == NULL);

    if (!IS_SET(sk->flags, SOCK_QUIC_CONNECTION)) {
        fprintf(stderr, "[BUG] on_cert_verification "
                        "called with bad ctx socket\n");
        return;
    }
    if (sk->pem_cert) {
        fprintf(stderr, "[BUG?] Certificate already received!\n");
        return;
    }

    sk->pem_cert = malloc(length);
    if (!sk->pem_cert) {
        perror("[on_cert_verification] unable to "
               "allocate memory for pem_cert");
        return;
    }
    sk->pem_cert_length = length;
    memcpy(sk->pem_cert, cert_data, length);

}


static int client_callback(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx,
                           void *v_stream_ctx) {
    assert(callback_ctx != NULL);

    struct picoquic_socket *sk_conn = callback_ctx;
    struct picoquic_master_socket *sk_master = sk_conn->master;
    struct picoquic_socket *sk_stream = v_stream_ctx;
    int ret;


    ret = 0;
    switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (!v_stream_ctx) {
                fprintf(stderr, "ERROR stream ctx not set !\n");
                break;
            }

            /* very ugly hack, unlock master_lock as no picoquic ctx is altered */
            pthread_mutex_unlock(&sk_stream->master->picoquic_master_lock);
            /* this call could deadlock if no space left in the queue */
            /* todo this call could starve QUIC !!!!! */
            wait_queue_push(&sk_stream->pending_recv_data, bytes, length);
            /* tell the socket, there is data on the stream */
            signal_data(sk_stream);
            /* and re-lock as callee has "still" the lock */
            pthread_mutex_lock(&sk_stream->master->picoquic_master_lock);

            /*if (fin_or_event == picoquic_callback_stream_fin) {
                SET_FLAG(sk_stream->flags, SOCK_STOP);
            }*/
            break;
        case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
            /* Mark stream as abandoned, close the file, etc. */
            picoquic_reset_stream(cnx, stream_id, 0);
            /* Fall through */
        case picoquic_callback_stream_reset: /* Server reset stream #x */
            picoquic_get_remote_stream_error(cnx, stream_id);
            SET_FLAG(sk_stream->flags, SOCK_STOP);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Mark the connection as completed */
            if (sk_conn) {
                queue_for_each(&sk_conn->sk_streams, iter_sk_stream_close);
                SET_FLAG(sk_conn->flags, SOCK_STOP);
                picoquic_set_callback(sk_conn->quic_cnx_ctx, NULL, NULL);

                event_del(sk_master->read_fd_evt);
                event_del(sk_master->write_fd_evt);
                event_del(sk_master->poll_write_evt);

                sk_master->closed = 1;
                close(sk_master->udp_sock);
            }
            /* Remove the application callback */
            //picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_prepare_to_send:
            fprintf(stderr, "This should not be called !\n");
            abort();
            if (!v_stream_ctx) {
                //picoquic_provide_stream_data_buffer(bytes, 0, 0, 1);
                fprintf(stderr, "FATAL NO STREAM CONTEXT\n");
                break;
            }
            break;
        case picoquic_callback_almost_ready:
            break;
        case picoquic_callback_ready:
            SET_FLAG(sk_conn->flags, CONNECTED);
            UNSET_FLAG(sk_conn->flags, CONNECTION_INITIATED);
            vpoll_ctl(sk_conn->sk.sockfd, VPOLL_CTL_ADDEVENTS, EPOLLOUT);
            //eventfd_reset(sk_conn->sk.sockfd);
            //eventfd_post(sk_conn->sk.sockfd, 1);
            break;
        case picoquic_callback_certificate_received:
            fprintf(stderr, "Certificate from server received!\n");
            on_cert_verification(sk_conn, bytes, length);
            break;
        default:
            /* unexpected -- just ignore. */
            break;
    }

    return ret;
}

static int server_callback_new_conn(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes,
                                    size_t length, picoquic_call_back_event_t fin_or_event,
                                    void *callback_ctx, void *v_stream_ctx) {
    struct picoquic_socket *sk_listen;
    struct picoquic_socket *sk_conn;

    assert(callback_ctx);

    sk_listen = callback_ctx;
    sk_conn = intern_picoquic_socket__();
    if (!sk_conn) {
        picoquic_close_immediate(cnx);
        return -1;
    }
    SET_FLAG(sk_conn->flags, SOCK_QUIC_CONNECTION);

    sk_conn->quic_cnx_ctx = cnx;
    sk_conn->conn_type = QUIC_SERVER;
    sk_conn->stream_id_cnt = 0;
    sk_conn->master = sk_listen->master;
    sk_conn->master->conn_ctx = sk_conn;
    queue_init(&sk_conn->pending_new_stream);
    queue_init(&sk_conn->sk_streams);

    /* wake up the listener when the connection is ready */
    sk_conn->wake_fd_on_connect = sk_listen;

    /* change callback for this connection */
    picoquic_set_callback(cnx, server_callback, sk_conn);

    return server_callback(cnx, stream_id, bytes, length,
                           fin_or_event, sk_conn, v_stream_ctx);
}


struct picoquic_socket *new_picoquic_socket_stream(uint64_t stream_id, struct picoquic_socket *sk_conn,
                                                   struct picoquic_master_socket *sk_master) {
    struct picoquic_socket *sk_stream;

    sk_stream = intern_picoquic_socket__();
    if (!sk_stream) return NULL;
    SET_FLAG(sk_stream->flags, SOCK_QUIC_STREAM);
    sk_stream->stream_id = stream_id;
    sk_stream->sk_conn = sk_conn;
    sk_stream->master = sk_master;
    sk_stream->signaled = 0;
    sk_stream->signal_lock = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    wait_queue_init(&sk_stream->pending_recv_data, BUF_RMEM);
    //queue_init(&sk_stream->pending_send_data);

    /* directly open --> set write event */
    vpoll_ctl(sk_stream->sk.sockfd, VPOLL_CTL_ADDEVENTS, EPOLLOUT);

    return sk_stream;
}

struct picoquic_socket *new_picoquic_socket_listen() {
    struct picoquic_socket *sk_listen;
    sk_listen = intern_picoquic_socket__();
    if (!sk_listen) return NULL;

    queue_init(&sk_listen->pending_new_conn);

    SET_FLAG(sk_listen->flags, SOCK_QUIC_LISTENER);
    return sk_listen;
}

static int server_callback(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx) {
    struct picoquic_master_socket *sk_master;
    struct picoquic_socket *sk_stream;
    struct picoquic_socket *sk_conn;
    uint8_t *buffer;
    int ret;

    sk_conn = callback_ctx;
    sk_master = sk_conn->master;
    sk_stream = v_stream_ctx;

    ret = 0;

    switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (sk_stream == NULL) {
                /* should create stream context */
                assert(sk_master);

                sk_stream = new_picoquic_socket_stream(stream_id, sk_conn, sk_master);
                if (!sk_stream) return -1;

                /* inform connection a new stream is available */
                queue_add(&sk_conn->pending_new_stream, &sk_stream, sizeof(&sk_conn));
                /* this stream is linked to this connection */
                queue_add(&sk_conn->sk_streams, &sk_stream, sizeof(&sk_conn));
                SET_FLAG(sk_conn->flags, HAS_PENDING_STREAM);
                //eventfd_post(sk_conn->sk.sockfd, 1);
                vpoll_ctl(sk_conn->sk.sockfd, VPOLL_CTL_ADDEVENTS, EPOLLIN);
                picoquic_set_app_stream_ctx(cnx, stream_id, sk_stream);
            }

            /* very ugly hack, unlock master_lock as no picoquic ctx is altered */
            pthread_mutex_unlock(&sk_stream->master->picoquic_master_lock);
            /* this call could deadlock if no space left in the queue, so this
             * is why we unlock picoquic_master_lock to let user app to drain
             * this queue. However:
             * fixme:: this call could starve QUIC !!!!! We only hope
             * fixme:: that user-app read data as soon as possible */
            wait_queue_push(&sk_stream->pending_recv_data, bytes, length);
            /* tells the socket there is data on the stream */
            signal_data(sk_stream);
            /* and re-lock as callee has "still" the lock */
            pthread_mutex_lock(&sk_stream->master->picoquic_master_lock);

            //wait_queue_push(&sk_stream->pending_recv_data, bytes, length);
            break;
        case picoquic_callback_prepare_to_send:
            fprintf(stderr, "This should not be called\n");
            abort();
            if (!v_stream_ctx) {
                //picoquic_provide_stream_data_buffer(bytes, 0, 0, 1);
                fprintf(stderr, "FATAL NO STREAM CONTEXT\n");
                break;
            }
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            picoquic_reset_stream(cnx, stream_id, 0);
            SET_FLAG(sk_stream->flags, SOCK_STOP);
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            if (sk_conn) {
                queue_for_each(&sk_conn->sk_streams, iter_sk_stream_close);
                SET_FLAG(sk_conn->flags, SOCK_STOP);
                picoquic_set_callback(sk_conn->quic_cnx_ctx, NULL, NULL);

                /* do not close UDP sockets since it is used by listening sockets */
            }
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
            break;
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            SET_FLAG(sk_conn->flags, CONNECTED);
            UNSET_FLAG(sk_conn->flags, CONNECTION_INITIATED);
            /* tell to event socket a new * quic connection is established */
            /*if (eventfd_post(sk_conn->wake_fd_on_connect, 1) != 0) {
                return -1;
            }*/
            pthread_mutex_lock(&sk_conn->wake_fd_on_connect->signal_conn);
            queue_add(&sk_conn->wake_fd_on_connect->pending_new_conn, &sk_conn, sizeof(&sk_conn));
            vpoll_ctl(sk_conn->wake_fd_on_connect->sk.sockfd, VPOLL_CTL_ADDEVENTS, EPOLLIN);
            pthread_mutex_unlock(&sk_conn->wake_fd_on_connect->signal_conn);
            sk_conn->wake_fd_on_connect = NULL;
            break;
        case picoquic_callback_certificate_received:
            // fprintf(stderr, "Certificate from client received!\n");
            on_cert_verification(sk_conn, bytes, length);
            break;
        default:
            /* unexpected */
            break;
    }


    return ret;
}


void *event_base_loop_thread(void *arg) {
    int err;
    struct event_loop_arg *evt_args = arg;

    if (evt_args->set_core_id >= 0) {
        err = stick_this_thread_to_core(evt_args->set_core_id);
        if (err != 0) {
            perror("[WARN] Failed to set thread affinity");
        } else {
            fprintf(stderr, "[INFO] IO QUIC thread set to core #%ld\n", evt_args->set_core_id);
        }
    }

    event_base_loop(evt_args->eb, evt_args->flags);

    if (!thrd_finished) {
        fprintf(stderr, "[BUG] What a terrible failure! event_base_loop exited !\n");
    }

    pid_t pid;
    unsigned long nb_cpus;
    unsigned long running_cpus[64];
    unsigned long i;
    /*pid = gettid();
    if ((nb_cpus = get_affinity(pid, running_cpus,
                                sizeof(running_cpus) / sizeof(running_cpus[0]))) >= 0) {
        fprintf(stderr, "Process %d CPU affinity: ", pid);
        for (i = 0; i < nb_cpus; i++) {
            fprintf(stderr, "%lu ", running_cpus[i]);
        }
        fprintf(stderr, "\n");
    }*/

    return NULL;
}


int picoquic_init(const char *app_name) {
    pid_t pid;
    static int init = 0;
    static struct event_loop_arg loop_arg;
    const char *io_quic_core_id;
    long core_id;
    char *endptr;

    (void) app_name;

    if (init) return 0;

    if (evthread_use_pthreads() != 0) {
        fprintf(stderr, "evthread_use_pthreads failed!\n");
    }

    ALL_SOCKS = (struct sock_table *) sock_table_room;
    ALL_SOCKS->socks = (struct common_sock **) (sock_table_room + sizeof(struct sock_table));
    ALL_SOCKS->len = MAX_SOCKFD;
    init_sock_table(ALL_SOCKS);

    //event_enable_debug_mode();
    //evthread_enable_lock_debugging();

    pid = getpid();

    ev_base = event_base_new();
    if (!ev_base) return -1;

    loop_arg.eb = ev_base;
    loop_arg.flags = EVLOOP_NO_EXIT_ON_EMPTY;
    loop_arg.set_core_id = -1;

    if ((io_quic_core_id = getenv(IO_QUIC_CORE_ID))) {
        errno = 0;
        core_id = strtol(io_quic_core_id, &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
            fprintf(stderr, "[WARN] BAD %s. Unknown value \"%s\". Skip thread pinning\n",
                    IO_QUIC_CORE_ID, io_quic_core_id);
        } else {
            loop_arg.set_core_id = core_id;
        }
    }

    thrd_finished = 0;
    if (pthread_create(&io_thrd, NULL, event_base_loop_thread, &loop_arg) != 0) {
        return -1;
    }

    root_ca_path = NULL;
    memset(root_ca_path_, 0, sizeof(root_ca_path_));

    init = 1;
    return 0;
}


void picoquic_set_default_root_ca_path(const char *root_cert_path) {
    // memset in case of override
    memset(root_ca_path_, 0, sizeof(root_ca_path_));
    strncpy(root_ca_path_, root_cert_path, sizeof(root_ca_path_) - 1);
    // doubly make sure last char is 0
    root_ca_path_[sizeof(root_ca_path_) - 1] = 0;

    root_ca_path = root_ca_path_;
}

void picoquic_finished(void) {
    unsigned long i;
    unsigned long running_cpus[64];
    unsigned long nb_cpus;
    pid_t pid;
    struct timeval tv = {0};

    /*pid = getpid();
    if ((nb_cpus = get_affinity(pid, running_cpus,
                                sizeof(running_cpus) / sizeof(running_cpus[0]))) >= 0) {
        fprintf(stderr, "Process %d CPU affinity: ", pid);
        for (i = 0; i < nb_cpus; i++) {
            fprintf(stderr, "%lu ", running_cpus[i]);
        }
        fprintf(stderr, "\n");
    }*/

    thrd_finished = 1;
    event_base_loopexit(ev_base, &tv);
    pthread_join(io_thrd, NULL);
}

static inline uint16_t sockaddr_get_port(const struct sockaddr *addr) {
    struct sockaddr_in *in_addr;
    struct sockaddr_in6 *in6_addr;

    if (!addr) return 0;

    switch (addr->sa_family) {
        case AF_INET:
            in_addr = (struct sockaddr_in *) addr;
            return ntohs(in_addr->sin_port);
        case AF_INET6:
            in6_addr = (struct sockaddr_in6 *) addr;
            return ntohs(in6_addr->sin6_port);
        default:
            break;
    }

    return 0;
}

static int is_ipv6_link_local(struct sockaddr *addr) {
    if (addr->sa_family != AF_INET6) return 0;

    return IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *) addr)->sin6_addr);
}

static inline int create_udp_sock(int af, uint16_t port, const char *bind_dev, size_t bind_dev_len) {
    int ecn_rcv_set;
    int ecn_snd_set;
    int sfd;

    sfd = socket(af, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sfd < 0) {
        return -1;
    }

    if (picoquic_socket_set_pkt_info(sfd, af) != 0) return -1;
    if (picoquic_socket_set_pmtud_options(sfd, af) != 0) return -1;
    if (picoquic_socket_set_ecn_options(sfd, af, &ecn_rcv_set, &ecn_snd_set)) return -1;

    if (port > 0) {
        picoquic_bind_to_port(sfd, af, port);
    }

    if (bind_dev && bind_dev_len > 0) {
        if (setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, bind_dev, bind_dev_len) < 0) {
            return -1;
        }
    }

    return sfd;
}

static inline struct picoquic_master_socket *create_master_sock(
        struct sockaddr *local_addr, struct sockaddr *dest_addr,
        struct tls_config *tls_config, char client,
        unsigned int max_conn, struct picoquic_socket *sk_callback) {
    struct picoquic_master_socket *master_sock;
    struct sockaddr_storage ss_addr;
    picoquic_cnx_t *cnx_ctx;
    struct event *poll_write_evt;
    struct event *write_evt;
    struct event *read_evt;
    picoquic_quic_t *quic;
    uint64_t current_time;
    char bind_dev[IF_NAMESIZE];
    const char *do_bind_dev;
    int must_set_local_addr;
    unsigned int if_index;
    size_t bind_dev_len;
    int sfd;
    int af;

    do_bind_dev = NULL;
    bind_dev_len = 0;
    must_set_local_addr = 0;
    master_sock = calloc(1, sizeof(*master_sock));
    if (!master_sock) {
        return NULL;
    }

    if (!local_addr) {
        master_sock->bind_port = 0;
    } else if ((master_sock->bind_port = sockaddr_get_port(local_addr)) == 0 && !client) {
        /* the server must bind */
        return NULL;
    }

    if (client) {
        if (!dest_addr) return NULL;
        af = dest_addr->sa_family;
        if (is_ipv6_link_local(dest_addr)) {
            if (!local_addr) {
                /* if dest_addr is link local, we must bind to
                 * the local interface. So local_addr must be indicated ! */
                return NULL;
            }
            /* just try to set picoquic local addr */
            must_set_local_addr = 1;

            /*bind_dev_len = sizeof(bind_dev);
            if (iface_from_ipv6_link_local(local_addr, bind_dev, &bind_dev_len) != 0) {
                return NULL;
            }
            do_bind_dev = bind_dev;*/
        }
    } else if (local_addr) {
        af = local_addr->sa_family;
    } else {
        return NULL;
    }

    if ((sfd = create_udp_sock(af, master_sock->bind_port, do_bind_dev, bind_dev_len)) < 0) {
        return NULL;
    }

    if (master_sock->bind_port == 0) {
        if (picoquic_get_local_address(sfd, &ss_addr) != 0) {
            fprintf(stderr, "Get bind port failed");
            return NULL;
        }

        master_sock->bind_port = ss_addr.ss_family == AF_INET ? ntohs(((struct sockaddr_in *) &ss_addr)->sin_port) :
                                 ss_addr.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6 *) &ss_addr)->sin6_port) :
                                 0;
    }

    master_sock->udp_sock = sfd;

    intern_master_io_buf(master_sock, BUF_RMEM);

    max_conn = client ? 1 : max_conn;

    current_time = picoquic_current_time();
    quic = picoquic_create(max_conn, tls_config->certificate_file,
                           tls_config->private_key_file,
                           tls_config->root_ca_file ? tls_config->root_ca_file : root_ca_path,
                           (const char *) tls_config->alpn[0].alpn_name, NULL, NULL,
                           NULL, NULL, NULL, current_time, NULL,
                           NULL, NULL, 0);
    if (!quic) {
        return NULL;
    }
    master_sock->quic_ctx = quic;

    if (client) {
        assert(dest_addr);
        assert(IS_SET(sk_callback->flags, SOCK_QUIC_CONNECTION));
        cnx_ctx = picoquic_create_cnx(quic, picoquic_null_connection_id,
                                      picoquic_null_connection_id,
                                      (struct sockaddr *) dest_addr,
                                      current_time, 0,
                                      tls_config->sni,
                                      (const char *) tls_config->alpn[0].alpn_name, client);

        if (!cnx_ctx) {
            return NULL;
        }
        picoquic_enable_keep_alive(cnx_ctx, 0);
        sk_callback->quic_cnx_ctx = cnx_ctx;
        picoquic_set_callback(cnx_ctx, client_callback, sk_callback);
        if (must_set_local_addr) {
            if (is_ipv6_link_local(dest_addr) &&
                (((struct sockaddr_in6 *) local_addr)->sin6_scope_id == 0)) {
                /* scope id is not set, get iface id */
                if ((if_index = ifidx_from_addr(local_addr, NULL, 0)) == 0) {
                    return NULL;
                }
                ((struct sockaddr_in6 *) local_addr)->sin6_scope_id = if_index;
            }
            if (picoquic_set_local_addr(cnx_ctx, local_addr)) {
                return NULL;
            }
        }
    } else {
        assert(IS_SET(sk_callback->flags, SOCK_QUIC_LISTENER));
        sk_callback->quic_cnx_ctx = NULL; // still no connection
        picoquic_set_default_callback(quic, server_callback_new_conn, sk_callback);
        if (tls_config->require_client_authentication) {
            picoquic_set_client_authentication(quic, 1);
        }
    }


    master_sock->picoquic_master_lock = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    if (tls_config->qlog_dir) {
        picoquic_set_binlog(master_sock->quic_ctx, tls_config->qlog_dir);
    }

    /* prepare this udp socket to be run in the libevent loop */
    read_evt = event_new(ev_base, sfd, EV_READ | EV_PERSIST, picoquic_event_cb, master_sock);
    write_evt = event_new(ev_base, sfd, EV_WRITE, picoquic_event_cb, master_sock);
    poll_write_evt = evtimer_new(ev_base, picoquic_event_cb, master_sock);

    if (!read_evt || !write_evt || !poll_write_evt) {
        return NULL;
    }

    master_sock->read_fd_evt = read_evt;
    /* write event will be set when connection is started */
    master_sock->write_fd_evt = write_evt;
    master_sock->poll_write_evt = poll_write_evt;

    // queue_init(&master_sock->pending_msg);

    return master_sock;
}

static int start_read_evt(struct picoquic_master_socket *master) {
    return event_add(master->read_fd_evt, NULL);
}

static int intern_master_io_buf(struct picoquic_master_socket *sock, size_t r_len) {
    unsigned char *blk;

    blk = malloc(r_len);
    if (!blk) {
        return -1;
    }

    sock->r_buf = blk;
    sock->r_buf_len = r_len;
    return 0;
}

int picoquic_socket() {
    struct picoquic_socket *sock;

    sock = intern_picoquic_socket__();
    if (!sock) return -1;

    return sock->sk.sockfd;
}

int picoquic_bind(int sockfd,
                  const struct sockaddr *addr,
                  socklen_t addrlen) {
    struct picoquic_socket *socket;
    socket = (struct picoquic_socket *) get_sock(ALL_SOCKS, sockfd);
    if (!IS_PICOQUIC_SOCK(socket)) {
        return -1;
    }

    if (addrlen > sizeof(socket->local_addr)) {
        return -1;
    }
    memcpy(&socket->local_addr, addr, addrlen);
    socket->local_addr_len = addrlen;

    return 0;
}

int picoquic_listen(int sockfd,
                    struct tls_config *tls_config) {
    struct picoquic_socket *sk_listen;
    struct picoquic_master_socket *master;
    sk_listen = (struct picoquic_socket *) get_sock(ALL_SOCKS, sockfd);
    if (!IS_PICOQUIC_SOCK(sk_listen)) {
        return -1;
    }

    /* init pending conn queue */
    queue_init(&sk_listen->pending_new_conn);
    sk_listen->signal_conn = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;


    SET_FLAG(sk_listen->flags, SOCK_QUIC_LISTENER);
    master = create_master_sock((struct sockaddr *) &sk_listen->local_addr, NULL,
                                tls_config, 0, 255, sk_listen);
    if (!master) {
        return -1;
    }

    sk_listen->master = master;
    return start_read_evt(master);
}

int picoquic_accept(int sockfd,
                    struct sockaddr *address,
                    socklen_t *restrict address_len) {
    struct picoquic_socket *sk_listen;
    struct picoquic_socket *sk_conn;
    sk_listen = (struct picoquic_socket *) get_sock(ALL_SOCKS, sockfd);
    if (!IS_PICOQUIC_SOCK(sk_listen)) {
        return -1;
    }

    if (!IS_SET(sk_listen->flags, SOCK_QUIC_LISTENER)) {
        errno = EINVAL;
        return -1;
    }

    if (!queue_has_data(&sk_listen->pending_new_conn)) {
        errno = EWOULDBLOCK;
        return -1;
    }

    queue_pop(&sk_listen->pending_new_conn, &sk_conn, sizeof(&sk_conn));

    /*if (eventfd_wait(sk_listen->sk.sockfd, 1, &nb_pending_conn) != 0) {
        return -1;
    }*/

    if (pthread_mutex_lock(&sk_listen->signal_conn) != 0) abort();
    if (!queue_has_data(&sk_listen->pending_new_conn)) {
        vpoll_ctl(sk_listen->sk.sockfd, VPOLL_CTL_DELEVENTS, EPOLLIN);
    }
    if (pthread_mutex_unlock(&sk_listen->signal_conn) != 0) abort();

    if (picoquic_remote_getsockname(sk_conn->sk.sockfd, address, address_len) != 0) {
        /* make sure address_len is 0 */
        *address_len = 0;
    }

    return sk_conn->sk.sockfd;
}

int picoquic_accept_stream(int sockfd,
                           struct sockaddr *address,
                           socklen_t *restrict address_len) {
    struct picoquic_socket *sk_conn;
    struct picoquic_socket *sk_stream;
    uint64_t nb_pending_stream;
    sk_conn = (struct picoquic_socket *) get_sock(ALL_SOCKS, sockfd);
    if (!IS_PICOQUIC_SOCK(sk_conn)) {
        return -1;
    }

    if (!IS_SET(sk_conn->flags, CONNECTED)) {
        fprintf(stderr, "Socket is not yet connected !\n");
        return -1;
    }

    if (!IS_SET(sk_conn->flags, HAS_PENDING_STREAM)) {
        fprintf(stderr, "No streams to accept yet!\n");
        return -1;
    }


    /* read the counter from event fd socket */
    /*if (eventfd_wait(sk_conn->sk.sockfd, 1, &nb_pending_stream) != 0) {
        perror("eventfd read");
        return -1;
    }*/

    if (queue_pop(&sk_conn->pending_new_stream, &sk_stream, sizeof(&sk_stream)) != 0) {
        fprintf(stderr, "queue_pop failed\n");
        return -1;
    }

    if (!queue_has_data(&sk_conn->pending_new_stream)) {
        UNSET_FLAG(sk_stream->flags, HAS_PENDING_STREAM);
        vpoll_ctl(sk_conn->sk.sockfd, VPOLL_CTL_DELEVENTS, EPOLLIN);
    }

    /* should return the socket corresponding to the stream */
    SET_FLAG(sk_stream->flags, SOCK_QUIC_STREAM);

    if (picoquic_remote_getsockname(sk_stream->sk.sockfd, address, address_len) != 0) {
        /* make sure address_len is 0 */
        *address_len = 0;
    }

    return sk_stream->sk.sockfd;
}

int picoquic_open_stream(int sfd) {
    struct picoquic_master_socket *master_sock;
    struct picoquic_socket *sock_stream;
    struct picoquic_socket *sock_conn;
    uint64_t stream_id;

    sock_conn = (struct picoquic_socket *) get_sock(ALL_SOCKS, sfd);
    if (!IS_PICOQUIC_SOCK(sock_conn)) {
        return -1;
    }
    if (!IS_SET(sock_conn->flags, SOCK_QUIC_CONNECTION)) {
        return -1;
    }

    master_sock = sock_conn->master;

    sock_stream = new_picoquic_socket_stream(0, sock_conn, master_sock);
    if (!sock_stream) return -1;

    /* increment stream_id */
    /* FIXME: this may overflow if stream_id_cnt >= 2**62 */
    stream_id = sock_conn->stream_id_cnt;
    sock_conn->stream_id_cnt = next_stream_id(sock_conn);
    sock_stream->stream_id = stream_id;

    queue_add(&sock_conn->sk_streams, &sock_stream, sizeof(&sock_stream));
    return sock_stream->sk.sockfd;
}

int picoquic_connect(int sockfd,
                     const struct sockaddr *addr,
                     socklen_t addrlen,
                     struct tls_config *tls_config) {
    struct picoquic_master_socket *master;
    struct picoquic_socket *sk_conn;
    sk_conn = (struct picoquic_socket *) get_sock(ALL_SOCKS, sockfd);
    if (!IS_PICOQUIC_SOCK(sk_conn)) {
        return -1;
    }

    if (IS_SET(sk_conn->flags, SOCK_STOP)) {
        errno = ECONNREFUSED;
        return -1;
    }

    if (IS_SET(sk_conn->flags, CONNECTED)) {
        vpoll_ctl(sk_conn->sk.sockfd, VPOLL_CTL_DELEVENTS, EPOLLOUT);
        return 0;
    }

    if (IS_SET(sk_conn->flags, CONNECTION_INITIATED)) {
        errno = EINPROGRESS;
        return -1;
    }

    if (addrlen > sizeof(sk_conn->local_addr)) {
        return -1;
    }
    memcpy(&sk_conn->remote_addr, addr, addrlen);
    sk_conn->remote_addr_len = addrlen;

    if (tls_config->nb_alpn <= 0) {
        return -1;
    }

    SET_FLAG(sk_conn->flags, SOCK_QUIC_CONNECTION);
    master = create_master_sock(sk_conn->local_addr_len > 0 ? (struct sockaddr *) &sk_conn->local_addr : NULL,
                                (struct sockaddr *) &sk_conn->remote_addr,
                                tls_config, 1, 1, sk_conn);

    /* block "write" --> vpoll (see vpoll_create) blocks write event */
    /*if (eventfd_block_write(sk_conn->sk.sockfd)) {
        return -1;
    }*/

    if (!master) return -1;
    sk_conn->master = master;
    master->conn_ctx = sk_conn;

    /*if (sk_conn->local_addr_len) {
        picoquic_set_local_addr(sk_conn->quic_cnx_ctx, (struct sockaddr *) &sk_conn->local_addr);
    }*/

    if (tls_config->secret_log_file) {
        picoquic_set_key_log_file(sk_conn->master->quic_ctx, tls_config->secret_log_file);
    }


    sk_conn->conn_type = QUIC_CLIENT;
    if (picoquic_start_client_cnx(sk_conn->quic_cnx_ctx) != 0) {
        return -1;
    }

    queue_init(&sk_conn->sk_streams);

    SET_FLAG(sk_conn->flags, CONNECTION_INITIATED);

    if (start_read_evt(master) != 0) {
        fprintf(stderr, "Start read evt failed\n");
        return -1;
    }

    /* launch the event system */
    reschedule_write_event(master, 0);

    errno = EINPROGRESS;
    return -1;
}

/* little hack todo expose function */
int picoquic_recvmsg(int fd,
                     struct sockaddr_storage *addr_from,
                     struct sockaddr_storage *addr_dest,
                     int *dest_if,
                     unsigned char *received_ecn,
                     uint8_t *buffer, int buffer_max);

static void picoquic_event_cb_read(evutil_socket_t sfd, void *arg);

//static void picoquic_event_cb_write(evutil_socket_t sfd, void *arg);

static void picoquic_event_cb_poll_write(void *arg);

void picoquic_event_cb(evutil_socket_t sfd, short evts, void *arg) {

    if (evts & EV_READ) {
        picoquic_event_cb_read(sfd, arg);
    } else if (evts & EV_WRITE) {
        fprintf(stderr, "Should not be called\n");
        abort();
        //picoquic_event_cb_write(sfd, arg);
    } else if (evts & EV_TIMEOUT) { // only triggered by write
        picoquic_event_cb_poll_write(arg);
    } else {
        fprintf(stderr, "unrecognized event 0x%x !\n", evts);
    }
}

void thread_write_on(struct picoquic_master_socket *master) {
    /*if (event_pending(master->write_fd_evt, EV_WRITE, NULL)) {
        return;
    }*/

    if (event_add(master->write_fd_evt, NULL) != 0) {
        fprintf(stderr, "Failed to add write event !\n");
    }
}

void thread_write_off(struct picoquic_master_socket *master) {
}

static void picoquic_event_cb_read(evutil_socket_t sfd, void *arg) {
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    struct picoquic_master_socket *sk;
    picoquic_cnx_t *last_cnx;
    unsigned char recv_ecn;
    int bytes_recv;
    int dest_if;

    sk = arg;
    last_cnx = NULL;

    if (sk->closed) {
        event_del(sk->read_fd_evt);
        return;
    }

    uint64_t current_time;
    int64_t wake_time;

    current_time = picoquic_get_quic_time(sk->quic_ctx);

    /* recv plain data from UDP socket */
    bytes_recv = picoquic_recvmsg(sk->udp_sock, &addr_from, &addr_dest,
                                  &dest_if, &recv_ecn, sk->r_buf,
                                  sk->r_buf_len);

    if (bytes_recv <= 0) {
        /* the network socket has problems :( */
        fprintf(stderr, "NO bytes recv!\n");
        return;
    }

    if (pthread_mutex_lock(&sk->picoquic_master_lock) != 0) {
        abort();
    }

    /* picoquic_recvmsg does not update
     * the port on which data are received.
     * This must be done manually */
    if (addr_dest.ss_family == AF_INET) {
        ((struct sockaddr_in *) &addr_dest)->sin_port = htons(sk->bind_port);
    } else if (addr_dest.ss_family == AF_INET6) {
        ((struct sockaddr_in6 *) &addr_dest)->sin6_port = htons(sk->bind_port);
    }

    /* this should call the main callback */
    if (picoquic_incoming_packet_ex(sk->quic_ctx, sk->r_buf, bytes_recv,
                                    (struct sockaddr *) &addr_from,
                                    (struct sockaddr *) &addr_dest, dest_if, recv_ecn,
                                    &last_cnx, current_time) != 0) {
        fprintf(stderr, "picoquic_read internal error\n");
        return;
    }

    wake_time = picoquic_get_next_wake_delay(sk->quic_ctx, picoquic_get_quic_time(sk->quic_ctx), 100000000);
    if (pthread_mutex_unlock(&sk->picoquic_master_lock) != 0) {
        abort();
    }

    /* Write event as there might be something to write after receiving data */
    reschedule_write_event(sk, wake_time);

    /* add the event back into the "event loop" since everything went well */
    /*if (event_add(sk->read_fd_evt, NULL) != 0) {
        fprintf(stderr, "event_add failed\n");
    }*/
}

int retry_no_gso(int fd, struct sockaddr *peer_addr, struct sockaddr *local_addr, int if_index,
                 const char *send_buffer, int send_msg_size, int send_length) {

    int sock_ret;
    int sock_err;
    size_t packet_index = 0;
    size_t packet_size = send_msg_size;

    while (packet_index < send_length) {
        if (packet_index + packet_size > send_length) {
            packet_size = send_length - packet_index;
        }
        sock_ret = picoquic_sendmsg(fd,
                                    (struct sockaddr *) peer_addr, (struct sockaddr *) local_addr, if_index,
                                    (const char *) (send_buffer + packet_index), (int) packet_size, 0, &sock_err);
        if (sock_ret > 0) {
            packet_index += packet_size;
        } else {
            fprintf(stderr, "Still errors while sending message :/ %s\n", strerror(sock_err));
            return -1;
        }
    }
    return 0;
}

void picoquic_event_cb_poll_write(void *arg) {
#define USER_DATA_MAX_LEN 131072
    static unsigned char write_buf[sizeof(struct write_pquic_strm) + USER_DATA_MAX_LEN];
    static struct write_pquic_strm *strm = (struct write_pquic_strm *) write_buf;
    static size_t available_size = sizeof(write_buf) - sizeof(struct write_pquic_strm);

    struct picoquic_master_socket *master;
    size_t *send_msg_ptr;
    uint64_t curr_time;
    int64_t wake_time;
    int gso_err;
    int ret;

    master = arg;
    curr_time = picoquic_get_quic_time(master->quic_ctx);

    send_msg_ptr = master->must_disable_gso ? NULL : &strm->send_msg_size;

    strm->send_time = curr_time;

    if (pthread_mutex_lock(&master->picoquic_master_lock) != 0) {
        abort();
    }

    ret = picoquic_prepare_next_packet_ex(master->quic_ctx, curr_time,
                                          (uint8_t *) strm->data, available_size, &strm->msg_len,
                                          &strm->peer_addr, &strm->local_addr, &strm->if_index,
                                          &strm->log_cid, &strm->last_cnx,
                                          send_msg_ptr);
    wake_time = picoquic_get_next_wake_delay(master->quic_ctx, curr_time, 100000000);
    if (pthread_mutex_unlock(&master->picoquic_master_lock) != 0) {
        abort();
    }

    if (!strm->if_index && is_ipv6_link_local((struct sockaddr *)&strm->local_addr)) {
        fprintf(stderr, "if index invalid ! Trying to get real one\n");
        char dev_name[IF_NAMESIZE];
        size_t dev_name_len = sizeof(dev_name);
        unsigned int iface_idx_to;
        if (iface_from_ipv6_link_local((struct sockaddr *)&strm->local_addr, dev_name, &dev_name_len)) {
            fprintf(stderr, "Unable to get interface name from local addr :'(\n");
        } else if (!(iface_idx_to = iface_name_to_idx(dev_name))) {
            fprintf(stderr, "Unable to get interface index from interface name\n");
        } else {
            strm->if_index = iface_idx_to;
            fprintf(stderr, "Interface ID %d\n", strm->if_index);
        }
    }

    if (ret == 0 && strm->msg_len > 0) {
        /* there is data to send, write event trigger */
        int sock_err;
        int sock_ret;

        sock_ret = picoquic_sendmsg(master->udp_sock, (struct sockaddr *) &strm->peer_addr,
                                    (struct sockaddr *) &strm->local_addr, strm->if_index,
                                    strm->data, (int) strm->msg_len, (int) strm->send_msg_size, &sock_err);
        if (sock_ret <= 0) {
            if (sock_err == EBADF && master->closed) {
                return; // this can happen if the user abruptly closes the socket
            }
            if (sock_err == EMSGSIZE) {
                fprintf(stderr, "GSO problem ?\n");
                if (retry_no_gso(master->udp_sock, (struct sockaddr *) &strm->peer_addr,
                                 (struct sockaddr *) &strm->local_addr, strm->if_index,
                                 strm->data, strm->send_msg_size, strm->msg_len) != 0) {
                    fprintf(stderr, "Give up...\n");
                }
                master->must_disable_gso = 1;
            } else if ((sock_err == ENETUNREACH || sock_err == ENETDOWN) &&
                       master->conn_ctx->conn_type == QUIC_CLIENT && /* only client do connection migration */
                       master->conn_ctx->fallback.local_iface_id != 0 &&
                       !master->conn_ctx->fallback.has_migrated) {
                fprintf(stderr, "Network is unreachable but fallback address is requested !\n");
                if (picoquic_do_conn_migration(master->conn_ctx) != 0) {
                    fprintf(stderr, "Failed to migrate connection !\n");
                }
            } else if (sock_err == EINVAL && is_ipv6_link_local((struct sockaddr *)&strm->local_addr) &&
                       ifidx_from_addr((struct sockaddr *)&strm->local_addr, NULL, 0) == 0 &&
                       master->conn_ctx->fallback.local_iface_id != 0 &&
                       master->conn_ctx->conn_type == QUIC_CLIENT &&
                       !master->conn_ctx->fallback.has_migrated) {
                fprintf(stderr, "No more IPv6 link local addr but fallback address is set\n");
                if (picoquic_do_conn_migration(master->conn_ctx) != 0) {
                    fprintf(stderr, "Failed to migrate connection from link local to another address\n");
                }
            } else {
                fprintf(stderr, "picosend failed (errno #%d) %s\n", sock_err, strerror(sock_err));
            }
        }
    } else if (ret != 0) {
        fprintf(stderr, "ret -1 ?\n");
    }

    reschedule_write_event(master, wake_time);
}


ssize_t picoquic_read(int sfd, void *buf, size_t count) {
    struct picoquic_socket *sk_stream;
    size_t effective_read;
    size_t tot_available;
    ssize_t tot_read;
    struct read_strm_data **strmdata;

    sk_stream = (struct picoquic_socket *) get_sock(ALL_SOCKS, sfd);
    if (!IS_PICOQUIC_SOCK(sk_stream)) {
        return -1;
    }

    if (!IS_SET(sk_stream->flags, SOCK_QUIC_STREAM)) {
        return -1;
    }

    if (IS_SET(sk_stream->flags, SOCK_STOP)) {
        return 0;
    }

    if (!wait_queue_has_data(&sk_stream->pending_recv_data)) {
        errno = EWOULDBLOCK;
        return -1;
    }

    tot_read = wait_queue_pop(&sk_stream->pending_recv_data, buf, count);
    if (tot_read < 0) {
        return -1;
    }

    /* we consumed data, unsignal event if no more data on the queue */
    unsignal_data(sk_stream);
    return tot_read;
}

ssize_t picoquic_write(int sfd, const void *buf, size_t count) {
    struct picoquic_socket *sk_stream;
    int active_stream;
    int64_t wake_time;

    active_stream = 0;
    sk_stream = (struct picoquic_socket *) get_sock(ALL_SOCKS, sfd);
    if (!IS_PICOQUIC_SOCK(sk_stream)) {
        return -1;
    }

    if (!IS_SET(sk_stream->flags, SOCK_QUIC_STREAM)) {
        fprintf(stderr, "Not a quic stream\n");
        /* we only handle streams for now. Datagram maybe later */
        return -1;
    }

    if (IS_SET(sk_stream->flags, SOCK_STOP)) {
        return -1;
    }

    // queue_add(&sk_stream->pending_send_data, buf, count);


    if (pthread_mutex_lock(&sk_stream->master->picoquic_master_lock) != 0) {
        abort();
    }

    if (picoquic_add_to_stream_with_ctx(sk_stream->sk_conn->quic_cnx_ctx,
                                        sk_stream->stream_id, buf, count, 0, sk_stream) != 0) {

    } else {
        active_stream = 1;
    }

    wake_time = picoquic_get_next_wake_delay(sk_stream->master->quic_ctx,
                                             picoquic_get_quic_time(sk_stream->master->quic_ctx),
                                             100000000);

    if (pthread_mutex_unlock(&sk_stream->master->picoquic_master_lock) != 0) {
        abort();
    }

    if (!active_stream) {
        return -1;
    }

    /* trigger poll event now */
    reschedule_write_event(sk_stream->master, wake_time);

    return count;
}

int picoquic_s_close(int sfd) {
    struct picoquic_socket *sk;

    sk = (struct picoquic_socket *) get_sock(ALL_SOCKS, sfd);
    assert(sk->sk.sockfd == sfd);
    if (!IS_PICOQUIC_SOCK(sk)) {
        return -1;
    }
    SET_FLAG(sk->flags, SOCK_STOP);

    if (IS_SET(sk->flags, SOCK_QUIC_STREAM)) {
        /* remove all pending data */
        // TODO: wait_queue_flush(&sk->pending_send_data);

        /* delete socket from the connection */
        queue_remove(&sk->sk_conn->sk_streams, &sk, sizeof(&sk));

        pthread_mutex_lock(&sk->master->picoquic_master_lock);
        picoquic_discard_stream(sk->sk_conn->quic_cnx_ctx, sk->stream_id, 0);
        pthread_mutex_unlock(&sk->master->picoquic_master_lock);
        /* trigger a final write event */
        reschedule_write_event(sk->master, 0);
    }
    if (IS_SET(sk->flags, SOCK_QUIC_CONNECTION)) {
        pthread_mutex_lock(&sk->master->picoquic_master_lock);
        picoquic_close(sk->quic_cnx_ctx, 0);
        pthread_mutex_unlock(&sk->master->picoquic_master_lock);

        /* trigger a final write event */
        reschedule_write_event(sk->master, 0);

        //event_del(sk->master->write_fd_evt);
        //event_del(sk->master->read_fd_evt);
        //event_del(sk->master->poll_write_evt);

        /* todo gracefully close udp sockets after sending the last data on the event loop */
    }

    if (IS_SET(sk->flags, SOCK_QUIC_LISTENER)) {
        event_del(sk->master->write_fd_evt);
        event_del(sk->master->read_fd_evt);
        event_del(sk->master->poll_write_evt);
        close(sk->master->udp_sock);
    }

    /* clear all events that might be already there in the socket */
    vpoll_close(sk->sk.sockfd);

    del_sock(ALL_SOCKS, (struct common_sock *) sk);
    return 0;
}

int picoquic_remote_getsockname(int fd, struct sockaddr *addr, socklen_t *restrict len) {
    return picoquic_getsockname__(fd, addr, len, picoquic_get_peer_addr, NULL);
}

int picoquic_getsockname(int fd, struct sockaddr *addr, socklen_t *restrict len, unsigned long *ifindex) {
    return picoquic_getsockname__(fd, addr, len, picoquic_get_local_addr, ifindex);
}

static inline int picoquic_getsockname__(int fd, struct sockaddr *addr, socklen_t *restrict len,
                                         void get_addr_fn(struct st_picoquic_cnx_t *, struct sockaddr **),
                                         unsigned long *ifindex) {
    struct picoquic_socket *sk;
    struct sockaddr *s_addr;
    picoquic_cnx_t *cnx;

    if (!len || !addr) {
        errno = EINVAL;
        return -1;
    }

    sk = (struct picoquic_socket *) get_sock(ALL_SOCKS, fd);
    if (!IS_PICOQUIC_SOCK(sk)) {
        errno = EBADF;
        return -1;
    }

    if (IS_SET(sk->flags, SOCK_QUIC_CONNECTION)) {
        cnx = sk->quic_cnx_ctx;
    } else if (IS_SET(sk->flags, SOCK_QUIC_STREAM)) {
        if (!sk->sk_conn) {
            fprintf(stderr, "stream conn cnx is NULL !\n");
            return -1;
        }
        cnx = sk->sk_conn->quic_cnx_ctx;
    } else {
        cnx = NULL;
    }

    if (cnx == NULL && IS_SET(sk->flags, SOCK_QUIC_LISTENER)) {
        s_addr = (struct sockaddr *) &sk->local_addr;
    } else if (cnx == NULL) {
        return -1;
    } else {
        get_addr_fn(cnx, &s_addr);
    }

    if (s_addr == NULL) {
        errno = EBADF;
        return -1;
    }
    switch (s_addr->sa_family) {
        case AF_INET6:
            if (*len < sizeof(struct sockaddr_in6)) {
                errno = EINVAL;
                return -1;
            }
            memcpy(addr, s_addr, sizeof(struct sockaddr_in6));
            *len = sizeof(struct sockaddr_in6);
            break;
        case AF_INET:
            if (*len < sizeof(struct sockaddr_in)) {
                errno = EINVAL;
                return -1;
            }
            memcpy(addr, s_addr, sizeof(struct sockaddr_in));
            *len = sizeof(struct sockaddr_in);
            break;
        default:
            errno = EAFNOSUPPORT;
            return -1;
    }

    if (ifindex) {
        if (!cnx) {
            errno = EINVAL;
            return -1;
        }

        *ifindex = picoquic_get_local_if_index(cnx);
    }

    return 0;
}

size_t picoquic_get_remote_certificate(int sfd, void *buf, int max_buf_len) {
    struct picoquic_socket *sk;

    sk = (struct picoquic_socket *) get_sock(ALL_SOCKS, sfd);
    if (!sk) {
        errno = EBADF;
        return -1;
    }
    if (!IS_SET(sk->flags, SOCK_QUIC_CONNECTION)) {
        errno = EBADF;
        return -1;
    }

    if (!sk->pem_cert) {
        fprintf(stderr, "Certificate not yet received !\n");
        return -1;
    }

    if (max_buf_len < sk->pem_cert_length) {
        fprintf(stderr, "Buf length too small to hold the certificate\n");
        return -1;
    }

    /* Copy remote cert to user defined mem space */
    memcpy(buf, sk->pem_cert, sk->pem_cert_length);
    return sk->pem_cert_length;
}

int picoquic_set_fallback_address(int sfd, const struct sockaddr *from, const struct sockaddr *to) {
    struct picoquic_socket *sk;
    struct sockaddr *local_addr;
    unsigned int if_index;
    in_port_t current_port;

    sk = (struct picoquic_socket *) get_sock(ALL_SOCKS, sfd);
    if (!sk) {
        errno = EBADF;
        return -1;
    }

    if (!IS_SET(sk->flags, SOCK_QUIC_CONNECTION)) {
        errno = EBADF;
        return -1;
    }

    if (sk->conn_type != QUIC_CLIENT) {
        /* conn migration for now only initiated by client */
        errno = EINVAL;
        return -1;
    }

    /* todo check if *sk->local_addr != *from && *sk->remote_addr != *to */

    memcpy(&sk->fallback.local_addr, from, get_sock_size(from));
    memcpy(&sk->fallback.remote_addr, to, get_sock_size(to));


    /* get port info from "from" addr */
    current_port = sockaddr_get_port(from);

    /* use the port from the main path if no port is set */
    if (current_port == 0) {
        picoquic_get_local_addr(sk->quic_cnx_ctx, &local_addr);
        current_port = sockaddr_get_port(local_addr);

        if (from->sa_family == AF_INET) {
            ((struct sockaddr_in *) from)->sin_port = htons(current_port);
        } else {
            ((struct sockaddr_in6 *) from)->sin6_port = htons(current_port);
        }
    }

    if_index = ifidx_from_addr(from, NULL, 0);
    if (if_index == 0) {
        return -1;
    }

    sk->fallback.local_iface_id = if_index;
    return 0;
}

int picoquic_prepare_connection_migration(int sfd, const struct sockaddr *from, const struct sockaddr *to) {
    struct picoquic_socket *sk;
    struct sockaddr *local_addr;
    unsigned int if_index;
    int err;
    in_port_t current_port;

    sk = (struct picoquic_socket *) get_sock(ALL_SOCKS, sfd);
    if (!sk) {
        errno = EBADF;
        return -1;
    }

    /* get port info from "from" addr */
    current_port = sockaddr_get_port(from);

    /* use the port from the main path if no port is set */
    if (current_port == 0) {
        picoquic_get_local_addr(sk->quic_cnx_ctx, &local_addr);
        current_port = sockaddr_get_port(local_addr);

        if (from->sa_family == AF_INET) {
            ((struct sockaddr_in *) from)->sin_port = htons(current_port);
        } else {
            ((struct sockaddr_in6 *) from)->sin6_port = htons(current_port);
        }
    }

    if_index = ifidx_from_addr(from, NULL, 0);
    if (if_index == 0) {
        return -1;
    }

    pthread_mutex_lock(&sk->master->picoquic_master_lock);
    err = picoquic_probe_new_path_ex(sk->quic_cnx_ctx, to, from, if_index,
                                     picoquic_get_quic_time(sk->master->quic_ctx), 0);
    pthread_mutex_unlock(&sk->master->picoquic_master_lock);
    return err;
}


static int picoquic_do_conn_migration(struct picoquic_socket *sk) {
    int err;

    /* double check */
    if (sk->fallback.local_iface_id == 0) {
        return -1;
    }

    if (sk->fallback.has_migrated) {
        fprintf(stderr, "Already migrated!\n");
        return -1;
    }

    pthread_mutex_lock(&sk->master->picoquic_master_lock);
    err = picoquic_probe_new_path_ex(sk->quic_cnx_ctx, (struct sockaddr *) &sk->fallback.remote_addr,
                                     (struct sockaddr *) &sk->fallback.local_addr,
                                     sk->fallback.local_iface_id,
                                     picoquic_get_quic_time(sk->master->quic_ctx), 0);
    if (err != -1) {
        reschedule_write_event(sk->master, 0);
        sk->fallback.has_migrated = 1;
    }
    pthread_mutex_unlock(&sk->master->picoquic_master_lock);
    return err;
}