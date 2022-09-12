//
// Created by thomas on 15/06/22.
//

#include "msquic_sock.h"
#include <quic_sock/msquic_sock_api.h>

#include <sys/eventfd.h>
#include <stddef.h>
#include <stdlib.h>
#include "common/utlist.h"
#include "common/util_sock_mgr.h"
#include "common/util_eventfd.h"
#include <string.h>

#include <msquichelper.h>


#define READ_ON 1
#define READ_OFF 1

#define MAX_ALPN_BUFFERS 128

static char sock_table_room[sizeof(struct sock_table) +  (MAX_SOCKFD * sizeof(struct common_sock *))];
static struct sock_table *socks__ = NULL;
#define ALL_SOCKS socks__

static const QUIC_API_TABLE *msquic;
static HQUIC registration;


static inline int alpn_buffer2msquic_alpn_buffer(struct alpn_buffer *alpn_bufs,
                                                 size_t nb_alpn_bufs, QUIC_BUFFER *ms_bufs, size_t nb_ms_bufs) {
    size_t i;
    if (nb_ms_bufs < nb_alpn_bufs) return -1;

    for (i = 0; i < nb_alpn_bufs; i++) {
        ms_bufs[i].Buffer = (uint8_t *) alpn_bufs[i].alpn_name;
        ms_bufs[i].Length = alpn_bufs[i].alpn_size;
    }

    return 0;
}


static int init_socket(struct msquic_socket *sock) {
    int fd;
    if (!sock) return -1;

    fd = eventfd_new();
    if (!fd) return -1;

    memset(sock, 0, sizeof(*sock));
    sock->sk.sockfd = fd;
    sock->sk.type = SOCK_TYPE_MSQUIC;
    return 0;
}

extern inline
_Null_terminated_
const char *
QuicStatusToString(
        _In_ QUIC_STATUS Status
); /// redefine header


static inline void config_clean(void *hquic) {
    msquic->ConfigurationClose(hquic);
}

/* must be called once ! */
int msquic_init(const char *app_name) {
    int status;
    static QUIC_REGISTRATION_CONFIG reg_config;

    reg_config = (QUIC_REGISTRATION_CONFIG) {
            .AppName = app_name,
            .ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY
    };

    if (QUIC_FAILED(status = MsQuicOpen2(&msquic))) {
        fprintf(stderr, "MsQuicOpen failed, 0x%x! (%s)\n", status,
                QuicStatusToString(status));
        goto err;
    }

    if (QUIC_FAILED(status = msquic->RegistrationOpen(&reg_config, &registration))) {
        fprintf(stderr, "MsQuic RegistrationOpen failed 0x%x! (%s)\n",
                status, QuicStatusToString(status));
        goto err;
    }

    ALL_SOCKS = (struct sock_table *) sock_table_room;
    ALL_SOCKS->socks = (struct common_sock **) (sock_table_room + sizeof(struct sock_table));
    ALL_SOCKS->len = MAX_SOCKFD;
    init_sock_table(ALL_SOCKS);

    return 0;

    err:
    if (registration) msquic->RegistrationClose(registration);
    if (msquic) MsQuicClose(msquic);
    return -1;
}

/*int msquic_settings(HQUIC *reg, HQUIC *config) {
    int status;
    QUIC_SETTINGS settings = {0};

    settings.ServerResumptionLevel = QUIC_SERVER_NO_RESUME;
    settings.IsSet.ServerResumptionLevel = TRUE;

    settings.IdleTimeoutMs = 23;
    settings.IsSet.IdleTimeoutMs = TRUE;

    if (QUIC_FAILED(status = msquic->ConfigurationOpen(*reg, NUKK, 1, &settings, sizeof(settings), NULL, config))) {
        fprintf(stderr, "ConfigurationOpen Failed 0x%x!\n", status);
        goto err;
    }

    return 0;

    err:
    if (config) msquic->ConfigurationClose(*config);
    return -1;
}*/

static inline struct msquic_socket *intern_msquic_socket__(void) {
    struct msquic_socket *ms_sock;

    ms_sock = malloc(sizeof(*ms_sock));
    if (!ms_sock) {
        goto err;
    }

    if (init_socket(ms_sock) != 0) {
        goto err;
    }

    if (add_sock(ALL_SOCKS, (struct common_sock *)ms_sock) != 0) {
        goto err;
    }
    if (ms_sock->sk.type != SOCK_TYPE_MSQUIC) {
        goto err;
    }

    queue_init(&ms_sock->pdt_conn);

    CxPlatEventInitialize(&ms_sock->r_evt, FALSE, FALSE);
    CxPlatEventInitialize(&ms_sock->w_evt, FALSE, FALSE);

    return ms_sock;

    err:
    if (ms_sock) {
        free(ms_sock);
    }

    return NULL;
}

int msquic_socket(void) {
    struct msquic_socket *ms_sock;

    ms_sock = intern_msquic_socket__();

    if (!ms_sock) return -1;

    return ms_sock->sk.sockfd;
}


int msquic_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct msquic_socket *ms_sock;
    QUIC_ADDR *quic_addr;
    if (!(ms_sock = (struct msquic_socket *) get_sock(ALL_SOCKS, sockfd))) {
        return -1;
    } if (ms_sock->sk.type != SOCK_TYPE_MSQUIC) {
        return -1;
    }
    quic_addr = &ms_sock->local_address;

    switch (addr->sa_family) {
        case AF_INET:
        case AF_INET6:
            break;
        default:
            errno = EAFNOSUPPORT;
            return -1;
    }
    ms_sock->must_bind = 1;
    memcpy(&quic_addr->Ip, addr, addrlen);
    return 0;
}

//static size_t read_event(struct msquic_socket *s, QUIC_STREAM_EVENT *evt) {
//    const QUIC_BUFFER *qbf;
//    size_t tot_read;
//    size_t curr_read;
//    uint32_t i;
//
//    qbf = evt->RECEIVE.Buffers;
//    tot_read = 0;
//
//    if (buffer_lock(&s->rbuf) != 0) {
//        fprintf(stderr, "Failed to lock buffer\n");
//        return 0;
//    }
//    for (i = 0; i < evt->RECEIVE.BufferCount; i++) {
//        curr_read = buffer_write(&s->rbuf, qbf[i].Buffer, qbf[i].Length);
//        tot_read += curr_read;
//        if (curr_read < qbf[i].Length || curr_read == 0) {
//            goto ok_exit;
//        }
//    }
//
//    ok_exit:
//
//    if (buffer_unlock(&s->rbuf) != 0) {
//        fprintf(stderr, "Failed to unlock buffer\n");
//        return 0;
//    }
//
//    /* tells to event fd that data
//     * is ready to be read */
//    if (event_post(s->sockfd, tot_read)) {
//        fprintf(stderr, "Event wait failed !\n");
//    }
//    return tot_read;
//}

static unsigned int stream_cb(HQUIC stream __attribute__((unused)), void *ctx, QUIC_STREAM_EVENT *event) {
    struct msquic_socket *ms_sock_stream;

    ms_sock_stream = ctx;

    assert(stream == ms_sock_stream->stream);

    switch (event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            ms_sock_stream->buf = event->RECEIVE.Buffers->Buffer;
            ms_sock_stream->buf_length = event->RECEIVE.Buffers->Length;

            /* tells to event fd that data
             * is ready to be read */
            if (eventfd_post(ms_sock_stream->sk.sockfd, READ_ON)) {
                fprintf(stderr, "Event wait failed !\n");
            }
            /* read is not made in the callback but in msquic_read */
            event->RECEIVE.TotalBufferLength = 0;

            CxPlatEventSet(ms_sock_stream->r_evt);
            return QUIC_STATUS_PENDING;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            /* send is complete unlock msquic_write */
            CxPlatEventSet(ms_sock_stream->w_evt);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            fprintf(stderr, "fd %d, peer send shutdown (%p)\n", ms_sock_stream->sk.sockfd, ms_sock_stream);
            SET_FLAG(ms_sock_stream->flags, SOCK_STOP);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            fprintf(stderr, "fd %d, stream aborted, errcode: %lu (%p)\n",
                    ms_sock_stream->sk.sockfd, event->Type == QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED ?
                                            event->PEER_RECEIVE_ABORTED.ErrorCode : event->PEER_SEND_ABORTED.ErrorCode,
                    ms_sock_stream);
            SET_FLAG(ms_sock_stream->flags, SOCK_STOP);
            eventfd_post(ms_sock_stream->sk.sockfd, READ_ON);
            break;
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
            SET_FLAG(ms_sock_stream->flags, SOCK_STOP);
            eventfd_post(ms_sock_stream->sk.sockfd, READ_ON);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            if (event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                SET_FLAG(ms_sock_stream->flags, CLOSED);
                msquic->StreamClose(stream);
            }
            break;
        case QUIC_STREAM_EVENT_START_COMPLETE:
            SET_FLAG(ms_sock_stream->flags, STREAMED);
            break;
        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

static unsigned int server_connection_cb(HQUIC connection, void *ctx, QUIC_CONNECTION_EVENT *event) {
    struct msquic_socket *ms_sock_conn;
    struct msquic_socket *ms_sock_stream;

    ms_sock_conn = ctx;

    switch (event->Type) {

        case QUIC_CONNECTION_EVENT_CONNECTED:
            /* handshake completed ! should soon receive data from the remote peer */
            SET_FLAG(ms_sock_conn->flags, CONNECTED);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            SET_FLAG(ms_sock_conn->flags, SOCK_STOP);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            SET_FLAG(ms_sock_conn->flags, SOCK_STOP);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                SET_FLAG(ms_sock_conn->flags, SOCK_STOP);
                msquic->ConnectionClose(connection);
            }
            break;
        case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            ms_sock_stream = intern_msquic_socket__();
            if (!ms_sock_stream) return QUIC_STATUS_INTERNAL_ERROR;

            if (queue_add(&ms_sock_conn->pdt_conn, &ms_sock_stream, sizeof(&ms_sock_stream))) {
                fprintf(stderr, "Unable to put new stream socket to the queue\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            msquic->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, stream_cb, ms_sock_stream);
            msquic->ConnectionSendResumptionTicket(connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
            ms_sock_stream->stream = event->PEER_STREAM_STARTED.Stream;

            /* wakeup eventfd */
            if (eventfd_post(ms_sock_conn->sk.sockfd, 1)) {
                fprintf(stderr, "eventfd_post failed\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }
            SET_FLAG(ms_sock_conn->flags, HAS_PENDING_STREAM);
            break;
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
            break;
        case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
            break;
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_RESUMED:
            break;
        case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
            break;
        case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
            break;
        default:
            break;

    }

    return QUIC_STATUS_SUCCESS;

}


static unsigned int server_listener_cb(HQUIC listener, void *ctx, QUIC_LISTENER_EVENT *event) {
    //int status;
    struct msquic_socket *ms_sock_listen;
    struct msquic_socket *ms_sock_conn;
    const QUIC_NEW_CONNECTION_INFO *conn_info;
    unsigned int status;

    ms_sock_listen = ctx;

#ifdef NDEBUG
    (void) listener;
#endif

    assert(listener == ms_sock_listen->listener);

    switch (event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            conn_info = event->NEW_CONNECTION.Info;

            /* create a new socket that represents a quic connection */
            ms_sock_conn = intern_msquic_socket__();
            if (!ms_sock_conn) return QUIC_STATUS_INTERNAL_ERROR;

            ms_sock_conn->remote_address = *conn_info->RemoteAddress;
            ms_sock_conn->connection = event->NEW_CONNECTION.Connection;
            ms_sock_conn->configuration = ms_sock_listen->configuration;

            /* put the new connection QUIC socket to the listening socket queue */
            if (queue_add(&ms_sock_listen->pdt_conn, &ms_sock_conn, sizeof(&ms_sock_conn)) != 0) {
                fprintf(stderr, "Add new conn sock to queue error !\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }


            /* we put the setcallback + connection set config in the callback */
            msquic->SetCallbackHandler(ms_sock_conn->connection, server_connection_cb, ms_sock_conn);
            if (QUIC_FAILED(status = msquic->ConnectionSetConfiguration(ms_sock_conn->connection,
                                                                        ms_sock_listen->configuration->ref))) {
                fprintf(stderr, "ConnectionSetConfiguration failed 0x%x!\n", status);
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            if (IS_SET(ms_sock_listen->flags, SHOULD_EXPOSE_SECRETS)) {
                if (QUIC_FAILED(status = msquic->SetParam(ms_sock_conn->connection, QUIC_PARAM_CONN_TLS_SECRETS,
                                                          sizeof(ms_sock_conn->secrets), &ms_sock_conn->secrets))) {
                    fprintf(stderr, "[WARN] QUIC Secrets failed 0x%x: %s\n", status, QuicStatusToString(status));
                }
                SET_FLAG(ms_sock_conn->flags, SECRETS_EXPOSED);
            }

            /* lock the reference since config is used for this connection */
            assert(ms_sock_listen->configuration == ms_sock_conn->configuration);
            sh_ref_lock(ms_sock_listen->configuration);

            /* notify the underlying socket that a new connection
             * is ready to be accepted */
            if (eventfd_post(ms_sock_listen->sk.sockfd, 1) != 0) {
                fprintf(stderr, "eventfd_post failed\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }
            SET_FLAG(ms_sock_listen->flags, HAS_PENDING_CONN);
            break;
        case QUIC_LISTENER_EVENT_STOP_COMPLETE:
            SET_FLAG(ms_sock_listen->flags, SOCK_STOP);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

int msquic_listen(int sockfd, struct tls_config *tls_config) {
    int status;
    struct msquic_socket *ms_sock;
    struct QUIC_BUFFER alpn_buffers[MAX_ALPN_BUFFERS];
    QUIC_CREDENTIAL_CONFIG_HELPER creds;
    QUIC_SETTINGS settings = {0};
    HQUIC h_config;
    struct sh_ref *hquic_ref;

    memset(&creds, 0, sizeof(creds));
    creds.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    if (!tls_config) {
        return -1;
    }

    if (!(ms_sock = (struct msquic_socket *) get_sock(ALL_SOCKS, sockfd))) {
        return -1;
    }

    if (tls_config->nb_alpn > MAX_ALPN_BUFFERS) {
        return -1;
    }

    settings.PeerBidiStreamCount = 32;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    creds.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    creds.CredConfig.CertificateFile = &creds.CertFile;
    creds.CertFile.CertificateFile = tls_config->certificate_file;
    creds.CertFile.PrivateKeyFile = tls_config->private_key_file;

    if (tls_config->insecure) {
        creds.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    if (alpn_buffer2msquic_alpn_buffer(tls_config->alpn, tls_config->nb_alpn,
                                       alpn_buffers, MAX_ALPN_BUFFERS) != 0) {
        return -1;
    }

    if (QUIC_FAILED(status = msquic->ConfigurationOpen(registration, alpn_buffers, tls_config->nb_alpn,
                                                       &settings, sizeof(settings), NULL, &h_config))) {
        return -1;
    }

    hquic_ref = sh_ref_new(h_config);
    if (!hquic_ref) {
        return -1;
    }
    sh_ref_set_clean_fn(hquic_ref, config_clean);
    sh_ref_lock(hquic_ref);

    if (QUIC_FAILED(status = msquic->ConfigurationLoadCredential(hquic_ref->ref, &creds.CredConfig))) {
        fprintf(stderr, "ConfigurationLoadCredential failed: %s (0x%x)\n", QuicStatusToString(status), status);
        return -1;
    }

    if (tls_config->secret_log_file) {
        SET_FLAG(ms_sock->flags, SHOULD_EXPOSE_SECRETS);
    }

    if (QUIC_FAILED(status = msquic->ListenerOpen(registration, server_listener_cb, ms_sock, &ms_sock->listener))) {
        fprintf(stderr, "ListenerOpen failed: %s (0x%x)!\n", QuicStatusToString(status), status);
        return -1;
    }


    if (QUIC_FAILED(status = msquic->ListenerStart(ms_sock->listener, alpn_buffers,
                                                   tls_config->nb_alpn, &ms_sock->local_address))) {
        fprintf(stderr, "ListenerStart failed: %s (0x%x)!\n", QuicStatusToString(status), status);
        goto err;
    }

    ms_sock->configuration = hquic_ref;

    return 0;

    err:
    if (ms_sock->listener) msquic->ListenerClose(ms_sock->listener);
    return -1;
}

static inline int msquic_addr_to_sockaddr(const QUIC_ADDR *addr, struct sockaddr *restrict address,
                                          socklen_t *restrict address_len) {
    /* copy ip address */
    switch (addr->Ip.sa_family) {
        case AF_INET:
            memcpy(address, &addr->Ipv4, sizeof(addr->Ipv4));
            if (address_len) *address_len = sizeof(addr->Ipv4);
            break;
        case AF_INET6:
            memcpy(address, &addr->Ipv6, sizeof(addr->Ipv6));
            if (address_len) *address_len = sizeof(addr->Ipv6);
            break;
        default:
            return -1;
    }

    return 0;
}

static inline int sockaddr_to_msquic_addr(const struct sockaddr *restrict addr, socklen_t address_len,
                                          QUIC_ADDR *restrict ms_addr, uint16_t *port) {
    switch (addr->sa_family) {
        case AF_INET:
            *port = be16toh(((const struct sockaddr_in *) addr)->sin_port);
            memcpy(&ms_addr->Ipv4, addr, address_len);
            break;
        case AF_INET6:
            *port = be16toh(((const struct sockaddr_in6 *) addr)->sin6_port);
            memcpy(&ms_addr->Ipv6, addr, address_len);
            break;
        default:
            return -1;
    }
    return 0;
}

int msquic_accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len) {
    // int status;
    uint64_t counter;
    struct msquic_socket *ms_sock;
    struct msquic_socket *ms_sock_conn;

    if (!(ms_sock = (struct msquic_socket *) get_sock(ALL_SOCKS, socket))) {
        return -1;
    }

    if (!IS_SET(ms_sock->flags, HAS_PENDING_CONN)) {
        fprintf(stderr, "No connections !\n");
        errno = EWOULDBLOCK;
        return -1;
    }

    /* read the counter associated to the eventfd socket */
    if (eventfd_wait(ms_sock->sk.sockfd, 1, &counter) != 0) {
        perror("event_wait failed");
        return -1;
    }

    /* get the socket created in the callback */
    if (queue_pop(&ms_sock->pdt_conn, &ms_sock_conn, sizeof(&ms_sock_conn)) != 0) {
        fprintf(stderr, "Unable to retrieve ");
        return -1;
    }

    if (msquic_addr_to_sockaddr(&ms_sock_conn->remote_address, address, address_len) != 0) {
        fprintf(stderr, "copy_ipaddress failed, addr family no supported !\n");
        return -1;
    }

    /*msquic->SetCallbackHandler(ms_sock->connection, server_connection_cb, ms_sock_conn);
    if (QUIC_FAILED(status = msquic->ConnectionSetConfiguration(ms_sock->connection, ms_sock->configuration))) {
        fprintf(stderr, "ConnectionSetConfiguration failed 0x%x!\n", status);
        return -1;
    }*/


    if (counter <= 0) {
        UNSET_FLAG(ms_sock->flags, HAS_PENDING_CONN);
    }

    /* should return the new socket file descriptor */
    return ms_sock_conn->sk.sockfd;
}

int msquic_accept_stream(int socket) {
    struct msquic_socket *ms_sock_conn;
    struct msquic_socket *ms_sock_stream;
    uint64_t counter;

    if (!(ms_sock_conn = (struct msquic_socket *) get_sock(ALL_SOCKS, socket))) {
        return -1;
    }

    if (!IS_SET(ms_sock_conn->flags, CONNECTED)) {
        fprintf(stderr, "Socket is not yet connected !\n");
        return -1;
    }

    if (!IS_SET(ms_sock_conn->flags, HAS_PENDING_STREAM)) {
        fprintf(stderr, "No streams to accept yet!\n");
        return -1;
    }

    /* read the counter from event fd socket */
    if (eventfd_wait(ms_sock_conn->sk.sockfd, 1, &counter) != 0) {
        perror("eventfd read");
        return -1;
    }

    if (queue_pop(&ms_sock_conn->pdt_conn, &ms_sock_stream, sizeof(&ms_sock_stream)) != 0) {
        fprintf(stderr, "queue_pop failed\n");
        return -1;
    }

    if (counter <= 0) {
        UNSET_FLAG(ms_sock_conn->flags, HAS_PENDING_STREAM);
    }

    /* should return the socket corresponding to the stream */
    SET_FLAG(ms_sock_stream->flags, SOCK_QUIC_STREAM);
    return ms_sock_stream->sk.sockfd;
}


unsigned int client_conn_cb(HQUIC connection, void *ctx, QUIC_CONNECTION_EVENT *event) {
    struct msquic_socket *ms_sock_conn;

    ms_sock_conn = ctx;

    switch (event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            /* trigger eventfd */
            if (eventfd_post(ms_sock_conn->sk.sockfd, 1) != 0) {
                perror("write eventfd");
            }
            UNSET_FLAG(ms_sock_conn->flags, CONNECTION_INITIATED);
            SET_FLAG(ms_sock_conn->flags, CONNECTED);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            fprintf(stderr, "Error Shutdown initiated by transport: "
                            "%s\n", QuicStatusToString(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
            SET_FLAG(ms_sock_conn->flags, SOCK_STOP);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            SET_FLAG(ms_sock_conn->flags, CLIENT_SIDE_CLOSED);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                SET_FLAG(ms_sock_conn->flags, SOCK_STOP);
                msquic->ConnectionClose(connection);
            }
            break;
        case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            break;
        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
            break;
        case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
            break;
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
            break;
        case QUIC_CONNECTION_EVENT_RESUMED:
            break;
        case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
            break;
        case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
            break;
        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

static inline const char *sockaddr_ntop(int af, const void *restrict src,
                                        char *restrict dst, socklen_t size) {
    const void *sockaddr_addr;

    switch (af) {
        case AF_INET:
            sockaddr_addr = &((const struct sockaddr_in *) src)->sin_addr;
            break;
        case AF_INET6:
            sockaddr_addr = &((const struct sockaddr_in6 *) src)->sin6_addr;
            break;
        default:
            return NULL;
    }
    return inet_ntop(af, sockaddr_addr, dst, size);
}

int msquic_connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen, struct tls_config *tls_config) {
    unsigned int status;
    uint16_t port;
    char str_ip[64];
    struct msquic_socket *ms_sock;
    QUIC_BUFFER ms_alpn_buffers[MAX_ALPN_BUFFERS];
    HQUIC h_config;
    struct sh_ref *hquic_ref;

    QUIC_CREDENTIAL_CONFIG_HELPER cred_config;

    if (!(ms_sock = (struct msquic_socket *)get_sock(ALL_SOCKS, sockfd))) {
        return -1;
    }

    if (IS_SET(ms_sock->flags, CONNECTED)) {
        return 0;
    }

    if (IS_SET(ms_sock->flags, CONNECTION_INITIATED)) {
        errno = EINPROGRESS;
        return -1;
    }

    if (!tls_config) {
        return -1;
    }

    if (tls_config->nb_alpn > MAX_ALPN_BUFFERS) {
        return -1;
    }

    if (alpn_buffer2msquic_alpn_buffer(tls_config->alpn, tls_config->nb_alpn,
                                       ms_alpn_buffers,
                                       sizeof(ms_alpn_buffers) / sizeof(ms_alpn_buffers[0])) != 0) {
        return -1;
    }

    memset(&cred_config, 0, sizeof(cred_config));

    /* "msquic_connect" will always be used as client */
    cred_config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;

    if (tls_config->insecure) {
        cred_config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    if (tls_config->private_key_file == NULL && tls_config->certificate_file == NULL) {
        cred_config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    } else {
        cred_config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        cred_config.CredConfig.CertificateFile = &cred_config.CertFile;
        cred_config.CredConfig.CertificateFile->CertificateFile = tls_config->certificate_file;
        cred_config.CredConfig.CertificateFile->PrivateKeyFile = tls_config->private_key_file;
    }

    if (QUIC_FAILED(status = msquic->ConfigurationOpen(registration, ms_alpn_buffers,
                                                       tls_config->nb_alpn, NULL, 0, NULL,
                                                       &h_config))) {
        fprintf(stderr, "ConfigurationOpen failed 0x%x!\n", status);
        return -1;
    }

    hquic_ref = sh_ref_new(h_config);
    if (!hquic_ref) {
        return -1;
    }
    sh_ref_set_clean_fn(hquic_ref, config_clean);
    sh_ref_lock(hquic_ref);


    if (QUIC_FAILED(status = msquic->ConfigurationLoadCredential(hquic_ref->ref, &cred_config.CredConfig))) {
        fprintf(stderr, "ConfigurationLoadCredential failed 0x%x!\n", status);
        return -1;
    }

    if (QUIC_FAILED(status = msquic->ConnectionOpen(registration, client_conn_cb,
                                                    ms_sock, &ms_sock->connection))) {
        fprintf(stderr, "ConnectionOpen failed 0x%x!\n", status);
        return -1;
    }

    if (tls_config->secret_log_file) {
        if (QUIC_FAILED(status = msquic->SetParam(ms_sock->connection, QUIC_PARAM_CONN_TLS_SECRETS,
                         sizeof(ms_sock->secrets), &ms_sock->secrets))) {
            fprintf(stderr, "[WARN] QUIC Secrets failed 0x%x: %s\n", status, QuicStatusToString(status));
        }
        SET_FLAG(ms_sock->flags, SECRETS_EXPOSED);
    }

    if (ms_sock->must_bind) {
        if (QUIC_FAILED(status = msquic->SetParam(ms_sock->connection, QUIC_PARAM_CONN_LOCAL_ADDRESS,
                                                  sizeof(ms_sock->local_address), &ms_sock->local_address))) {
            fprintf(stderr, "Unable to bind quic connect socket to "
                            "local address 0x%x: %s\n", status, QuicStatusToString(status));
            return -1;
        }
    }

    memset(str_ip, 0, sizeof(str_ip));
    if (!sockaddr_ntop(addr->sa_family, addr, str_ip, sizeof(str_ip))) {
        fprintf(stderr, "Unable to convert addr to the string repr\n");
        return -1;
    }

    if (sockaddr_to_msquic_addr(addr, addrlen, &ms_sock->remote_address, &port) != 0) {
        fprintf(stderr, "addr familly not supported\n");
        return -1;
    }

    if (QUIC_FAILED(status = msquic->ConnectionStart(ms_sock->connection, hquic_ref->ref,
                                                     QuicAddrGetFamily(&ms_sock->remote_address),
                                                     str_ip, port))) {
        fprintf(stderr, "ConnectionStart failed 0x%x (%s)!\n", status, QuicStatusToString(status));
    }

    ms_sock->configuration = hquic_ref;

    SET_FLAG(ms_sock->flags, CONNECTION_INITIATED);

    errno = EINPROGRESS;
    return -1;
}


int msquic_open_stream(int socket) {
    int status;
    struct msquic_socket *ms_sock_conn;
    struct msquic_socket *ms_sock_stream;

    if (!(ms_sock_conn = (struct msquic_socket *) get_sock(ALL_SOCKS, socket))) {
        return -1;
    }

    if (!IS_SET(ms_sock_conn->flags, CONNECTED)) {
        return -1;
    }

    ms_sock_stream = intern_msquic_socket__();
    if (!ms_sock_stream) {
        return -1;
    }

    if (QUIC_FAILED(status = msquic->StreamOpen(ms_sock_conn->connection, QUIC_STREAM_OPEN_FLAG_NONE,
                                                stream_cb, ms_sock_stream, &ms_sock_stream->stream))) {
        fprintf(stderr, "StreamOpen failed 0x%x!\n", status);
        return -1;
    }

    if (QUIC_FAILED(status = msquic->StreamStart(ms_sock_stream->stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
        fprintf(stderr, "StreamStart failed 0x%x!\n", status);
        return -1;
    }

    SET_FLAG(ms_sock_stream->flags, SOCK_QUIC_STREAM);
    /* stream is directly ready */
    return ms_sock_stream->sk.sockfd;
}


ssize_t msquic_read(int fd, void *buf, size_t count) {
    struct msquic_socket *ms_sock;
    uint64_t offset;

    if (!(ms_sock = (struct msquic_socket *) get_sock(ALL_SOCKS, fd))) {
        return -1;
    }

    if (!IS_SET(ms_sock->flags, SOCK_QUIC_STREAM)) {
        /* we only handle streams for now. Datagram maybe later */
        fprintf(stderr, "Not a QUIC stream\n");
        return -1;
    }

    if (IS_SET(ms_sock->flags, SOCK_STOP)) {
        return 0;
    }

    if (!CxPlatEventWaitWithTimeout(ms_sock->r_evt, 0)) {
        errno = EAGAIN;
        return -1;
    }


    offset = 0;
    size_t room;
    room = count < ms_sock->buf_length ? count : ms_sock->buf_length;
    memcpy(buf + offset, ms_sock->buf, room);
    offset += room;

    /* we consume data */
    if (offset > 0 && eventfd_wait(ms_sock->sk.sockfd, READ_OFF, NULL) != 0) {
        perror("event_wait");
        return -1;
    }

    msquic->StreamReceiveComplete(ms_sock->stream, offset);
    msquic->StreamReceiveSetEnabled(ms_sock->stream, TRUE);

    return offset;
}

/*
 * due to socket API and MSQUIC abstraction,
 * the buffer buf is copied to an internal MSQUIC
 * buffer before passing it to the MsQUIC stack
 */
ssize_t msquic_write(int fd, const void *buf, size_t count) {
    int status;
    struct msquic_socket *ms_sock;
    static QUIC_BUFFER qbuf = {0};

    if (!(ms_sock = (struct msquic_socket *) get_sock(ALL_SOCKS, fd))) {
        return -1;
    }

    if (!IS_SET(ms_sock->flags, SOCK_QUIC_STREAM)) {
        fprintf(stderr, "Not a quic stream\n");
        /* we only handle streams for now. Datagram maybe later */
        return -1;
    }

    if (IS_SET(ms_sock->flags, SOCK_STOP)) {
        return -1;
    }



    qbuf.Length = count;
    qbuf.Buffer = (uint8_t *) buf;

    if (QUIC_FAILED(status = msquic->StreamSend(ms_sock->stream, &qbuf, 1, QUIC_SEND_FLAG_NONE, ms_sock))) {
        fprintf(stderr, "StreamSend failed (0x%x)! %s", status, QuicStatusToString(status));
        return -1;
    }

    CxPlatEventWaitForever(ms_sock->w_evt);
    return qbuf.Length;
}


static inline int msquic_close__(int fd) {
    struct common_sock *_ms_sock;
    struct msquic_socket *ms_sock;

    _ms_sock = get_sock(ALL_SOCKS, fd);
    if (!_ms_sock) {
        return -1;
    }
    ms_sock = (struct msquic_socket *) _ms_sock;

    SET_FLAG(ms_sock->flags, SOCK_STOP);

    if (ms_sock->stream && !IS_SET(ms_sock->flags, CLOSED)) {
        msquic->StreamShutdown(ms_sock->stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
    }
    if (ms_sock->listener) {
        msquic->ListenerClose(ms_sock->listener);
    }
    if (ms_sock->connection) {
        msquic->ConnectionShutdown(ms_sock->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }

    sh_ref_unlock(ms_sock->configuration);

    del_sock(ALL_SOCKS, _ms_sock);
    return 0;
}

int msquic_close(int fd) {
    assert(fd >= 0);
    return msquic_close__(fd);
}


int msquic_getsockname(int fd, struct sockaddr *addr, socklen_t *restrict len) {
    struct msquic_socket *ms_sock;
    QUIC_ADDR local_addr;
    uint32_t local_addr_len;
    QUIC_STATUS status;

    ms_sock = (struct msquic_socket *) get_sock(ALL_SOCKS, fd);
    if (!ms_sock) {
        return -1;
    }

    local_addr_len = sizeof(local_addr);

    if (ms_sock->listener) {
        status = msquic->GetParam(ms_sock->listener, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &local_addr_len, &local_addr);
        if (QUIC_FAILED(status)) {
            errno = EBADF;
            return -1;
        }
    } else if (ms_sock->connection) {
        status = msquic->GetParam(ms_sock->connection, QUIC_PARAM_CONN_LOCAL_ADDRESS, &local_addr_len, &local_addr);
        if (QUIC_FAILED(status)) {
            errno = EBADF;
            return -1;
        }
    } else {
        errno = EOPNOTSUPP;
        return -1;
    }

    return msquic_addr_to_sockaddr(&local_addr, addr, len);
}