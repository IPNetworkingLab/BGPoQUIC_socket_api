
set(QUICSOCK_API_HEADERS
        quic_sock/msquic_sock_api.h
        quic_sock/picoquic_sock_api.h
        quic_sock/sock_api_common.h)

install(FILES
        ${QUICSOCK_API_HEADERS}
        DESTINATION include/quic_sock)