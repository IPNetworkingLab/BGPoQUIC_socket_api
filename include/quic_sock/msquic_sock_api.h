/** \file */
//
// Created by thomas on 5/07/22.
//

#ifndef QUIC_SOCK_MSQUIC_SOCK_API_H
#define QUIC_SOCK_MSQUIC_SOCK_API_H

#include <stdlib.h>
#include <sys/socket.h>
#include "sock_api_common.h"

/**
 * Initialize the MsQuic API.
 * This call must be done before using any other MsQuic
 * API functions !
 * @param app_name The name of the application using the API
 * @return 0 if the initialization succeeds
 *        -1 otherwise
 */
int msquic_init(const char *app_name);

/**
 * Creates an endpoint for a QUIC communication
 * @return In case of success, it returns a >= 0 file descriptor on the
 *         new MsQuic socket created. On failure, -1 is returned.
 */
int msquic_socket(void);

/**
 * Binds an address for a socket
 * @param sockfd bind the address contained in "addr" in the
 *               file descriptor
 * @param addr The address that will be used to bind the file descriptor
 * @param addrlen Size in bytes of the addr
 * @return 0 is returned on success. -1, on errors
 */
int msquic_bind(int sockfd,
                const struct sockaddr *addr,
                socklen_t addrlen);

/**
 * Listen for connections on a socket
 * @param sockfd MsQuic file descriptor
 * @param tls_config The tls configuration for the listening socket.
 * tls_config must point to a valid tls configuration and thus
 * must not be NULL.
 * @see struct tls_config to know how to use this structure.
 * @endcode
 * @return 0, on success. -1 on failure.
 */
int msquic_listen(int sockfd,
                  struct tls_config *tls_config);

/**
 * Accept a new QUIC connection for a remote peer;
 * @param socket the listening file descriptor
 * @param address will be filled by the function with the address
 *                of the peer.
 * @param address_len The length of the sockaddr address structure
 * @return
 */
int msquic_accept(int socket,
                  struct sockaddr *restrict address,
                  socklen_t *restrict address_len);

/**
 * Accept a new stream from a remote peer.
 * @param socket The connected listening stream. The file descriptor
 *               must be created with the msquic_listen_stream function
 * @return a file descriptor representing the QUIC stream.
 *         Returns -1 on error.
 */
int msquic_accept_stream(int socket);

/**
 * Opens a new QUIC stream
 * @param socket The connected QUIC file descriptor.
 * @return The file descriptor representing the created QUIC stream.
 *         On error, returns -1.
 */
int msquic_open_stream(int socket);

/**
 * Initiate a connection on a socket
 * @param sockfd a freshly created socket (msquic_socket)
 * @param addr Connect the socket with the address of the remote peer
 * @param addrlen the size of the sockaddr addr structure
 * @param tls_config The tls configuration for this socket.
 * @see struct tls_config to know how to use this structure
 * @return 0 on success, -1 on error.
 */
int msquic_connect(int sockfd,
                   const struct sockaddr *addr,
                   socklen_t addrlen,
                   struct tls_config *tls_config);
/**
 * Read from a MsQUIC stream file descriptor
 * @param fd The
 * @param buf
 * @param count
 * @return
 */
ssize_t msquic_read(int fd,
                    void *buf,
                    size_t count);

/**
 * Write to a MsQUIC stream file descriptor
 * @param fd
 * @param buf
 * @param count
 * @return
 */
ssize_t msquic_write(int fd,
                     const void *buf,
                     size_t count);
/**
 * Closes any file descriptor related to the QUIC socket API.
 * @param fd The file descriptor to close.
 * @return 0 on success, -1 on error.
 */
int msquic_close(int fd);

/**
 * Returns the current address to which the socket fd is bound
 * @param fd the connected file descriptor
 * @param addr Fill the address in the sockaddr addr
 *             structure on which fd is bound
 * @param len On input, the length of the sockaddr addr structure.
 *            On output, the effective length of the sockaddr structure
 * @return 0 on success, -1 on failure.
 */
int msquic_getsockname(int fd, struct sockaddr *addr, socklen_t *restrict len);

#endif //QUIC_SOCK_MSQUIC_SOCK_API_H
