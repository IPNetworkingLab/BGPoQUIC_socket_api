//
// Created by thomas on 7/07/22.
//

#ifndef QUIC_SOCK_UTIL_EVENTFD_H
#define QUIC_SOCK_UTIL_EVENTFD_H

#include <stdint.h>
#include <stddef.h>

int eventfd_new(void);

int eventfd_set_max_buf_size(int fd, uint64_t max_size);

int eventfd_block_write(int fd);

int eventfd_reset(int fd);

int eventfd_wait(int fd, size_t decrement, uint64_t *current_counter);

int eventfd_post(int fd, uint64_t increment);

int eventfd_close(int fd);

#endif //QUIC_SOCK_UTIL_EVENTFD_H
