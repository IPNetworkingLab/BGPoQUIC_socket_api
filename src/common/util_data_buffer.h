//
// Created by thomas on 5/07/22.
//

#ifndef QUIC_SOCK_UTIL_DATA_BUFFER_H
#define QUIC_SOCK_UTIL_DATA_BUFFER_H

#include <stddef.h>
#include <pthread.h>
#include "util_var_sem.h"

struct q_buffer {
    size_t size;
    pthread_mutex_t lock;
    var_sem_t full;
    var_sem_t empty;
    unsigned char *buf;
    unsigned char *pos;
    unsigned char *end;
};

#define buffer_len(q_buf) ((size_t) ((q_buf)->pos - (q_buf)->buf))

void buffer_init(struct q_buffer *q_buf, void *buf, size_t buf_size);

size_t buffer_has_space(struct q_buffer *q_buf, size_t len);

size_t buffer_write(struct q_buffer *q_buf, const void *data, size_t data_len);

size_t buffer_read(struct q_buffer *q_buf, void *data, size_t len);

void *buffer_get_data(struct q_buffer *q_buf, size_t *len);

void buffer_reset(struct q_buffer *q_buf);

int buffer_lock(struct q_buffer *q_buf);

int buffer_unlock(struct q_buffer *q_buf);

size_t buffer_read_blk(struct q_buffer *q_buf, void *data, size_t len);

size_t buffer_write_blk(struct q_buffer *q_buf, const void *data, size_t len);

#endif //QUIC_SOCK_UTIL_DATA_BUFFER_H
