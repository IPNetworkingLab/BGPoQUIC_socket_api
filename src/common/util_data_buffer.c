//
// Created by thomas on 5/07/22.
//

#include "util_data_buffer.h"
#include "util_common_sock.h"
#include <assert.h>
#include <string.h>
#include <stdint.h>


#define max_read(q_buf, len) (((q_buf)->buf + (len)) <=  (q_buf)->pos ? (len) : (size_t)((q_buf)->pos - (q_buf)->buf))

void buffer_init(struct q_buffer *q_buf, void *buf, size_t buf_size) {
    uint8_t *c_buf;

    if (!q_buf) return;
    c_buf = buf;

    *q_buf = (struct q_buffer) {
            .buf = c_buf,
            .size = buf_size,
            .pos = c_buf,
            .end = c_buf + buf_size,
            .lock = PTHREAD_MUTEX_INITIALIZER
    };

    var_sem_init(&q_buf->empty, buf_size);
    var_sem_init(&q_buf->full, 0);
}

size_t buffer_has_space(struct q_buffer *q_buf, size_t len) {
    if (!q_buf) return 0;
    if (!q_buf->buf) return 0;

    return (q_buf->pos + len) <= q_buf->end ? len : (size_t) (q_buf->end - q_buf->pos);
}

size_t buffer_write(struct q_buffer *q_buf, const void *data, size_t data_len) {
    size_t nb_written;

    if (!(nb_written = buffer_has_space(q_buf, data_len))) return 0;

    memcpy(q_buf->pos, data, nb_written);

    q_buf->pos += nb_written;
    return nb_written;
}

size_t buffer_read(struct q_buffer *q_buf, void *data, size_t len) {
    size_t nb_read;
    unsigned char *consumed;

    nb_read = max_read(q_buf, len);
    memcpy(data, q_buf->buf, nb_read);

    /*
     * If the buffer is not totally flushed,
     * should memmove the remaining data to
     * the beginning of the buffer
     */
    if (buffer_len(q_buf) > nb_read) {
        consumed = q_buf->buf + nb_read;
        memmove(q_buf->buf, consumed, q_buf->pos - consumed);
    }
    q_buf->pos -= nb_read;

    assert(q_buf->buf <= q_buf->pos);
    return nb_read;
}


void *buffer_get_data(struct q_buffer *q_buf, size_t *len) {
    if (len) *len = buffer_len(q_buf);
    return q_buf->buf;
}

void buffer_reset(struct q_buffer *q_buf) {
    q_buf->pos = q_buf->buf;
}

int buffer_lock(struct q_buffer *q_buf) {
    return pthread_mutex_lock(&q_buf->lock);
}

int buffer_unlock(struct q_buffer *q_buf) {
    return pthread_mutex_unlock(&q_buf->lock);
}

size_t buffer_read_blk(struct q_buffer *q_buf, void *data, size_t len) {
    size_t effective_read;
    size_t nb_read = max_read(q_buf, len);

    var_sem_wait(&q_buf->full, nb_read);
    buffer_lock(q_buf);

    effective_read = buffer_read(q_buf, data, nb_read);
    assert(effective_read == nb_read);
    unused__(effective_read);

    buffer_unlock(q_buf);
    var_sem_post(&q_buf->empty, nb_read);

    return nb_read;
}

size_t buffer_write_blk(struct q_buffer *q_buf, const void *data, size_t len) {
    size_t nb_written;
    size_t tot_written;

    if (!(nb_written = buffer_has_space(q_buf, len))) return 0;

    var_sem_wait(&q_buf->empty, nb_written);
    buffer_lock(q_buf);

    tot_written = buffer_write(q_buf, data, nb_written);
    assert(tot_written == nb_written);
    unused__(tot_written);

    buffer_unlock(q_buf);
    var_sem_post(&q_buf->full, nb_written);

    return nb_written;
}