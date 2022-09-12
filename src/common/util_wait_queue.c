//
// Created by thomas on 12/12/22.
//

#include "util_wait_queue.h"

#include <stddef.h>
#include <string.h>
#include <assert.h>
#include "ring-buffer/webrtc_ring_buf.h"
#include "util_var_sem.h"
#include "util_common_sock.h"

int wait_queue_init(struct wait_queue *w_queue, size_t buf_len) {
    memset(w_queue, 0, sizeof(*w_queue));

    if (!POWER_2(buf_len)) {
        return -1;
    }

    *w_queue = (struct wait_queue) {
            .lock = PTHREAD_MUTEX_INITIALIZER,
            .cond_free = PTHREAD_COND_INITIALIZER,
            .cond_full = PTHREAD_COND_INITIALIZER,
            .curr_length = 0,
            .len = buf_len,
            .r_buf = WebRtc_CreateBuffer(buf_len, 1),
    };

    if (!w_queue->r_buf) {
        return -1;
    }

    //ring_buffer_init(&w_queue->r_buf, w_queue->len);

    return 0;
}

int wait_queue_push(struct wait_queue *wait_queue, const void *data, size_t len) {
    size_t written_len;

    //available_length = wait_queue->len - wait_queue->curr_length;
    //assert(available_length >= 0);

    // if (available_length == 0) { return 0; }

    /* data is too large to fit in the wait queue */
    if (len > wait_queue->len) {
        return -1;
    }

    pthread_mutex_lock(&wait_queue->lock);
    while (wait_queue->curr_length > wait_queue->len - len) {
        pthread_cond_wait(&wait_queue->cond_full, &wait_queue->lock);
    }

    written_len = WebRtc_WriteBuffer(wait_queue->r_buf, data, len);
    assert(written_len == len);
    unused__(written_len);

    //ring_buffer_push(&wait_queue->r_buf, data, len);
    wait_queue->curr_length += len;

    pthread_mutex_unlock(&wait_queue->lock);
    pthread_cond_signal(&wait_queue->cond_free);

    return 0;
}

unsigned int wait_queue_pop(struct wait_queue *wait_queue, void *data, size_t len) {
    size_t req_len;
    size_t pop_len;


    pthread_mutex_lock(&wait_queue->lock);

    while (!wait_queue->curr_length) {
        pthread_cond_wait(&wait_queue->cond_free, &wait_queue->lock);
    }
    req_len = MIN(len, wait_queue->curr_length);

    pop_len = WebRtc_ReadBuffer(wait_queue->r_buf, NULL, data, req_len);
    //pop_data = ring_buffer_pop(&wait_queue->r_buf, &pop_len);
    //memcpy(data, pop_data, pop_len);

    //assert(pop_len == req_len);
    wait_queue->curr_length -= pop_len;

    pthread_mutex_unlock(&wait_queue->lock);

    pthread_cond_signal(&wait_queue->cond_full);
    return pop_len;
}

int wait_queue_has_data(struct wait_queue *w_queue) {
    return w_queue->curr_length > 0;
}

size_t wait_queue_size(struct wait_queue *w_queue) {
    return w_queue->curr_length;
}

size_t wait_queue_available_size(struct wait_queue *wait_queue) {
    return wait_queue->len - wait_queue->curr_length;
}