//
// Created by thomas on 12/12/22.
//

#ifndef QUIC_SOCK_UTIL_WAIT_QUEUE_H
#define QUIC_SOCK_UTIL_WAIT_QUEUE_H

#include <stddef.h>
#include <pthread.h>
#include <semaphore.h>

// #include "ring-buffer/ring_buffer.h"
#include "ring-buffer/webrtc_ring_buf.h"
#include "util_var_sem.h"

struct wait_queue {
    pthread_mutex_t lock;
    pthread_cond_t cond_free;
    pthread_cond_t cond_full;

    size_t curr_length;
    size_t len;
    //ring_buffer_t r_buf;
    RingBuffer *r_buf;
};

int wait_queue_init(struct wait_queue *w_queue, size_t buf_len);

void wait_queue_release(struct wait_queue *w_queue);

int wait_queue_push(struct wait_queue *wait_queue, const void *data, size_t len);

unsigned int wait_queue_pop(struct wait_queue *wait_queue, void *data, size_t len);

int wait_queue_has_data(struct wait_queue *w_queue);

size_t wait_queue_size(struct wait_queue *w_queue);

size_t wait_queue_available_size(struct wait_queue *wait_queue);

#endif //QUIC_SOCK_UTIL_WAIT_QUEUE_H
