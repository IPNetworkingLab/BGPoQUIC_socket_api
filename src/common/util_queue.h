//
// Created by thomas on 5/07/22.
//

#ifndef QUIC_SOCK_UTIL_QUEUE_H
#define QUIC_SOCK_UTIL_QUEUE_H

#include <stddef.h>
#include <pthread.h>

struct queue_node {
    struct queue_node *prev, *next;
    size_t data_len;
    char *data;
};

struct q_queue {
    _Atomic int elem;
    pthread_mutex_t lock;
    struct queue_node *q;
};

typedef int queue_cb_iter(void *elem);

void queue_init(struct q_queue *q);

int queue_add(struct q_queue *q, const void *data, size_t data_len);

int queue_remove(struct q_queue *q, void *data, size_t data_len);

int queue_push(struct q_queue *q, void *data, size_t data_len);

int queue_pop(struct q_queue *q, void *data, size_t data_len);

int queue_pop_stream(struct q_queue *q, void *data, size_t data_len);

int queue_has_data(struct q_queue *q);

size_t queue_peek(struct q_queue *q, void **data);

void queue_for_each(struct q_queue *q, queue_cb_iter *callback);

void queue_flush(struct q_queue *q);

#endif //QUIC_SOCK_UTIL_QUEUE_H
