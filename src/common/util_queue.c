//
// Created by thomas on 5/07/22.
//

#include "util_queue.h"

#include <pthread.h>

#include "utlist.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void queue_init(struct q_queue *q) {
    if (!q) return;

    memset(q, 0, sizeof(*q));

    *q = (struct q_queue) {
            .lock = PTHREAD_MUTEX_INITIALIZER,
            .q = NULL,
            .elem = 0,
    };
}

enum {
    AT_BEGINNING = 0,
    AT_END = 1,
};

static inline int queue_insert(struct q_queue *q, const void *data, size_t data_len, int at_end) {
    struct queue_node *pdt;

    pdt = malloc(sizeof(*pdt) + data_len);
    if (!pdt) return -1;

    pdt->data = (char *) (pdt + 1);

    memcpy(pdt->data, data, data_len);
    pdt->data_len = data_len;

    if (pthread_mutex_lock(&q->lock) != 0) { return -1; }

    if (at_end) {
        DL_APPEND(q->q, pdt);
    } else {
        DL_PREPEND(q->q, pdt);
    }
    q->elem += 1;
    if (pthread_mutex_unlock(&q->lock) != 0) { return -1; }

    return 0;
}

int queue_add(struct q_queue *q, const void *data, size_t data_len) {
    return queue_insert(q, data, data_len, AT_END);
}

int queue_push(struct q_queue *q, void *data, size_t data_len) {
    return queue_insert(q, data, data_len, AT_BEGINNING);
}

int queue_remove(struct q_queue *q, void *data, size_t data_len) {
    int ret;
    struct queue_node *q_node;
    struct queue_node *q_node_tmp;

    ret = -1;

    if (pthread_mutex_lock(&q->lock) != 0) { return -1; }
    DL_FOREACH_SAFE(q->q, q_node, q_node_tmp) {
        if (memcmp(data, q_node->data, data_len) == 0) {
            DL_DELETE(q->q, q_node);
            ret = 0;
            q->elem -= 1;
            goto fin;
        }
    }
    fin:
    if (pthread_mutex_unlock(&q->lock) != 0) { return -1; }
    return ret;
}

int queue_pop(struct q_queue *q, void *data, size_t data_len) {
    struct queue_node *pdt;

    if (pthread_mutex_lock(&q->lock) != 0) { return -1; }

    if (!q->q) {
        /* no data */
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    pdt = q->q;
    if (pdt->data_len < data_len) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    DL_DELETE(q->q, pdt);
    q->elem -= 1;
    if (pthread_mutex_unlock(&q->lock) != 0) { return -1; }

    if (data) memcpy(data, pdt->data, pdt->data_len);
    free(pdt);

    return 0;
}

int queue_pop_stream(struct q_queue *q, void *data, size_t data_len) {
    struct queue_node *pdt;
    int usr_buf_too_small;
    int should_delete;
    size_t max_read;
    char *pdt_cpy_usr;

    usr_buf_too_small = 0;
    should_delete = 0;

    if (pthread_mutex_lock(&q->lock) != 0) { return -1; }

    if (!q->q) {
        /* no data */
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    pdt = q->q;
    pdt_cpy_usr = pdt->data;
    if (pdt->data_len > data_len) {
        usr_buf_too_small = 1;
        max_read = data_len;
    } else {
        max_read = pdt->data_len;
    }
    //max_read = pdt->data_len > data_len ? data_len : pdt->data_len;

    pdt->data_len -= max_read;

    if (usr_buf_too_small) {
        /* update data pointer but don't
         * delete elem from the queue */
        //pdt->data_len -= max_read;
        pdt->data += max_read;
    }

    if (pdt->data_len <= 0) {
        should_delete = 1;
        DL_DELETE(q->q, pdt);
        q->elem -= 1;
    }

    if (pthread_mutex_unlock(&q->lock) != 0) { return -1; }

    if(data) memcpy(data, pdt_cpy_usr, max_read);

    if (should_delete)
        free(pdt);

    return max_read;
}


int queue_has_data(struct q_queue *q) {
    return q->elem > 0;
}

size_t queue_peek(struct q_queue *q, void **data) {
    size_t size;
    if (!queue_has_data(q)) {
        if (data) *data = NULL;
        return 0;
    }

    if (pthread_mutex_lock(&q->lock) != 0) { return -1; }

    if (data) *data = q->q->data;
    size = q->q->data_len;

    if (pthread_mutex_unlock(&q->lock) != 0) { return -1; }

    return size;
}

void queue_for_each(struct q_queue *q, queue_cb_iter *callback) {
    struct queue_node *q_node;
    struct queue_node *q_node_tmp;

    if (pthread_mutex_lock(&q->lock) != 0) { return; }
    DL_FOREACH_SAFE(q->q, q_node, q_node_tmp) {
        if (callback(q_node->data) != 0) {
            break;
        }
    }
    if (pthread_mutex_unlock(&q->lock) != 0) { return; }

}


void queue_flush(struct q_queue *q) {
    struct queue_node *q_node;
    struct queue_node *q_node_tmp;

    if (pthread_mutex_lock(&q->lock) != 0) { return; }
    DL_FOREACH_SAFE(q->q, q_node, q_node_tmp) {
        DL_DELETE(q->q, q_node);
        free(q_node);
    }
    if (pthread_mutex_unlock(&q->lock) != 0) { return; }
}