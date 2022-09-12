//
// Created by thomas on 4/10/22.
//

#include <stdio.h>
#include <stdlib.h>
#include "util_var_sem.h"


int var_sem_init(var_sem_t *sem, uint64_t val) {
    *sem = (var_sem_t) {
        .mtx = PTHREAD_MUTEX_INITIALIZER,
        .cnd = PTHREAD_COND_INITIALIZER,
        .var_int = val,
        .signaled = 0,
    };

    return 0;
}

int var_sem_post(var_sem_t *sem, uint64_t inc) {
    int res;

    res = pthread_mutex_lock(&sem->mtx);
    if (res != 0) return res;

    if (sem->var_int > UINT64_MAX - inc) {
        /* overflow ! */
        goto end;
    }

    sem->signaled = 1;
    sem->var_int += inc;

    pthread_cond_broadcast(&sem->cnd);

    end:
    res = pthread_mutex_unlock(&sem->mtx);

    return res;
}

int var_sem_wait(var_sem_t *sem, uint64_t dec) {
    int res;

    res = pthread_mutex_lock(&sem->mtx);
    if (res != 0) goto end;

    do {
        if (sem->var_int >= dec) {
            sem->var_int -= dec;
            break;
        } else {
            while (!sem->signaled) {
                res = pthread_cond_wait(&sem->cnd, &sem->mtx);
                if (res != 0) {
                    fprintf(stderr, "pthread error\n");
                    fflush(stderr);
                    abort();
                }
            }

            sem->signaled = 0;
        }
    } while(1);

    res = pthread_mutex_unlock(&sem->mtx);
    end:
    return res;
}

uint64_t var_sem_get(var_sem_t *sem) {
    return sem->var_int;
}