//
// Created by thomas on 4/10/22.
//

#ifndef QUIC_SOCK_UTIL_VAR_SEM_H
#define QUIC_SOCK_UTIL_VAR_SEM_H

#include <pthread.h>
#include <stdint.h>

typedef struct var_sem var_sem_t;

/**
 * Semaphore that can be incremented
 * or decremented with arbitrary values.
 */
struct var_sem {
    pthread_mutex_t mtx; /**< Guard mutex for the condition variable cnd */
    pthread_cond_t cnd; /**< Condition variable */
    _Atomic uint64_t var_int; /**< Internal semaphore value */
    _Atomic int signaled; /**< denotes if the semaphore has been signaled */
};

/**
 * Initialize a semaphore.
 * @param sem The semaphore to initialize
 * @param val The initial value for the semaphore
 * @return 0
 */
int var_sem_init(var_sem_t *sem, uint64_t val);

/**
 * Increments by inc the semaphore pointed by sem
 * @param sem The semaphore to be incremented
 * @param inc The increment to add to the current
 *            semaphore value
 * @return 0 on success. Any other value on failure.
 */
int var_sem_post(var_sem_t *sem, uint64_t inc);

/**
 * Decrements by dec the semaphore pointed by sem.
 * The function blocks until it become possible to
 * do the decrement.
 * @param sem the semaphore to be decremented
 * @param dec The decrement value to subtract to the
 *            semaphore value
 * @return 0 on success. Any other value is returned on failure
 */
int var_sem_wait(var_sem_t *sem, uint64_t dec);

/**
 * Get the internal semaphore value
 * @param sem The semaphore
 * @return The internal semaphore value of sem
 */
uint64_t var_sem_get(var_sem_t *sem);

#endif //QUIC_SOCK_UTIL_VAR_SEM_H
