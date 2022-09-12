//
// Created by thomas on 7/07/22.
//

#include "util_eventfd.h"

#include <stdio.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>


int eventfd_new(void) {
    int fd;

    fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) {
        perror("eventfd");
        return -1;
    }
    return fd;
}

int eventfd_set_max_buf_size(int fd, uint64_t max_size) {
    uint64_t initial_val;

    initial_val = (UINT64_MAX - 1) - max_size;

    if (eventfd_write(fd, initial_val) != 0) {
        return -1;
    }
    return 0;
}

int eventfd_block_write(int fd) {
    uint64_t counter;

    /* reset kernel internal counter to 0 */
    if (eventfd_read(fd, &counter) != 0) {
        if (errno != EAGAIN) {
            /* if the read should block,
             * this is not an error */
            return -1;
        }
    }

    /* write the maximum value to the buffer */
    return eventfd_write(fd, UINT64_MAX-1);
}

int eventfd_reset(int fd) {
    uint64_t counter;
    /* reset kernel internal counter to 0 */
    if (eventfd_read(fd, &counter) != 0) {
            /* if the read should block (EAGAIN),
             * because the counter is already at 0,
             * this is not an error */
        if (errno != EAGAIN) {
            return -1;
        }
    }
    return 0;
}

/* decrement */
int eventfd_wait(int fd, size_t decrement, uint64_t *current_counter) {
    uint64_t counter;

    if (eventfd_read(fd, &counter) != 0) {
        perror("read");
        return -1;
    }

    /* counter is reset to zero, so should rewrite
     * the counter to eventfd */
    if (counter < decrement) {
        /* try to decrement too much! */
        return -1;
    }

    counter -= decrement;
    if (current_counter) *current_counter = counter;

    /*
     * if 'counter' is already at 0
     * this is useless since read syscall
     * resets eventfd internal counter to 0
     */
    if (counter == 0) return 0;

    if (eventfd_write(fd, counter) != 0) {
        perror("write");
        return -1;
    }

    return 0;
}

/* increment */
int eventfd_post(int fd, uint64_t increment) {
    if (eventfd_write(fd, increment) != 0) {
        perror("write");
        return -1;
    }
    return 0;
}

int eventfd_close(int fd) {
    return close(fd);
}