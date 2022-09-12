//
// Created by thomas on 11/07/22.
//

#include "test_queue.h"
#include "test_main.h"

#include <stddef.h>
#include <CUnit/CUnit.h>
#include <stdint.h>

#include <common/util_queue.h>

static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

static void test_queue(void) {
    struct q_queue q;
    size_t i, size;
    uint64_t received_data;
    uint64_t simple_data[] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
    };
    int status;

    queue_init(&q);

    size = sizeof(simple_data) / sizeof(simple_data[0]);
    for (i = 0; i < size; i++) {
        status = queue_add(&q, &simple_data[i], sizeof(simple_data[i]));
        CU_ASSERT_EQUAL(status, 0);
    }

    for (i = 0; i < size; i++) {
        status = queue_pop(&q, &received_data, sizeof(received_data));
        CU_ASSERT_EQUAL(status, 0);
    }

}


static void test_queue_empty(void) {
    struct q_queue q;
    unsigned char buf[64];
    unsigned char recv_buf[64];
    size_t i;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = 'a' + i;
    }

    queue_init(&q);

    CU_ASSERT_EQUAL(queue_pop(&q, recv_buf, sizeof(recv_buf)), -1);
    CU_ASSERT_EQUAL(queue_pop(&q, recv_buf, sizeof(recv_buf)), -1);
    CU_ASSERT_EQUAL(queue_add(&q, buf, sizeof(buf)), 0);
    CU_ASSERT_EQUAL(queue_pop(&q, recv_buf, sizeof(recv_buf)), 0);
    CU_ASSERT_EQUAL(memcmp(buf, recv_buf, sizeof(buf)), 0);
    CU_ASSERT_EQUAL(queue_pop(&q, recv_buf, sizeof(recv_buf)), -1);
}

static CU_ErrorCode test_queue_init(CU_pSuite suite, const char **err_msg) {
    if ((NULL == CU_add_test(suite, "queue add/pop", test_queue)) ||
        (NULL == CU_add_test(suite, "queue_pop empty", test_queue_empty))) {
        *err_msg = CU_get_error_msg();
        return CU_get_error();
    }

    return CUE_SUCCESS;
}

const struct suite test_queue_suite = {
        .suite_name = "QUIC Queue",
        .setup = setup,
        .teardown = teardown,
        .fn_add = test_queue_init
};
