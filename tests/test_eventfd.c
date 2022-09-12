//
// Created by thomas on 11/07/22.
//

#include "test_eventfd.h"
#include "test_main.h"
#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>

#include "common/util_eventfd.h"

#define TIMEOUT_BLOCK_MS 5000

static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

static void test_eventfd(void) {
    int efd, status;
    uint64_t cnt;
    efd = eventfd_new();
    CU_ASSERT_FATAL(efd >= 0);

    status = eventfd_post(efd, 123);
    CU_ASSERT_EQUAL_FATAL(status, 0)

    status = eventfd_wait(efd, 123, &cnt);
    CU_ASSERT_EQUAL_FATAL(status, 0);

    eventfd_close(efd);
}


static void test_eventfd_block(void) {
    int efd;
    int ret;
    struct pollfd pfds;

    efd = eventfd_new();
    CU_ASSERT_FATAL(efd >= 0);

    /* efd is by default non-blocking ! */
    pfds = (struct pollfd) {
            .fd = efd,
            .events = POLLIN,
    };

    /* eventfd should block */
    ret = poll(&pfds, 1, TIMEOUT_BLOCK_MS);
    switch (ret) {
        case -1: CU_FAIL("poll err");
            break;
        case 0:
            /* time out */
        CU_PASS("eventfd correctly block");
            break;
        default: CU_FAIL("eventfd should block");
            break;
    }


    /* Save the stack environment and the current signal mask */
    eventfd_close(efd);
}


static void test_eventfd_select(void) {
    int efd;
    int ret;
    struct pollfd pfds;
    int status;
    uint64_t counter;

    efd = eventfd_new();
    CU_ASSERT_FATAL(efd >= 0);

    /* efd is by default non blocking ! */
    pfds = (struct pollfd) {
            .fd = efd,
            .events = POLLIN,
    };

    eventfd_post(efd, 56);

    /* eventfd should block */
    ret = poll(&pfds, 1, TIMEOUT_BLOCK_MS);
    switch (ret) {
        case -1: CU_FAIL("poll err");
            break;
        case 0:
            /* time out */
        CU_PASS("eventds should not block");
            break;
        default:
            status = eventfd_wait(efd, 56, &counter);
            CU_ASSERT_EQUAL(status, 0);
            CU_ASSERT_EQUAL(counter, 0);
            break;
    }


    /* Save the stack environment and the current signal mask */
    eventfd_close(efd);
}


static void test_successive_post_wait(void) {
    struct pollfd pfd;
    uint64_t counter;
    int status;
    const int efd = eventfd_new();

    CU_ASSERT_FATAL(efd >= 0);

    status = eventfd_post(efd, 42);
    CU_ASSERT_EQUAL(status, 0);
    status = eventfd_post(efd, 58);
    CU_ASSERT_EQUAL(status, 0);

    pfd = (struct pollfd) {
            .fd = efd,
            .events = POLLIN,
    };

    status = poll(&pfd, 1, TIMEOUT_BLOCK_MS);

    switch (status) {
        case -1:
            /* poll error */
        CU_FAIL("poll call error");
            goto exit;
        case 0:
            /* timeout */
        CU_FAIL("efd should not block!");
            goto exit;
        default: CU_PASS("OK, event");
            break;
    }

    status = eventfd_wait(efd, 51, &counter);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(counter, 49);

    status = eventfd_post(efd, 789);
    CU_ASSERT_EQUAL(status, 0);

    status = eventfd_wait(efd, 838, &counter);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(counter, 0);

    /* now this should block */
    status = poll(&pfd, 1, TIMEOUT_BLOCK_MS);

    switch (status) {
        case -1:
            /* poll error */
        CU_FAIL("poll call error");
            goto exit;
        case 0:
            /* timeout */
        CU_PASS("efd correctly block!");
            /* the call should return an error (remember that efd is a non-blocking socket) */
            status = eventfd_wait(efd, 10, NULL);
            CU_ASSERT_EQUAL(status, -1);
            goto exit;
        default: CU_FAIL("KO, efd should block now !");
            break;
    }

    exit:

    status = eventfd_close(efd);
    CU_ASSERT_EQUAL(status, 0);
}

static CU_ErrorCode test_eventfd_init(CU_pSuite suite, const char **err_msg) {
    if ((NULL == CU_add_test(suite, "simple eventfd test", test_eventfd)) ||
        (NULL == CU_add_test(suite, "eventfd should block", test_eventfd_block)) ||
        (NULL == CU_add_test(suite, "eventfd select", test_eventfd_select)) ||
        (NULL == CU_add_test(suite, "eventfd successive calls", test_successive_post_wait))) {
        *err_msg = CU_get_error_msg();
        return CU_get_error();
    }

    return CUE_SUCCESS;
}


const struct suite test_eventfd_suite = {
        .suite_name = "QUIC Eventfd",
        .setup = setup,
        .teardown = teardown,
        .fn_add = test_eventfd_init
};
