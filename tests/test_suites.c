//
// Created by thomas on 6/07/22.
//

#include "test_suites.h"

#include "test_main.h"
#include "test_buffer.h"
#include "test_queue.h"
#include "test_eventfd.h"
#include "test_msquic_sock_api.h"
#include "test_picoquic_sock_api.h"

#include <stddef.h>

/* add here all test suites */
const struct suite *const all_suites[] = {
        /* add here all test suites */
        &test_buffer_suite,
        &test_queue_suite,
        &test_eventfd_suite,
        &test_msquic_sock_api_suite,
        &test_picoquic_sock_api_suite,
        /* end suites */
};

const size_t nb_all_suites = sizeof(all_suites) / sizeof(all_suites[0]);