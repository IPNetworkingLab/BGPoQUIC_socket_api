//
// Created by thomas on 8/07/22.
//

#include "test_buffer.h"
#include "test_main.h"

#include <CUnit/CUnit.h>

#include "common/util_data_buffer.h"

static int test_buffer_setup(void) {
    return 0;
}

static int test_buffer_teardown(void) {
    return 0;
}

static void test_simple_buffer_write(void) {
    const char dummy_data[] = "abcdefghijklmnopqrstuvwxyz1234567890";
    struct q_buffer q_buf;
    char buf[256];
    int dummy_data_len;
    size_t data_written;

    memset(buf, 0, sizeof(buf));

    dummy_data_len = sizeof(dummy_data);
    buffer_init(&q_buf, buf, sizeof(buf));

    data_written = buffer_write(&q_buf, dummy_data, dummy_data_len);

    CU_ASSERT_EQUAL(data_written, dummy_data_len);

    CU_ASSERT_STRING_EQUAL(buf, dummy_data);
}

static void test_simple_short_buffer(void) {
    struct q_buffer q_buf;
    const char long_word[] = "this_is_an_extra_long_word";
    const char *expected_write = "this_";
    char mini_buf[5];
    size_t bytes_written;

    memset(mini_buf, 0, sizeof(mini_buf));

    buffer_init(&q_buf, mini_buf, sizeof(mini_buf));

    bytes_written = buffer_write(&q_buf, long_word, sizeof(long_word));

    CU_ASSERT_EQUAL(bytes_written, sizeof(mini_buf));

    CU_ASSERT_NSTRING_EQUAL(mini_buf, expected_write, 5);
}

static void test_short_buffer_no_overflow(void) {
    struct q_buffer q_buf;
    const char long_number[] = "0123456789ABCDE";
    const char *expected_write = "01234";
    char mini_buf[6];
    size_t bytes_written;

    memset(mini_buf, 0, sizeof(mini_buf));
    buffer_init(&q_buf, mini_buf, sizeof(mini_buf) - 1);

    bytes_written = buffer_write(&q_buf, long_number, sizeof(long_number));

    CU_ASSERT_EQUAL(bytes_written, sizeof(mini_buf) - 1);
    CU_ASSERT_STRING_EQUAL(mini_buf, expected_write);
    CU_ASSERT_EQUAL(mini_buf[sizeof(mini_buf) - 1], 0);

}

static void test_no_further_write(void) {
    struct q_buffer q_buf;
    char mini_buf[8];
    const char full[] = "one";
    size_t bytes_written;

    buffer_init(&q_buf, mini_buf, 4);

    bytes_written = buffer_write(&q_buf, full, sizeof(full));
    CU_ASSERT_EQUAL(bytes_written, sizeof(full));
    CU_ASSERT_STRING_EQUAL(mini_buf, full);

    bytes_written = buffer_write(&q_buf, full, sizeof(full));
    CU_ASSERT_EQUAL(bytes_written, 0);
}

static void test_incremental_write(void) {
    struct q_buffer q_buf;
    const char full_word[] = "The water flowing down the river "
                             "didn't look that powerful from the car";
    size_t i;
    char buf[128];
    size_t bytes_written;

    buffer_init(&q_buf, buf, sizeof(buf));

    for (i = 0; i < sizeof(full_word); i++) {
        bytes_written = buffer_write(&q_buf, &full_word[i], 1);
        CU_ASSERT_EQUAL(bytes_written, 1);
        CU_ASSERT_NSTRING_EQUAL(buf, full_word, i);
    }

    CU_ASSERT_STRING_EQUAL(buf, full_word);
}

static void test_full_read(void) {
    struct q_buffer q_buf;
    const char buf[] = "The waves were crashing on the shore; "
                       "it was a lovely sight.";
    char int_buf[sizeof(buf)];
    char recv_buf[sizeof(buf) + 3];
    size_t bytes_read;
    size_t bytes_written;

    memset(recv_buf, 0, sizeof(recv_buf));
    memset(int_buf, 0, sizeof(int_buf));

    buffer_init(&q_buf, int_buf, sizeof(int_buf));
    bytes_written = buffer_write(&q_buf, buf, sizeof(buf));
    CU_ASSERT_EQUAL_FATAL(bytes_written, sizeof(buf));
    CU_ASSERT_STRING_EQUAL(int_buf, buf);

    bytes_read = buffer_read(&q_buf, recv_buf, sizeof(recv_buf));

    CU_ASSERT_EQUAL(bytes_read, sizeof(buf));
    CU_ASSERT_STRING_EQUAL(recv_buf, buf);
}

static void test_nothing_to_read(void) {
    struct q_buffer q_buf;
    const char shadow_buf[] = "ctrl.";
    char buf[] = "ctrl.";
    const char shadow_recv_buf[] = "The cake is a lie";
    char recv_buf[] = "The cake is a lie";
    size_t bytes_read;

    buffer_init(&q_buf, buf, sizeof(buf));
    bytes_read = buffer_read(&q_buf, recv_buf, sizeof(recv_buf));

    CU_ASSERT_EQUAL(bytes_read, 0);

    /* buf and recv_buf should not be altered */
    CU_ASSERT_STRING_EQUAL(recv_buf, shadow_recv_buf);
    CU_ASSERT_STRING_EQUAL(buf, shadow_buf);

}

static void test_incremental_read(void) {
    struct q_buffer q_buf;
    const char sentence[] = "He had decided to accept his fate of accepting his fate.";
    char buf[sizeof(sentence) + 5];
    char recv_buf[sizeof(sentence)];
    size_t bytes_read;
    size_t bytes_written;
    size_t i;

    memset(buf, 0, sizeof(buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    buffer_init(&q_buf, buf, sizeof(buf));
    bytes_written = buffer_write(&q_buf, sentence, sizeof(sentence));

    CU_ASSERT_EQUAL_FATAL(bytes_written, sizeof(sentence));
    for (i = 0; i < sizeof(sentence); i++) {
        bytes_read = buffer_read(&q_buf, &recv_buf[i], 1);
        CU_ASSERT_EQUAL(bytes_read, 1);
        CU_ASSERT_EQUAL(recv_buf[i], sentence[i]);
    }

    CU_ASSERT_STRING_EQUAL(recv_buf, sentence);

    bytes_read = buffer_read(&q_buf, recv_buf, sizeof(recv_buf));
    CU_ASSERT_EQUAL(bytes_read, 0);
}

static void test_mix_read_write(void) {
    struct q_buffer q_buf;
    size_t offset;
    const char full_sentence[] = "abcdefghijklmnopqrstuvhxyz01";
    char buf[128];
    char recv_buffer[sizeof(full_sentence)];
    size_t bytes_read;
    size_t bytes_written;

    offset = 0;
    memset(buf, 0, sizeof(buf));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    buffer_init(&q_buf, buf, sizeof(buf));

    bytes_written = buffer_write(&q_buf, &full_sentence[offset], 8);
    CU_ASSERT_EQUAL(bytes_written, 8);
    offset += 8;
    bytes_read = buffer_read(&q_buf, recv_buffer, 4);
    CU_ASSERT_EQUAL(bytes_read, 4);
    CU_ASSERT_NSTRING_EQUAL(recv_buffer, full_sentence, 4);

    bytes_written = buffer_write(&q_buf, &full_sentence[offset], 16);
    CU_ASSERT_EQUAL(bytes_written, 16);
    offset += 16;

    bytes_read = buffer_read(&q_buf, &recv_buffer[4], 12);
    CU_ASSERT_EQUAL(bytes_read, 12);
    CU_ASSERT_NSTRING_EQUAL(recv_buffer, full_sentence, 16);

    bytes_written = buffer_write(&q_buf, &full_sentence[offset], 4);
    CU_ASSERT_EQUAL(bytes_written, 4);
    bytes_read = buffer_read(&q_buf, &recv_buffer[16], 12);
    CU_ASSERT_EQUAL(bytes_read, 12);
    CU_ASSERT_STRING_EQUAL(recv_buffer, full_sentence);
}

static CU_ErrorCode test_buffer_init(CU_pSuite suite, const char **err_msg) {
    if ((NULL == CU_add_test(suite, "Simple buffer write", test_simple_buffer_write)) ||
        (NULL == CU_add_test(suite, "Short buffer write", test_simple_short_buffer)) ||
        (NULL == CU_add_test(suite, "Buffer no overflow", test_short_buffer_no_overflow)) ||
        (NULL == CU_add_test(suite, "No further write", test_no_further_write)) ||
        (NULL == CU_add_test(suite, "Incremental write", test_incremental_write)) ||
        (NULL == CU_add_test(suite, "Full Read", test_full_read)) ||
        (NULL == CU_add_test(suite, "Nothing to read", test_nothing_to_read)) ||
        (NULL == CU_add_test(suite, "Incremental read", test_incremental_read)) ||
        (NULL == CU_add_test(suite, "Mix read/write", test_mix_read_write))) {
        *err_msg = CU_get_error_msg();
        return CU_get_error();
    }

    return CUE_SUCCESS;
}

const struct suite test_buffer_suite = {
        .suite_name="QUIC Buffer",
        .setup = test_buffer_setup,
        .teardown=test_buffer_teardown,
        .fn_add = test_buffer_init
};