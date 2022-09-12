//
// Created by thomas on 6/07/22.
//

#ifndef QUIC_SOCK_TEST_MAIN_H
#define QUIC_SOCK_TEST_MAIN_H

#include <CUnit/CUnit.h>


extern const char *test_directory;
extern const char *python_interpreter;
extern const char *certs_dir;
extern const char *root_ca_name;
extern const char *pkey_name;
extern const char *cert_name;
extern const char *server_sni;
extern const char *client_cert_name;
extern const char *client_pkey_name;

typedef CU_ErrorCode (suite_init_fn)(CU_pSuite, const char **err_msg);

struct suite {
    const char *suite_name;
    CU_InitializeFunc setup;
    CU_InitializeFunc teardown;
    suite_init_fn *fn_add;
};

#define is_suite_null(suite) (((suite)->suite_name == NULL) && \
                              ((suite)->setup == NULL) && \
                              ((suite)->teardown == NULL) && \
                              ((suite)->fn_ass == NULL))

#endif //QUIC_SOCK_TEST_MAIN_H
