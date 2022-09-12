//
// Created by thomas on 5/07/22.
//

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "test_main.h"
#include "test_suites.h"

const char *test_directory = NULL;
const char *python_interpreter = NULL;
const char *certs_dir = NULL;
const char *root_ca_name = NULL;
const char *pkey_name = NULL;
const char *cert_name = NULL;
const char *server_sni = NULL;
const char *client_cert_name = NULL;
const char *client_pkey_name = NULL;

static inline void usage(const char *prog) {
    fprintf(stderr, "usage: %s -p <test directory> -d <certs directory> -i <python_interpreter>\n"
                    "       -c <cert_name> -a <root_ca_name> -k <private_key_name> -s <server_sni>\n"
                    "       -a <client_certificate> -b <client_private_key>\n"
                    "    -p <test directory>: path to the test directory\n"
                    "    -d <certs directory>: path to the X.509 certificate directory\n"
                    "    -i <python_interpreter>: path to the python interpreter to use\n"
                    "    -c <cert_name>:  the name of the server certificate contained in the cert directory\n"
                    "    -a <root_ca_name>: the name of the root CA container in the cert directory\n"
                    "    -k <private_key_name>: the name of the server private key contained in the cert directory\n"
                    "    -s <server_sni>: SNI that matches the CN or subjectAltName of the certificate\n"
                    "    -e <client_certificate>: the name of the client certificate (contained in the cert directory)\n"
                    "    -b <client_private_key>: the name of the client private key (contained in the cert directory)",
            prog);
}

static CU_pSuite add_suite(const char *suite_name, CU_InitializeFunc setup,
                           CU_CleanupFunc teardown, CU_ErrorCode *err) {
    CU_pSuite suite;

    suite = CU_add_suite(suite_name, setup, teardown);
    if (NULL == suite) {
        if (err) *err = CU_get_error();
        return NULL;
    }

    return suite;
}


#define assert_die(expr) \
do {                     \
    if (!(expr)) {       \
        fprintf(stderr, "%s:%d. Assertion \""#expr"\" failed\n", __FILE__, __LINE__); \
        usage(argv[0]);\
        return EXIT_FAILURE;\
    }\
} while(0)

int main(int argc, char *argv[]) {
    unsigned int nb_failed;
    int option_index = 0;
    const char *err_msg;
    CU_ErrorCode err;
    CU_pSuite suite;
    size_t i;
    int c;

    nb_failed = 0;

    static struct option long_options[] = {
            {"test-dir",           required_argument, 0, 'p'},
            {"python-interpreter", required_argument, 0, 'i'},
            {"certs_dir",          required_argument, 0, 'd'},
            {"root-ca",            required_argument, 0, 'a'},
            {"pkey",               required_argument, 0, 'k'},
            {"cert",               required_argument, 0, 'c'},
            {"sni",                required_argument, 0, 's'},
            {"client-cert",        required_argument, 0, 'e'},
            {"client-pkey",        required_argument, 0, 'b'},
            {0, 0,                                    0, 0}
    };


    while (1) {
        c = getopt_long(argc, argv, "p:i:d:a:k:c:s:e:b:",
                        long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'i':
                python_interpreter = optarg;
                break;
            case 'p':
                assert_die(!test_directory);
                test_directory = optarg;
                break;
            case 'd':
                assert_die(certs_dir == NULL);
                certs_dir = optarg;
                break;
            case 'c':
                assert_die(!cert_name);
                cert_name = optarg;
                break;
            case 'a':
                assert_die(!root_ca_name);
                root_ca_name = optarg;
                break;
            case 'k':
                assert_die(!pkey_name);
                pkey_name = optarg;
                break;
            case 's':
                assert_die(!server_sni);
                server_sni = optarg;
                break;
            case 'e':
                assert_die(!client_cert_name);
                client_cert_name = optarg;
                break;
            case 'b':
                assert_die(!client_pkey_name);
                client_pkey_name = optarg;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!certs_dir || !test_directory || !root_ca_name || !cert_name || !pkey_name || !server_sni) {
        fprintf(stderr, "missing -c, -p, -d, -a, -s or -k. Those are required args!\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if ((client_cert_name && !client_pkey_name) || (!client_cert_name && client_pkey_name)) {
        fprintf(stderr, "if -e option is set -b option must also be set and vice versa");
        usage(argv[0]);
    }

    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry()) {
        fprintf(stderr, "initialize_registry: %s\n", CU_get_error_msg());
        return EXIT_FAILURE;
    }

    /* add all suites to the registry */
    if (nb_all_suites == 0) {
        err = CUE_NOSUITE;
        fprintf(stderr, "%s:%d : get_suite hasn't returned any suite to run\n",
                __FILE__, __LINE__);
        goto exit;
    }

    for (i = 0; i < nb_all_suites; i++) {
        if ((suite = add_suite(all_suites[i]->suite_name, all_suites[i]->setup,
                               all_suites[i]->teardown, &err)) == NULL) {
            fprintf(stderr, "Init suite %s failed: %s\n", all_suites[i]->suite_name,
                    CU_get_error_msg());
            goto exit;
        }

        if ((err = all_suites[i]->fn_add(suite, &err_msg)) != CUE_SUCCESS) {
            fprintf(stderr, "Internal suite %s init failed: %s\n", all_suites[i]->suite_name, err_msg);
            goto exit;
        }
    }

    /* ok, all tests have been added, let's run them */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    err = CU_basic_run_tests();

    CU_basic_show_failures(CU_get_failure_list());
    printf("\n");

    nb_failed = CU_get_number_of_failures();

    exit:
    CU_cleanup_registry();
    return err == CUE_SUCCESS && nb_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
