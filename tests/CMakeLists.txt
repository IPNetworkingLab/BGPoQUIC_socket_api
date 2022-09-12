find_package(Python3 COMPONENTS Interpreter)

# setup venv if it doesn't exist
IF (NOT EXISTS "${CMAKE_BINARY_DIR}/venv")
    EXECUTE_PROCESS(COMMAND ${Python3_EXECUTABLE} "-m" "venv" "venv"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    EXECUTE_PROCESS(
            COMMAND ${CMAKE_BINARY_DIR}/venv/bin/pip "install" "-r" "${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt"
    )
ENDIF ()

UNSET(${Python3_EXECUTABLE})
# activate python venv
SET(ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/venv")
set (Python3_FIND_VIRTUALENV FIRST)
unset(Python3_EXECUTABLE)
find_package (Python3 COMPONENTS Interpreter Development)


set(CERTS_FOLDER ${CMAKE_CURRENT_BINARY_DIR}/certs)
set(CERT_NAME sample_server)
set(CERT_FILE ${CERTS_FOLDER}/${CERT_NAME}.cert.pem)
set(KEY_FILE ${CERTS_FOLDER}/${CERT_NAME}.key)
set(CERT_CN sample_server.be)

set(CLIENT_CERT_NAME sample_client)
set(CLIENT_CERT_FILE ${CERTS_FOLDER}/${CLIENT_CERT_NAME}.cert.pem)
set(CLIENT_KEY_FILE ${CERTS_FOLDER}/${CLIENT_CERT_NAME}.key)
set(CLIENT_CERT_CN sample_client.be)

set(GO_CLIENT go_simple_client)

add_custom_command(
        OUTPUT ${CERT_FILE} ${KEY_FILE} ${CLIENT_CERT_FILE} ${CLIENT_KEY_FILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND ${CMAKE_COMMAND} -E make_directory certs
        # generate dumb text to pass to generate_certs.sh
        COMMAND ${CMAKE_COMMAND} -E echo "simple text" > ./certs/simple.txt
        COMMAND ${CMAKE_SOURCE_DIR}/tools/generate_certs.sh ./certs ${CERT_NAME} ${CERT_CN} 10.0.0.1 ./certs/simple.txt
        COMMAND ${CMAKE_SOURCE_DIR}/tools/generate_certs.sh ./certs ${CLIENT_CERT_NAME} ${CLIENT_CERT_CN} 10.0.0.2 ./certs/simple.txt
)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/go_client/${GO_CLIENT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/go_client
        COMMAND go build ${GO_CLIENT}.go
)

add_executable(quic_sock_tests
        ${CERT_FILE} ${KEY_FILE} ${CMAKE_CURRENT_SOURCE_DIR}/go_client/${GO_CLIENT}
        test_main.c
        test_main.h
        test_suites.c
        test_suites.h
        test_buffer.c
        test_buffer.h
        test_queue.c
        test_queue.h
        test_eventfd.c
        test_eventfd.h
        test_msquic_sock_api.c
        test_msquic_sock_api.h test_quic_sock_api_common.c test_quic_sock_api_common.h test_picoquic_sock_api.c test_picoquic_sock_api.h)

target_include_directories(quic_sock_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)


add_compile_options(
        "$<$<CONFIG:DEBUG>:-O0>"
        "-Wall" "-Wshadow"
        "-Wextra" "-Wwrite-strings"
        "-Wcast-qual" "-Wmissing-prototypes"
        "-Wmissing-declarations" "-Wpointer-arith"
        "-Wbad-function-cast -Wstrict-prototypes")

pkg_check_modules(CUNIT REQUIRED cunit)


target_link_libraries(quic_sock_tests PRIVATE ${CUNIT_LIBRARIES} msquic_sock picoquic_sock)


add_test(
        NAME quic_sock_tests
        COMMAND quic_sock_tests -i ${Python3_EXECUTABLE} -p "${CMAKE_CURRENT_SOURCE_DIR}" -d "${CMAKE_CURRENT_BINARY_DIR}" -c "${CERT_NAME}.cert.pem" -a "ca.cert.pem" -k "${CERT_NAME}.key" -s ${CERT_CN} -e "${CLIENT_CERT_NAME}.cert.pem" -b "${CLIENT_CERT_NAME}.key"
)
