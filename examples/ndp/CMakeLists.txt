set(CERTS_FOLDER ${CMAKE_CURRENT_BINARY_DIR}/certs)
set(CERT_FILE_CLIENT ${CERTS_FOLDER}/client_cert.crt)
set(KEY_FILE_CLIENT ${CERTS_FOLDER}/client_key.key)
set(CERT_FILE_SERVER ${CERTS_FOLDER}/server_cert.crt)
set(KEY_FILE_SERVER ${CERTS_FOLDER}/server_key.key)

add_custom_command(
		OUTPUT ${CERT_FILE_SERVER} ${KEY_FILE_SERVER}
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMAND ${CMAKE_COMMAND} -E make_directory ${CERTS_FOLDER}
		COMMAND "openssl" "req" "-new" "-newkey" "rsa:4096"
		"-x509" "-sha256" "-days" "3650" "-nodes"
		"-subj" "\"/C=US/ST=Some-State/L=MyCity/O=Dis/CN=rtr-srv\""
		"-out" "${CERT_FILE_SERVER}" "-keyout" "${KEY_FILE_SERVER}"
)

add_custom_command(
		OUTPUT ${CERT_FILE_CLIENT} ${KEY_FILE_CLIENT}
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMAND ${CMAKE_COMMAND} -E make_directory ${CERTS_FOLDER}
		COMMAND "openssl" "req" "-new" "-newkey" "rsa:4096"
		"-x509" "-sha256" "-days" "3650" "-nodes"
		"-subj" "\"/C=US/ST=Some-State/L=MyCity/O=Dis/CN=rtr-client\""
		"-out" "${CERT_FILE_CLIENT}" "-keyout" "${KEY_FILE_CLIENT}"
)


add_executable(quic_sock_example_ndp
		${CERT_FILE_SERVER} ${KEY_FILE_SERVER}
	ndp.c
        common_ndp.h)
target_include_directories(quic_sock_example_ndp PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(quic_sock_example_ndp PRIVATE picoquic_sock)

add_executable(quic_sock_example_ndp_client
		${CERT_FILE_CLIENT} ${KEY_FILE_CLIENT}
	client.c
        common_ndp.h)
target_include_directories(quic_sock_example_ndp_client PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(quic_sock_example_ndp_client PRIVATE picoquic_sock)
