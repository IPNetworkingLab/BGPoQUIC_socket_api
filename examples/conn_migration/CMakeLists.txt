add_executable(client_migration
        client.c)

add_executable(server_migration
        server.c)

target_include_directories(client_migration PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(client_migration PRIVATE picoquic_sock)

target_include_directories(server_migration PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(server_migration PRIVATE picoquic_sock)