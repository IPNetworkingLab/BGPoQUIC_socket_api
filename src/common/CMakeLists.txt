add_library(quicsock_common
        util_ref.c
        util_ref.h
        util_queue.c
        util_queue.h
        util_eventfd.c
        util_eventfd.h
        util_sock_mgr.c
        util_sock_mgr.h
        util_data_buffer.c
        util_data_buffer.h
        uthash.h utlist.h
        util_var_sem.c
        util_var_sem.h
        util_common_sock.c
        util_wait_queue.c util_wait_queue.h
        ring-buffer/webrtc_ring_buf.c
        ring-buffer/webrtc_ring_buf.h)

install(TARGETS quicsock_common
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
        )


target_compile_features(quicsock_common PUBLIC c_std_11)

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")

target_compile_options(quicsock_common
        PRIVATE -Wall -Wextra -Wcast-qual -Wwrite-strings
                -Wshadow -Wbad-function-cast -Wstrict-prototypes
                -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith)

endif()