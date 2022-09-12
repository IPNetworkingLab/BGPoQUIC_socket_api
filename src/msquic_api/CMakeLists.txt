

add_library(msquic_sock
        msquic_sock_api.c
        msquic_sock.h
        )

install(TARGETS msquic_sock
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
)

target_include_directories(msquic_sock
        PUBLIC ${CMAKE_SOURCE_DIR}/include
        PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(msquic_sock PRIVATE quicsock_common platform inc warnings msquic)

if (NOT BUILD_SHARED_LIBS)
    target_link_libraries(msquic_sock PRIVATE base_link)
endif()

target_compile_features(msquic_sock PUBLIC c_std_11)

# IDEs should put the headers in a nice place
source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADERS_LIST})
