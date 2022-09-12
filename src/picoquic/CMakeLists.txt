find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
# search for libevent.pc
pkg_search_module(EVENT REQUIRED libevent)
pkg_search_module(EVENT_THREAD REQUIRED libevent_pthreads)


FETCHCONTENT_DECLARE(
        libvpoll
        GIT_REPOSITORY https://github.com/rd235/libvpoll-eventfd
        GIT_TAG 24ab39f4c23dab97b154ce490971ff154b7c716b
        PATCH_COMMAND sed -i "s/add_custom_target(uninstall/add_custom_target(uninstall-vpoll/g" CMakeLists.txt
)

FETCHCONTENT_DECLARE(
        libfduserdata
        GIT_REPOSITORY https://github.com/rd235/libfduserdata
        GIT_TAG 1114d36fa527e2d9664b7f103a9183c3b8333e76
        PATCH_COMMAND sed -i "s/add_custom_target(uninstall/add_custom_target(uninstall-fduserdata/g" CMakeLists.txt
)

#### fixme PLEASE FIX TARGET DIRECTORY "${CMAKE_BINARY_DIR}/include"
set(PROJECT_INCLUDEDIR "${CMAKE_BINARY_DIR}/include" CACHE INTERNAL "" FORCE)
FetchContent_MakeAvailable(libvpoll libfduserdata)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(FDUSERDATA)
find_package(VPOLL)

#set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
#pkg_check_modules()

# pkg_check_modules(FDUSERDATA REQUIRED libfduserdata)
#pkg_check_modules(VPOLL REQUIRED libvpoll)


message(STATUS "vpoll/include: ${VPOLL_INCLUDE_DIRS}")
message(STATUS "vpoll libraries: ${VPOLL_LIBRARIES}")
message(STATUS "fduserdata/include: ${FDUSERDATA_INCLUDE_DIRS}")
message(STATUS "fduserdata libraries: ${FDUSERDATA_LIBRARIES}")


add_library(picoquic_sock
        picoquic_sock_api.c
        picoquic_sock.h
        ## yeah I know, this is a small hack
        ${libfduserdata_SOURCE_DIR}/fduserdata.c
        ${libvpoll_SOURCE_DIR}/vpoll.c
        )

install(TARGETS picoquic_sock
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
        )

target_include_directories(picoquic_sock
        PUBLIC ${CMAKE_SOURCE_DIR}/include
        PRIVATE ${CMAKE_SOURCE_DIR}/src ${EVENT_INCLUDE_DIRS} ${EVENT_THREAD_INCLUDE_DIRS}
        ${VPOLL_INCLUDE_DIRS} ${FDUSERDATA_INCLUDE_DIRS})

target_link_libraries(picoquic_sock
        PUBLIC quicsock_common picoquic-core
        ${EVENT_LIBRARIES} ${EVENT_THREAD_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT})