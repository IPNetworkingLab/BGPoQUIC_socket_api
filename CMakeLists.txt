cmake_minimum_required(VERSION 3.16)
project(quic_sock
        DESCRIPTION "Socket API wrapper for Quic implementations")

enable_testing()

find_package(PkgConfig REQUIRED)
find_package(Git QUIET)

find_package(Doxygen
        REQUIRED dot
        OPTIONAL_COMPONENTS mscgen dia)

if (DOXYGEN_FOUND)
    # set input and output files
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    message("Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target( doc_doxygen ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM )
else (DOXYGEN_FOUND)
    message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

set(TESTS_DIR tests)


function(add_git_submodule dir)
    # add a Git submodule directory to CMake, assuming the
    # Git submodule directory is a CMake project.
    #
    # Usage: in CMakeLists.txt
    #
    # include(AddGitSubmodule.cmake)
    # add_git_submodule(mysubmod_dir)

    find_package(Git REQUIRED)

    if(NOT EXISTS ${dir}/CMakeLists.txt)
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive -- ${dir}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                COMMAND_ERROR_IS_FATAL ANY)
    endif()

    add_subdirectory(${dir})

endfunction(add_git_submodule)


# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(QUIC_BUILD_SHARED ON CACHE BOOL "Builds MsQuic as a dynamic library")
set(PICOQUIC_FETCH_PTLS ON)

add_git_submodule(${PROJECT_SOURCE_DIR}/submodules/msquic)
add_git_submodule(${PROJECT_SOURCE_DIR}/submodules/picoquic)

#add_subdirectory(submodules/msquic)
#add_subdirectory(submodules/picoquic)
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(include)
add_subdirectory(examples)
