# QUIC SOCKET API

A `C` socket API for several QUIC implementations.

We currently support the following QUIC implementation:

 - [MsQuic](https://github.com/microsoft/msquic)
 - [PicoQUIC](https://github.com/private-octopus/picoquic)

## Requirements

- `cmake`: to build this project
- `openssl`: to generate self-signed certificates for tests & build picoquic
- `libevent`: to build the picoquic socket API
- _**[optional]**_ `doxygen`: to build the documentation

## Build

```shell
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=<BUILD_TYPE> -DCMAKE_INSTALL_PREFIX=/install/path ..
$ make
[optional] $ make install 
```

`<BUILD_TYPE>` is either `Release` or `Debug` according
to the type of build you want to make.

## Launch tests

```shell
$ ctest --verbose
```

## Build the Documentation

```shell
$ make doc_doxygen
```

## Socket API Manual linking

If you want to manually import the socket api for
your application, you must include several libs.

To use the socket API for picoquic, you must import the following libraries:

```shell
-lpicoquic_sock -lquicsock_common \                  # our libs
-lpicoquic-core \                                    # picoquic libs
-lpicotls-fusion -lpicotls-openssl -lpicotls-core \  # picotls libs
$(pkg-config --libs openssl) \                       # openssl libs
$(pkg-config --libs libevent_pthreads)               # libevent
```

To use the MsQuic socket API, the following libraries must be imported:

```shell
-lmsquic_sock -lquicsock_common \  # our libs
-lmsquic -lplatform                # MsQuic libs
```

All libraries are installed in the directory `${CMAKE_INSTALL_PREFIX}/lib`
configured when building this project. If a non-standard library path
is used when configuring the project, you must add the path to this
directory with an equivalent `-L${CMAKE_INSTALL_PREFIX}` option according to
your C compiler.

# Developing your app with the QUIC socket API.

As for the libraries, the headers needed to use the socket API
are installed in `${CMAKE_INSTALL_PREFIX}/include`. If a non-standard
include directory is defined, you must tell the C compiler where to find
the headers with `-I${CMAKE_INSTALL_PREFIX}` (or an equivalent of this
option depending on your version of the C compiler).