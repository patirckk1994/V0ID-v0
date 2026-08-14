cmake_minimum_required(VERSION 3.20)
project(v0id LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenFHE CONFIG REQUIRED)
find_package(OpenSSL 3 REQUIRED)

# CMake 4 removed compatibility with policy versions older than 3.5. libzmq
# v4.3.5 still declares a 2.8.12...3.31 compatibility range, so a modern
# top-level build otherwise dies while configuring the fetched dependency.
# This is the supported compatibility escape hatch suggested by CMake itself;
# it avoids patching the upstream libzmq source tree.
if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.0")
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING
        "Minimum policy compatibility for legacy fetched dependencies" FORCE)
endif()

# Network prototype dependencies are fetched from their upstream public repos.
# libzmq provides the transport; cppzmq is the header-only C++ binding included
# by src/net/peer_transport.hpp as <zmq.hpp>.
include(FetchContent)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZMQ_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(WITH_DOCS OFF CACHE BOOL "" FORCE)
set(ENABLE_DRAFTS OFF CACHE BOOL "" FORCE)
set(CPPZMQ_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    libzmq
    GIT_REPOSITORY https://github.com/zeromq/libzmq.git
    GIT_TAG v4.3.5
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(libzmq)

FetchContent_Declare(
    cppzmq
    GIT_REPOSITORY https://github.com/zeromq/cppzmq.git
    GIT_TAG v4.11.0
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(cppzmq)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")

if(OpenFHE_SHARED)
    set(V0ID_OPENFHE_LIBRARIES ${OpenFHE_SHARED_LIBRARIES})
else()
    set(V0ID_OPENFHE_LIBRARIES ${OpenFHE_STATIC_LIBRARIES})
endif()

function(v0id_use_openfhe target)
    target_include_directories(${target} PRIVATE
        ${OPENMP_INCLUDES}
        ${OpenFHE_INCLUDE}
        ${OpenFHE_INCLUDE}/third-party/include
        ${OpenFHE_INCLUDE}/core
        ${OpenFHE_INCLUDE}/pke
        ${OpenFHE_INCLUDE}/binfhe
    )
    target_link_directories(${target} PRIVATE
        ${OpenFHE_LIBDIR}
        ${OPENMP_LIBRARIES}
    )
    target_link_libraries(${target} PRIVATE ${V0ID_OPENFHE_LIBRARIES})
endfunction()

# Client-side program representation and precomputed polymorphism compiler.
add_library(v0id_core
    src/polymorph/program_morpher.cpp
)
target_include_directories(v0id_core PUBLIC
    src/core
    src/polymorph
)
target_link_libraries(v0id_core PUBLIC OpenSSL::Crypto)

add_executable(v0id
    src/main.cpp
    src/integrity/toy_fingerprint.cpp
)
target_include_directories(v0id PRIVATE src/integrity)
target_link_libraries(v0id PRIVATE v0id_core OpenSSL::Crypto)
v0id_use_openfhe(v0id)

# Binary-safe transport layer. The envelope payload is deliberately opaque so
# OpenFHE serialized ciphertext bytes can be placed directly inside it.
add_library(v0id_net
    src/net/peer_transport.cpp
)
target_include_directories(v0id_net PUBLIC src/net)
target_link_libraries(v0id_net PUBLIC cppzmq)

# Plain transport smoke test.
add_executable(v0id-peer
    src/net/peer_demo.cpp
)
target_link_libraries(v0id-peer PRIVATE v0id_net)

# Actual FHE-over-network smoke test. The client sends a key-independent BinFHE
# context, bootstrapping keys and ciphertext; the server evaluates NOT without
# receiving the LWE secret key and returns only a result ciphertext.
add_executable(v0id-fhe-peer
    src/net/fhe_peer_demo.cpp
)
target_include_directories(v0id-fhe-peer PRIVATE src/fhe)
target_link_libraries(v0id-fhe-peer PRIVATE v0id_net)
v0id_use_openfhe(v0id-fhe-peer)

if(UNIX AND NOT APPLE)
    target_link_options(v0id PRIVATE -Wl,--no-as-needed)
    target_link_options(v0id-fhe-peer PRIVATE -Wl,--no-as-needed)
endif()
