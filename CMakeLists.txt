cmake_minimum_required(VERSION 3.20)
project(v0id LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenFHE CONFIG REQUIRED)
find_package(OpenSSL 3 REQUIRED)

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

add_executable(v0id src/main.cpp)
target_include_directories(v0id PRIVATE
    ${OPENMP_INCLUDES}
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/third-party/include
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)
target_link_directories(v0id PRIVATE
    ${OpenFHE_LIBDIR}
    ${OPENMP_LIBRARIES}
)
target_link_libraries(v0id PRIVATE
    ${V0ID_OPENFHE_LIBRARIES}
    OpenSSL::Crypto
)

# Binary-safe transport layer. The envelope payload is deliberately opaque so
# the next step can place OpenFHE serialized ciphertext bytes directly inside it.
add_library(v0id_net
    src/net/peer_transport.cpp
)
target_include_directories(v0id_net PUBLIC src/net)
target_link_libraries(v0id_net PUBLIC cppzmq)

add_executable(v0id-peer
    src/net/peer_demo.cpp
)
target_link_libraries(v0id-peer PRIVATE v0id_net)

if(UNIX AND NOT APPLE)
    target_link_options(v0id PRIVATE -Wl,--no-as-needed)
endif()
