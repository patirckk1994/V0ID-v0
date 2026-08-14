cmake_minimum_required(VERSION 3.20)
project(v0id LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenFHE CONFIG REQUIRED)
find_package(OpenSSL 3 REQUIRED)
find_package(Threads REQUIRED)

# CMake 4 removed compatibility with policy versions older than 3.5. Some
# fetched research dependencies still declare older compatibility ranges.
if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.0")
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING
        "Minimum policy compatibility for legacy fetched dependencies" FORCE)
endif()

include(FetchContent)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZMQ_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(WITH_DOCS OFF CACHE BOOL "" FORCE)
set(ENABLE_DRAFTS OFF CACHE BOOL "" FORCE)
set(CPPZMQ_BUILD_TESTS OFF CACHE BOOL "" FORCE)

# Network prototype dependencies.
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

# WAMR-backed mathematical sandbox. The transmitted artifact is portable Wasm
# bytecode; peers do not transmit native shared libraries. The V0ID profile is
# intentionally restrictive: classic interpreter so instruction metering works,
# no WASI, no libc shim, no JIT/AOT, no threads/shared memory, no mini-loader and
# no runtime switch that can disable bounds checks.
option(V0ID_ENABLE_MATHVM "Build the WAMR-backed V0ID MathVM sandbox" ON)
if(V0ID_ENABLE_MATHVM)
    FetchContent_Declare(
        wamr
        GIT_REPOSITORY https://github.com/wasm-micro-runtime/wasm-micro-runtime.git
        GIT_TAG WAMR-2.4.0
        GIT_SHALLOW TRUE
        # Populate the source without adding WAMR's product build. V0ID embeds
        # vmcore using WAMR's documented runtime_lib.cmake integration instead.
        SOURCE_SUBDIR doc
    )
    FetchContent_MakeAvailable(wamr)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(WAMR_BUILD_PLATFORM "linux")
    elseif(WIN32)
        set(WAMR_BUILD_PLATFORM "windows")
    elseif(APPLE)
        set(WAMR_BUILD_PLATFORM "darwin")
    else()
        message(FATAL_ERROR "V0ID MathVM: unsupported WAMR host platform ${CMAKE_SYSTEM_NAME}")
    endif()

    set(WAMR_ROOT_DIR "${wamr_SOURCE_DIR}")
    set(WAMR_BUILD_INTERP 1)
    set(WAMR_BUILD_FAST_INTERP 0)
    set(WAMR_BUILD_INSTRUCTION_METERING 1)
    set(WAMR_BUILD_AOT 0)
    set(WAMR_BUILD_JIT 0)
    set(WAMR_BUILD_FAST_JIT 0)
    set(WAMR_BUILD_LAZY_JIT 0)
    set(WAMR_BUILD_LIBC_BUILTIN 0)
    set(WAMR_BUILD_LIBC_WASI 0)
    set(WAMR_BUILD_LIBC_UVWASI 0)
    set(WAMR_BUILD_LIBC_EMCC 0)
    set(WAMR_BUILD_MULTI_MODULE 0)
    set(WAMR_BUILD_SHARED_MEMORY 0)
    set(WAMR_BUILD_THREAD_MGR 0)
    set(WAMR_BUILD_LIB_PTHREAD 0)
    set(WAMR_BUILD_LIB_WASI_THREADS 0)
    set(WAMR_BUILD_SIMD 0)
    set(WAMR_BUILD_REF_TYPES 0)
    set(WAMR_BUILD_MINI_LOADER 0)
    set(WAMR_CONFIGURABLE_BOUNDS_CHECKS 0)

    include("${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake")
    add_library(v0id_wamr STATIC ${WAMR_RUNTIME_LIB_SOURCE})
    target_include_directories(v0id_wamr PUBLIC
        "${WAMR_ROOT_DIR}/core/iwasm/include"
    )
    target_link_libraries(v0id_wamr PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
    if(UNIX)
        target_link_libraries(v0id_wamr PUBLIC m)
    endif()

    add_library(v0id_mathvm
        src/mathvm/mathvm.cpp
        src/mathvm/wamr_sandbox.cpp
    )
    target_include_directories(v0id_mathvm PUBLIC src/mathvm)
    target_link_libraries(v0id_mathvm PUBLIC v0id_wamr)

    add_executable(v0id-mathvm
        src/mathvm/mathvm_demo.cpp
    )
    target_link_libraries(v0id-mathvm PRIVATE v0id_mathvm)

    # Self-contained host-side sandbox tests. The test executable constructs
    # tiny Wasm modules in memory, so it does not require a wasm32 clang target.
    # It exercises successful execution plus rejection of loops, undeclared
    # primitives, provider-budget exhaustion, excessive memory, WASI imports and
    # non-Wasm/AOT-like input before MathVM is exposed over the network.
    add_executable(v0id-mathvm-tests
        src/mathvm/mathvm_tests.cpp
    )
    target_link_libraries(v0id-mathvm-tests PRIVATE v0id_mathvm)
endif()

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

# Client-side program representation, series-first derivation and precomputed
# polymorphism compiler. User-defined series patterns are local trusted code;
# peers exchange identifiers only, never executable crypto plugins.
add_library(v0id_core
    src/polymorph/program_morpher.cpp
    src/polymorph/series_generator.cpp
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

add_executable(v0id-peer
    src/net/peer_demo.cpp
)
target_link_libraries(v0id-peer PRIVATE v0id_net)

add_executable(v0id-fhe-peer
    src/net/fhe_peer_demo.cpp
)
target_include_directories(v0id-fhe-peer PRIVATE src/fhe)
target_link_libraries(v0id-fhe-peer PRIVATE v0id_net)
v0id_use_openfhe(v0id-fhe-peer)

# V0.4/V0.4.1 full-machine remote execution. The client derives a private series,
# uses it to seed the morph compiler, encrypts the full machine, and attaches a
# bounded public crypto/profile identifier. The series, series seed, MorphManifest
# and LWE secret key remain client-side.
add_executable(v0id-remote-machine
    src/net/remote_machine_demo.cpp
    src/fhe/remote_machine.cpp
    src/integrity/toy_fingerprint.cpp
)
target_include_directories(v0id-remote-machine PRIVATE
    src/fhe
    src/integrity
)
target_link_libraries(v0id-remote-machine PRIVATE
    v0id_net
    v0id_core
    OpenSSL::Crypto
)
v0id_use_openfhe(v0id-remote-machine)

if(UNIX AND NOT APPLE)
    target_link_options(v0id PRIVATE -Wl,--no-as-needed)
    target_link_options(v0id-fhe-peer PRIVATE -Wl,--no-as-needed)
    target_link_options(v0id-remote-machine PRIVATE -Wl,--no-as-needed)
endif()
