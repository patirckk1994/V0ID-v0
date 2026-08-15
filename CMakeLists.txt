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

option(V0ID_ENABLE_MATHVM "Build the WAMR-backed V0ID sandbox components" ON)
if(V0ID_ENABLE_MATHVM)
    FetchContent_Declare(
        wamr
        GIT_REPOSITORY https://github.com/bytecodealliance/wasm-micro-runtime.git
        GIT_TAG WAMR-2.4.0
        GIT_SHALLOW TRUE
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
        message(FATAL_ERROR "V0ID WAMR: unsupported host platform ${CMAKE_SYSTEM_NAME}")
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
    target_link_libraries(v0id_mathvm PUBLIC v0id_wamr OpenSSL::Crypto)

    add_executable(v0id-mathvm src/mathvm/mathvm_demo.cpp)
    target_link_libraries(v0id-mathvm PRIVATE v0id_mathvm)

    add_executable(v0id-mathvm-tests src/mathvm/mathvm_tests.cpp)
    target_link_libraries(v0id-mathvm-tests PRIVATE v0id_mathvm)

    add_executable(v0id-mathvm-byte-boundary-tests
        src/mathvm/byte_boundary_tests.cpp
    )
    target_link_libraries(v0id-mathvm-byte-boundary-tests PRIVATE v0id_mathvm)
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

# Series-first core: issuer-private KMACXOF schedule, trusted ProgramMorpher,
# transcript-bound post-KEM scheduling, and a whole-stack purpose schedule where
# purpose series are derived before concrete algorithm identifiers are chosen.
add_library(v0id_core
    src/polymorph/program_morpher.cpp
    src/polymorph/series_generator.cpp
    src/crypto/series_first_schedule.cpp
    src/crypto/series_first_stack.cpp
)
target_include_directories(v0id_core PUBLIC
    src/core
    src/polymorph
    src/crypto
)
target_link_libraries(v0id_core PUBLIC OpenSSL::Crypto)

add_executable(v0id-series-first-kex-tests
    src/crypto/series_first_schedule_tests.cpp
)
target_link_libraries(v0id-series-first-kex-tests PRIVATE v0id_core)

add_executable(v0id-series-first-stack-tests
    src/crypto/series_first_stack_tests.cpp
)
target_link_libraries(v0id-series-first-stack-tests PRIVATE v0id_core)

# Fast plaintext gate for the execution-bound polymorphism experiment. It uses
# one secret state-label encoding per round boundary, so a semantic fixed point
# does not also become a stable encrypted-machine representation.
add_executable(v0id-round-morph-schedule-tests
    src/polymorph/round_morph_schedule_tests.cpp
)
target_link_libraries(v0id-round-morph-schedule-tests PRIVATE v0id_core)

# PQ-facing plaintext quine commitment plus the hash-agnostic canonical subject
# and private execution-integrity construction boundary. SHA3-512 is the strong
# default client reference backend; runtime hash Programs remain private hooks.
add_library(v0id_quine
    src/integrity/quine_hash.cpp
    src/integrity/round_receipt.cpp
    src/integrity/canonical_self_image.cpp
    src/integrity/integrity_program.cpp
)
target_include_directories(v0id_quine PUBLIC
    src/integrity
    src/fhe
)
target_link_libraries(v0id_quine PUBLIC v0id_core OpenSSL::Crypto)

add_executable(v0id-quine-audit-tests
    src/integrity/quine_audit_tests.cpp
)
target_link_libraries(v0id-quine-audit-tests PRIVATE v0id_quine)

add_executable(v0id-canonical-self-image-tests
    src/integrity/canonical_self_image_tests.cpp
)
target_link_libraries(v0id-canonical-self-image-tests PRIVATE v0id_quine)

add_executable(v0id-integrity-program-tests
    src/integrity/integrity_program_tests.cpp
)
target_link_libraries(v0id-integrity-program-tests PRIVATE v0id_quine)

# Round-receipt execution-bound audit: a cheap SHA3-512 hash chain over
# evaluator-visible per-round ciphertext digests, bound to session/job/epoch/
# profile/round-count. Pure logic, no OpenFHE required, so it runs fast and
# independently of the slow BinFHE-backed malicious evaluator harness below.
add_executable(v0id-round-receipt-tests
    src/integrity/round_receipt_tests.cpp
)
target_link_libraries(v0id-round-receipt-tests PRIVATE v0id_quine)

# Phase-1 polymorphism leakage benchmark. It separates deliberately public fixed
# evaluator shape from a stronger plaintext diagnostic that the current BinFHE
# evaluator does not receive. Later wire/timing work is deferred behind execution
# soundness because honest-execution verification is the critical-path problem.
add_executable(v0id-polymorphism-distinguisher
    src/integrity/polymorphism_distinguisher.cpp
)
target_link_libraries(v0id-polymorphism-distinguisher PRIVATE v0id_core)

# Defensive malicious-evaluator harness. It uses the real ProgramMorpher,
# RemoteEncryptedMachine and legacy FHE fingerprint plumbing to demonstrate that
# an evaluator can skip requested rounds while preserving an accepted final
# output for a fixed-point job -- and that the round-receipt audit above
# rejects that same cheat while staying far cheaper than recomputation.
add_executable(v0id-malicious-evaluator-harness
    src/integrity/malicious_evaluator_harness.cpp
    src/integrity/toy_fingerprint.cpp
    src/fhe/remote_machine.cpp
)
target_include_directories(v0id-malicious-evaluator-harness PRIVATE
    src/fhe
    src/integrity
)
target_link_libraries(v0id-malicious-evaluator-harness PRIVATE
    v0id_core
    v0id_quine
    OpenSSL::Crypto
    Threads::Threads
)
v0id_use_openfhe(v0id-malicious-evaluator-harness)

# Intended execution-binding experiment: the client derives a different hidden
# state-label encoding for every round boundary, fingerprints the complete
# ordered encrypted schedule, then checks the final hidden state as well as the
# semantic tape. The 2/4 fixed-point cheat is expected to retain the right tape
# but fail the boundary-4 state check.
add_executable(v0id-round-morph-fhe-harness
    src/integrity/round_morph_fhe_harness.cpp
    src/integrity/toy_fingerprint.cpp
    src/fhe/remote_machine.cpp
)
target_include_directories(v0id-round-morph-fhe-harness PRIVATE
    src/fhe
    src/integrity
)
target_link_libraries(v0id-round-morph-fhe-harness PRIVATE
    v0id_core
    OpenSSL::Crypto
)
v0id_use_openfhe(v0id-round-morph-fhe-harness)

# Real standardized KEM composition gate. OpenSSL 3.5+ supplies ML-KEM-768;
# when the provider is unavailable the executable reports SKIP rather than
# pretending a synthetic shared secret exercised the KEM runtime.
add_executable(v0id-series-first-mlkem-tests
    src/crypto/series_first_mlkem_tests.cpp
)
target_link_libraries(v0id-series-first-mlkem-tests PRIVATE v0id_core OpenSSL::Crypto)

# Future coin/blockchain wrapper only: one accepted event may contain mining
# work, useful-compute complexity, or both. The six MI/MV/MC + CI/CV/CC payout
# primitives are classifications over that same event, not an issuance policy.
add_library(v0id_coin src/coin/work_token.cpp)
target_include_directories(v0id_coin PUBLIC src/coin)
target_link_libraries(v0id_coin PUBLIC OpenSSL::Crypto)

add_executable(v0id-work-token-tests src/coin/work_token_tests.cpp)
target_link_libraries(v0id-work-token-tests PRIVATE v0id_coin)

# Exact reduced-domain symbolic falsification gate. Affine and degree<=2 ANF
# recovery are linear in the unknown attacker coefficients, so a bit-packed
# Gaussian elimination over GF(2) is both complete for this attacker class and
# dramatically cheaper than a general SMT solver.
add_executable(v0id-symbolic-series-audit
    src/integrity/symbolic_series_audit.cpp
)
target_link_libraries(v0id-symbolic-series-audit PRIVATE v0id_core)

# Next attacker language: one shared bounded 8-bit straight-line program across
# the reduced-root family. Z3 may choose sources, immediates and output bits from
# XOR/AND/ADD/NOT/shift/rotate. Root bits are searched independently so UNKNOWN
# remains localized. The CEGIS loop rejects candidates against all 256 reduced
# roots and treats solver UNKNOWN as inconclusive, never as PASS. Z3 remains an
# audit-only dependency and never enters production V0ID.
option(V0ID_ENABLE_Z3_BITVECTOR_AUDIT
    "Build the optional Z3 bounded bitvector attacker audit" ON)
if(V0ID_ENABLE_Z3_BITVECTOR_AUDIT)
    find_path(V0ID_Z3_INCLUDE_DIR z3++.h)
    find_library(V0ID_Z3_LIBRARY NAMES z3 libz3)
    if(V0ID_Z3_INCLUDE_DIR AND V0ID_Z3_LIBRARY)
        # Exact reduced-domain lifting of production KMAC series outputs into Z3.
        # This does not symbolically implement SHA3/KMAC; it is a 256-root audit
        # model used by stronger symbolic experiments.
        add_library(v0id_z3_series_model
            src/integrity/z3_series_model.cpp
        )
        target_include_directories(v0id_z3_series_model PUBLIC
            src/integrity
            ${V0ID_Z3_INCLUDE_DIR}
        )
        target_link_libraries(v0id_z3_series_model PUBLIC
            v0id_core
            ${V0ID_Z3_LIBRARY}
        )

        add_executable(v0id-z3-series-model-tests
            src/integrity/z3_series_model_tests.cpp
        )
        target_link_libraries(v0id-z3-series-model-tests PRIVATE
            v0id_z3_series_model
        )

        add_executable(v0id-bitvector-series-audit
            src/integrity/bitvector_series_audit.cpp
        )
        target_include_directories(v0id-bitvector-series-audit PRIVATE
            ${V0ID_Z3_INCLUDE_DIR}
        )
        target_link_libraries(v0id-bitvector-series-audit PRIVATE
            v0id_core
            ${V0ID_Z3_LIBRARY}
        )
        message(STATUS "V0ID bitvector audit + reduced Z3 series model: Z3 enabled")
    else()
        message(STATUS "V0ID bitvector audit: Z3 not found; targets disabled")
    endif()
endif()

if(V0ID_ENABLE_MATHVM)
    add_library(v0id_wasm_polymorph
        src/polymorph/wasm_series_generator.cpp
    )
    target_include_directories(v0id_wasm_polymorph PUBLIC src/polymorph)
    target_link_libraries(v0id_wasm_polymorph PUBLIC v0id_core v0id_wamr)

    add_executable(v0id-wasm-polymorph-tests
        src/polymorph/wasm_series_tests.cpp
    )
    target_link_libraries(v0id-wasm-polymorph-tests PRIVATE v0id_wasm_polymorph)

    add_executable(v0id-wasm-polymorph-demo
        src/polymorph/wasm_series_demo.cpp
    )
    target_link_libraries(v0id-wasm-polymorph-demo PRIVATE v0id_wasm_polymorph)
endif()

add_executable(v0id
    src/main.cpp
    src/integrity/toy_fingerprint.cpp
)
target_include_directories(v0id PRIVATE src/integrity)
target_link_libraries(v0id PRIVATE v0id_core v0id_quine OpenSSL::Crypto)
v0id_use_openfhe(v0id)

# ZeroMQ remains the transport framing layer. Optional content-addressed Wasm
# synchronization uses OpenSSL SHA3-512 for exact module identity; executable
# validation remains the responsibility of WAMR/MathVM after receipt.
add_library(v0id_net
    src/net/peer_transport.cpp
    src/net/module_sync.cpp
)
target_include_directories(v0id_net PUBLIC src/net)
target_link_libraries(v0id_net PUBLIC cppzmq OpenSSL::Crypto)

add_executable(v0id-module-sync-tests src/net/module_sync_tests.cpp)
target_link_libraries(v0id-module-sync-tests PRIVATE v0id_net)

add_executable(v0id-peer src/net/peer_demo.cpp)
target_link_libraries(v0id-peer PRIVATE v0id_net)

add_executable(v0id-fhe-peer src/net/fhe_peer_demo.cpp)
target_include_directories(v0id-fhe-peer PRIVATE src/fhe)
target_link_libraries(v0id-fhe-peer PRIVATE v0id_net)
v0id_use_openfhe(v0id-fhe-peer)

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
    v0id_quine
    OpenSSL::Crypto
)
if(V0ID_ENABLE_MATHVM)
    target_link_libraries(v0id-remote-machine PRIVATE v0id_wasm_polymorph)
    target_compile_definitions(v0id-remote-machine PRIVATE
        V0ID_HAVE_WASM_POLYMORPH=1)
endif()
v0id_use_openfhe(v0id-remote-machine)

if(UNIX AND NOT APPLE)
    target_link_options(v0id PRIVATE -Wl,--no-as-needed)
    target_link_options(v0id-fhe-peer PRIVATE -Wl,--no-as-needed)
    target_link_options(v0id-remote-machine PRIVATE -Wl,--no-as-needed)
    target_link_options(v0id-malicious-evaluator-harness PRIVATE -Wl,--no-as-needed)
    target_link_options(v0id-round-morph-fhe-harness PRIVATE -Wl,--no-as-needed)
endif()
