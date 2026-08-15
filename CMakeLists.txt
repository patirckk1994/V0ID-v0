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

add_executable(v0id-round-morph-schedule-tests
    src/polymorph/round_morph_schedule_tests.cpp
)
target_link_libraries(v0id-round-morph-schedule-tests PRIVATE v0id_core)

add_library(v0id_boolean_integrity
    src/integrity/boolean_ir.cpp
    src/integrity/keccak_ir.cpp
    src/integrity/sha3_512_ir.cpp
    src/integrity/boolean_ir_mutator.cpp
    src/integrity/boolean_ir_lowering_plan.cpp
    src/integrity/boolean_ir_to_program.cpp
    src/integrity/boolean_program_image.cpp
    src/integrity/boolean_program_image_mutator.cpp
    src/integrity/keccak_program_image.cpp
)
target_include_directories(v0id_boolean_integrity PUBLIC
    src/integrity
    src/core
)
target_link_libraries(v0id_boolean_integrity PUBLIC v0id_core)

add_executable(v0id-sha3-program-tests
    src/integrity/sha3_program_tests.cpp
)
target_link_libraries(v0id-sha3-program-tests PRIVATE
    v0id_boolean_integrity
    OpenSSL::Crypto
)

add_executable(v0id-sha3-image-tests
    src/integrity/sha3_image_tests.cpp
)
target_include_directories(v0id-sha3-image-tests PRIVATE src/fhe)
target_link_libraries(v0id-sha3-image-tests PRIVATE
    v0id_boolean_integrity
    OpenSSL::Crypto
)

add_library(v0id_encrypted_boolean_program
    src/fhe/encrypted_boolean_program.cpp
)
target_include_directories(v0id_encrypted_boolean_program PUBLIC
    src/fhe
    src/integrity
    ${OPENMP_INCLUDES}
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/third-party/include
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)
target_link_libraries(v0id_encrypted_boolean_program PUBLIC
    v0id_boolean_integrity
)
v0id_use_openfhe(v0id_encrypted_boolean_program)

add_executable(v0id-encrypted-boolean-program-tests
    src/integrity/encrypted_boolean_program_tests.cpp
)
target_include_directories(v0id-encrypted-boolean-program-tests PRIVATE
    src/fhe
    src/integrity
)
target_link_libraries(v0id-encrypted-boolean-program-tests PRIVATE
    v0id_encrypted_boolean_program
)
v0id_use_openfhe(v0id-encrypted-boolean-program-tests)

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

add_executable(v0id-round-receipt-tests
    src/integrity/round_receipt_tests.cpp
)
target_link_libraries(v0id-round-receipt-tests PRIVATE v0id_quine)

add_executable(v0id-polymorphism-distinguisher
    src/integrity/polymorphism_distinguisher.cpp
)
target_link_libraries(v0id-polymorphism-distinguisher PRIVATE v0id_core)

# Defensive execution-soundness harness. ToyFingerprint has been retired; the
# harness now compares final-output-only verification against the SHA3-512
# round-receipt audit directly.
add_executable(v0id-malicious-evaluator-harness
    src/integrity/malicious_evaluator_harness.cpp
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

add_executable(v0id-series-first-mlkem-tests
    src/crypto/series_first_mlkem_tests.cpp
)
target_link_libraries(v0id-series-first-mlkem-tests PRIVATE v0id_core OpenSSL::Crypto)

add_library(v0id_coin src/coin/work_token.cpp)
target_include_directories(v0id_coin PUBLIC src/coin)
target_link_libraries(v0id_coin PUBLIC OpenSSL::Crypto)

add_executable(v0id-work-token-tests src/coin/work_token_tests.cpp)
target_link_libraries(v0id-work-token-tests PRIVATE v0id_coin)

add_executable(v0id-symbolic-series-audit
    src/integrity/symbolic_series_audit.cpp
)
target_link_libraries(v0id-symbolic-series-audit PRIVATE v0id_core)

option(V0ID_ENABLE_Z3_BITVECTOR_AUDIT
    "Build the optional Z3 bounded bitvector attacker audit" ON)
if(V0ID_ENABLE_Z3_BITVECTOR_AUDIT)
    find_path(V0ID_Z3_INCLUDE_DIR z3++.h)
    find_library(V0ID_Z3_LIBRARY NAMES z3 libz3)
    if(V0ID_Z3_INCLUDE_DIR AND V0ID_Z3_LIBRARY)
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

add_executable(v0id src/main.cpp)
target_link_libraries(v0id PRIVATE v0id_core OpenSSL::Crypto)
v0id_use_openfhe(v0id)

add_library(v0id_net
    src/net/peer_transport.cpp
    src/net/module_sync.cpp
)
target_include_directories(v0id_net PUBLIC src/net)
target_link_libraries(v0id_net PUBLIC cppzmq OpenSSL::Crypto)

add_executable(v0id-module-sync-tests src/net/module_sync_tests.cpp)
target_link_libraries(v0id-module-sync-tests PRIVATE v0id_net)

add_library(v0id_neural
    src/neural/neural_graph.cpp
)
target_include_directories(v0id_neural PUBLIC
    src/neural
    src/net
)
target_link_libraries(v0id_neural PUBLIC
    v0id_net
    OpenSSL::Crypto
)

add_executable(v0id-neural-graph-tests
    src/neural/neural_graph_tests.cpp
)
target_link_libraries(v0id-neural-graph-tests PRIVATE v0id_neural)

add_custom_target(v0id-test-neural-graph
    COMMAND $<TARGET_FILE:v0id-neural-graph-tests>
    DEPENDS v0id-neural-graph-tests
    USES_TERMINAL
    COMMENT "Running V0ID modular neural graph regression tests")

add_executable(v0id-peer src/net/peer_demo.cpp)
target_link_libraries(v0id-peer PRIVATE v0id_net)

add_executable(v0id-fhe-peer src/net/fhe_peer_demo.cpp)
target_include_directories(v0id-fhe-peer PRIVATE src/fhe)
target_link_libraries(v0id-fhe-peer PRIVATE v0id_net)
v0id_use_openfhe(v0id-fhe-peer)

add_executable(v0id-remote-machine
    src/net/remote_machine_demo.cpp
    src/fhe/remote_machine.cpp
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
endif()