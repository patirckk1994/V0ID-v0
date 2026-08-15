option(V0ID_ENABLE_GPU_FHE "Build the TFHE-rs CUDA FHE backend" OFF)

function(v0id_finish_tfhe_cuda_setup)
    if(NOT V0ID_ENABLE_GPU_FHE)
        return()
    endif()

    if(CMAKE_VERSION VERSION_LESS "3.24")
        message(FATAL_ERROR "V0ID TFHE CUDA backend requires CMake >= 3.24")
    endif()
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "V0ID TFHE CUDA backend currently supports Linux only")
    endif()

    find_program(V0ID_CARGO_EXECUTABLE cargo REQUIRED)
    find_program(V0ID_RUSTC_EXECUTABLE rustc REQUIRED)
    find_program(V0ID_NVCC_EXECUTABLE nvcc REQUIRED)
    find_program(V0ID_NVIDIA_SMI_EXECUTABLE nvidia-smi)

    execute_process(
        COMMAND "${V0ID_RUSTC_EXECUTABLE}" --version
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE V0ID_RUSTC_RESULT
        OUTPUT_VARIABLE V0ID_RUSTC_VERSION_TEXT
        ERROR_VARIABLE V0ID_RUSTC_VERSION_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_STRIP_TRAILING_WHITESPACE
    )
    if(NOT V0ID_RUSTC_RESULT EQUAL 0)
        message(FATAL_ERROR
            "V0ID TFHE CUDA requires Rust 1.91.1. rustc is present but no usable "
            "toolchain is selected. Run:\n"
            "  rustup toolchain install 1.91.1 --profile minimal\n"
            "The repository rust-toolchain.toml will then select it automatically.\n"
            "rustc said: ${V0ID_RUSTC_VERSION_ERROR}")
    endif()

    string(REGEX MATCH "rustc ([0-9]+\\.[0-9]+\\.[0-9]+)"
        _V0ID_RUSTC_MATCH "${V0ID_RUSTC_VERSION_TEXT}")
    set(V0ID_RUSTC_VERSION "${CMAKE_MATCH_1}")
    if(NOT V0ID_RUSTC_VERSION OR V0ID_RUSTC_VERSION VERSION_LESS "1.91.1")
        message(FATAL_ERROR
            "V0ID TFHE CUDA requires Rust >= 1.91.1 for TFHE-rs 1.6.1; "
            "found '${V0ID_RUSTC_VERSION_TEXT}'. Run:\n"
            "  rustup toolchain install 1.91.1 --profile minimal")
    endif()

    get_filename_component(V0ID_NVCC_REALPATH
        "${V0ID_NVCC_EXECUTABLE}" REALPATH)
    get_filename_component(V0ID_CUDA_BIN_DIR
        "${V0ID_NVCC_REALPATH}" DIRECTORY)
    get_filename_component(V0ID_CUDA_TOOLKIT_ROOT
        "${V0ID_CUDA_BIN_DIR}" DIRECTORY)

    execute_process(
        COMMAND "${V0ID_NVCC_REALPATH}" --version
        RESULT_VARIABLE V0ID_NVCC_RESULT
        OUTPUT_VARIABLE V0ID_NVCC_VERSION_TEXT
        ERROR_VARIABLE V0ID_NVCC_VERSION_ERROR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_STRIP_TRAILING_WHITESPACE
    )
    if(NOT V0ID_NVCC_RESULT EQUAL 0)
        message(FATAL_ERROR
            "V0ID TFHE CUDA found nvcc but could not execute it: "
            "${V0ID_NVCC_VERSION_ERROR}")
    endif()
    string(REGEX MATCH "release ([0-9]+\\.[0-9]+)"
        _V0ID_NVCC_MATCH "${V0ID_NVCC_VERSION_TEXT}")
    set(V0ID_CUDA_TOOLKIT_VERSION "${CMAKE_MATCH_1}")

    set(V0ID_GPU_COMPUTE_CAPABILITY "unknown")
    if(V0ID_NVIDIA_SMI_EXECUTABLE)
        execute_process(
            COMMAND "${V0ID_NVIDIA_SMI_EXECUTABLE}"
                --query-gpu=compute_cap --format=csv,noheader
            RESULT_VARIABLE V0ID_SMI_RESULT
            OUTPUT_VARIABLE V0ID_SMI_COMPUTE_CAPS
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(V0ID_SMI_RESULT EQUAL 0)
            string(REGEX MATCH "^([0-9]+)\\.([0-9]+)"
                _V0ID_CAP_MATCH "${V0ID_SMI_COMPUTE_CAPS}")
            if(CMAKE_MATCH_1)
                set(V0ID_GPU_COMPUTE_CAPABILITY
                    "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}")
            endif()
        endif()
    endif()

    if(NOT V0ID_GPU_COMPUTE_CAPABILITY STREQUAL "unknown"
       AND V0ID_GPU_COMPUTE_CAPABILITY VERSION_GREATER_EQUAL "10.0"
       AND V0ID_CUDA_TOOLKIT_VERSION
       AND V0ID_CUDA_TOOLKIT_VERSION VERSION_LESS "12.8")
        message(FATAL_ERROR
            "V0ID TFHE CUDA detected a Blackwell-class GPU (compute capability "
            "${V0ID_GPU_COMPUTE_CAPABILITY}) but nvcc is CUDA Toolkit "
            "${V0ID_CUDA_TOOLKIT_VERSION}. Blackwell requires CUDA Toolkit >= 12.8. "
            "nvidia-smi reports driver capability, not the installed nvcc toolkit. "
            "Install/select CUDA Toolkit 12.8 or newer, then re-run the gpu-fhe preset.")
    endif()

    set(V0ID_TFHE_CUDA_MANIFEST
        "${CMAKE_SOURCE_DIR}/rust/v0id_tfhe_cuda/Cargo.toml")
    set(V0ID_TFHE_CUDA_TARGET_DIR
        "${CMAKE_BINARY_DIR}/tfhe-cuda-target")
    set(V0ID_TFHE_CUDA_LIBRARY
        "${V0ID_TFHE_CUDA_TARGET_DIR}/release/libv0id_tfhe_cuda.so")

    add_custom_command(
        OUTPUT "${V0ID_TFHE_CUDA_LIBRARY}"
        COMMAND ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${V0ID_TFHE_CUDA_TARGET_DIR}
            CUDACXX=${V0ID_NVCC_REALPATH}
            CUDAHOSTCXX=${CMAKE_CXX_COMPILER}
            CUDA_HOME=${V0ID_CUDA_TOOLKIT_ROOT}
            CUDAToolkit_ROOT=${V0ID_CUDA_TOOLKIT_ROOT}
            "PATH=${V0ID_CUDA_BIN_DIR}:$ENV{PATH}"
            ${V0ID_CARGO_EXECUTABLE} build
                --manifest-path ${V0ID_TFHE_CUDA_MANIFEST}
                --release
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS
            "${V0ID_TFHE_CUDA_MANIFEST}"
            "${CMAKE_SOURCE_DIR}/rust-toolchain.toml"
            "${CMAKE_SOURCE_DIR}/rust/v0id_tfhe_cuda/src/lib.rs"
            "${CMAKE_SOURCE_DIR}/rust/v0id_tfhe_cuda/src/cloud.rs"
        USES_TERMINAL
        VERBATIM
        COMMENT "Building V0ID TFHE-rs CUDA sidecar"
    )

    add_custom_target(v0id-tfhe-cuda-sidecar
        DEPENDS "${V0ID_TFHE_CUDA_LIBRARY}")

    add_library(v0id_tfhe_cuda SHARED IMPORTED GLOBAL)
    set_target_properties(v0id_tfhe_cuda PROPERTIES
        IMPORTED_LOCATION "${V0ID_TFHE_CUDA_LIBRARY}"
        IMPORTED_NO_SONAME TRUE
    )

    if(NOT TARGET v0id_encrypted_boolean_program)
        message(FATAL_ERROR "V0ID TFHE CUDA hook ran before encrypted evaluator target existed")
    endif()
    if(NOT TARGET v0id_net)
        message(FATAL_ERROR "V0ID TFHE CUDA hook ran before network transport target existed")
    endif()

    target_sources(v0id_encrypted_boolean_program PRIVATE
        "${CMAKE_SOURCE_DIR}/src/fhe/gpu_fhe_backend.cpp")
    target_compile_definitions(v0id_encrypted_boolean_program PUBLIC
        V0ID_GPU_FHE_ENABLED=1)
    target_link_libraries(v0id_encrypted_boolean_program PUBLIC
        v0id_tfhe_cuda)
    add_dependencies(v0id_encrypted_boolean_program
        v0id-tfhe-cuda-sidecar)

    if(TARGET v0id-encrypted-boolean-program-tests)
        target_compile_definitions(v0id-encrypted-boolean-program-tests PRIVATE
            V0ID_GPU_FHE_ENABLED=1)
        add_dependencies(v0id-encrypted-boolean-program-tests
            v0id-tfhe-cuda-sidecar)
        set_target_properties(v0id-encrypted-boolean-program-tests PROPERTIES
            BUILD_RPATH "${V0ID_TFHE_CUDA_TARGET_DIR}/release")
    endif()

    # Two-tier validation split:
    #   A) tiny real TFHE program exercises the cryptographic/cloud path;
    #   B) full SHA3 + polymorphism execute client-side for fast semantic checks.
    # The old full homomorphic SHA3 executable remains available as an explicit
    # milestone/stress route rather than being the normal regression loop.
    add_executable(v0id-small-fhe-smoke-tests
        "${CMAKE_SOURCE_DIR}/src/integrity/small_fhe_smoke_tests.cpp")
    target_include_directories(v0id-small-fhe-smoke-tests PRIVATE
        "${CMAKE_SOURCE_DIR}/src/fhe"
        "${CMAKE_SOURCE_DIR}/src/integrity")
    target_link_libraries(v0id-small-fhe-smoke-tests PRIVATE
        v0id_encrypted_boolean_program)
    target_compile_definitions(v0id-small-fhe-smoke-tests PRIVATE
        V0ID_GPU_FHE_ENABLED=1)
    add_dependencies(v0id-small-fhe-smoke-tests
        v0id-tfhe-cuda-sidecar)
    set_target_properties(v0id-small-fhe-smoke-tests PROPERTIES
        BUILD_RPATH "${V0ID_TFHE_CUDA_TARGET_DIR}/release")

    # Network protocol codec stays independent of the FHE implementation, while
    # this demo binds it to the real streamed TFHE CUDA evaluator boundary.
    add_executable(v0id-tfhe-cloud-codec-tests
        "${CMAKE_SOURCE_DIR}/src/net/tfhe_cloud_codec_tests.cpp"
        "${CMAKE_SOURCE_DIR}/src/net/tfhe_cloud_codec.cpp")
    target_include_directories(v0id-tfhe-cloud-codec-tests PRIVATE
        "${CMAKE_SOURCE_DIR}/src/net")
    target_link_libraries(v0id-tfhe-cloud-codec-tests PRIVATE v0id_net)

    add_executable(v0id-tfhe-cloud
        "${CMAKE_SOURCE_DIR}/src/net/tfhe_cloud_demo.cpp"
        "${CMAKE_SOURCE_DIR}/src/net/tfhe_cloud_codec.cpp")
    target_include_directories(v0id-tfhe-cloud PRIVATE
        "${CMAKE_SOURCE_DIR}/src/net"
        "${CMAKE_SOURCE_DIR}/src/fhe"
        "${CMAKE_SOURCE_DIR}/src/integrity")
    target_link_libraries(v0id-tfhe-cloud PRIVATE
        v0id_net
        v0id_encrypted_boolean_program)
    target_compile_definitions(v0id-tfhe-cloud PRIVATE
        V0ID_GPU_FHE_ENABLED=1)
    add_dependencies(v0id-tfhe-cloud
        v0id-tfhe-cuda-sidecar)
    set_target_properties(v0id-tfhe-cloud PROPERTIES
        BUILD_RPATH "${V0ID_TFHE_CUDA_TARGET_DIR}/release")

    add_custom_target(v0id-test-large-client
        COMMAND $<TARGET_FILE:v0id-sha3-image-tests>
        COMMAND $<TARGET_FILE:v0id-round-morph-schedule-tests>
        DEPENDS
            v0id-sha3-image-tests
            v0id-round-morph-schedule-tests
        USES_TERMINAL
        COMMENT "Running fast large client-side SHA3 + polymorphism validation")

    add_custom_target(v0id-test-small-fhe
        COMMAND $<TARGET_FILE:v0id-small-fhe-smoke-tests>
        DEPENDS v0id-small-fhe-smoke-tests
        USES_TERMINAL
        COMMENT "Running tiny real TFHE CUDA validation")

    add_custom_target(v0id-test-milkshake
        COMMAND $<TARGET_FILE:v0id-sha3-image-tests>
        COMMAND $<TARGET_FILE:v0id-round-morph-schedule-tests>
        COMMAND $<TARGET_FILE:v0id-small-fhe-smoke-tests>
        DEPENDS
            v0id-sha3-image-tests
            v0id-round-morph-schedule-tests
            v0id-small-fhe-smoke-tests
        USES_TERMINAL
        COMMENT "Running V0ID fast-large + small-homomorphic validation split")

    add_custom_target(v0id-test-large-fhe-stress
        COMMAND $<TARGET_FILE:v0id-encrypted-boolean-program-tests>
        DEPENDS v0id-encrypted-boolean-program-tests
        USES_TERMINAL
        COMMENT "Running full mutated SHA3 through streamed TFHE CUDA (slow stress route)")

    add_custom_target(v0id-test-tfhe-cloud-codec
        COMMAND $<TARGET_FILE:v0id-tfhe-cloud-codec-tests>
        DEPENDS v0id-tfhe-cloud-codec-tests
        USES_TERMINAL
        COMMENT "Running TFHE ZeroMQ cloud framing regression tests")

    message(STATUS "V0ID TFHE CUDA backend: ENABLED")
    message(STATUS "  cargo       : ${V0ID_CARGO_EXECUTABLE}")
    message(STATUS "  rustc       : ${V0ID_RUSTC_VERSION_TEXT}")
    message(STATUS "  nvcc        : ${V0ID_NVCC_REALPATH} (CUDA ${V0ID_CUDA_TOOLKIT_VERSION})")
    message(STATUS "  CUDA root   : ${V0ID_CUDA_TOOLKIT_ROOT}")
    message(STATUS "  GPU CC      : ${V0ID_GPU_COMPUTE_CAPABILITY}")
    message(STATUS "  Rust sidecar: ${V0ID_TFHE_CUDA_LIBRARY}")
    message(STATUS "  TFHE cloud  : v0id-tfhe-cloud (ZeroMQ multipart)")
endfunction()

cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}"
    CALL v0id_finish_tfhe_cuda_setup)
