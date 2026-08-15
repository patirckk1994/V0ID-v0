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
            ${V0ID_CARGO_EXECUTABLE} build
                --manifest-path ${V0ID_TFHE_CUDA_MANIFEST}
                --release
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS
            "${V0ID_TFHE_CUDA_MANIFEST}"
            "${CMAKE_SOURCE_DIR}/rust/v0id_tfhe_cuda/src/lib.rs"
        USES_TERMINAL
        VERBATIM
        COMMENT "Building V0ID TFHE-rs CUDA sidecar"
    )

    add_custom_target(v0id-tfhe-cuda-sidecar
        DEPENDS "${V0ID_TFHE_CUDA_LIBRARY}")

    add_library(v0id_tfhe_cuda SHARED IMPORTED GLOBAL)
    set_target_properties(v0id_tfhe_cuda PROPERTIES
        IMPORTED_LOCATION "${V0ID_TFHE_CUDA_LIBRARY}"
    )

    if(NOT TARGET v0id_encrypted_boolean_program)
        message(FATAL_ERROR "V0ID TFHE CUDA hook ran before encrypted evaluator target existed")
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

    message(STATUS "V0ID TFHE CUDA backend: ENABLED")
    message(STATUS "  cargo : ${V0ID_CARGO_EXECUTABLE}")
    message(STATUS "  rustc : ${V0ID_RUSTC_EXECUTABLE}")
    message(STATUS "  nvcc  : ${V0ID_NVCC_EXECUTABLE}")
    message(STATUS "  Rust sidecar: ${V0ID_TFHE_CUDA_LIBRARY}")
endfunction()

# This file is loaded through CMAKE_PROJECT_INCLUDE by the GPU preset. Defer the
# target wiring until the top-level CMakeLists has created the evaluator targets.
cmake_language(DEFER CALL v0id_finish_tfhe_cuda_setup)
