# Extend the existing TFHE CUDA project include with the local web/control-plane
# adapter. Keep the core CUDA setup in its original file so non-dashboard users
# can still include it independently if desired.
include("${CMAKE_SOURCE_DIR}/cmake/V0idTfheCuda.cmake")

function(v0id_finish_tfhe_remote_control_setup)
    if(NOT V0ID_ENABLE_GPU_FHE)
        return()
    endif()

    if(NOT TARGET v0id_control OR NOT TARGET v0id-local-control)
        message(FATAL_ERROR
            "V0ID TFHE remote control hook ran before local control targets existed")
    endif()
    if(NOT TARGET v0id_encrypted_boolean_program)
        message(FATAL_ERROR
            "V0ID TFHE remote control requires v0id_encrypted_boolean_program")
    endif()

    target_sources(v0id_control PRIVATE
        "${CMAKE_SOURCE_DIR}/src/control/tfhe_remote_control.cpp"
        "${CMAKE_SOURCE_DIR}/src/net/tfhe_cloud_client.cpp"
        "${CMAKE_SOURCE_DIR}/src/net/tfhe_cloud_codec.cpp"
        "${CMAKE_SOURCE_DIR}/src/net/curve_peer_transport.cpp")

    target_include_directories(v0id_control PUBLIC
        "${CMAKE_SOURCE_DIR}/src/fhe"
        "${CMAKE_SOURCE_DIR}/src/integrity")

    target_link_libraries(v0id_control PUBLIC
        v0id_encrypted_boolean_program
        Threads::Threads)

    target_compile_definitions(v0id_control PRIVATE
        V0ID_CONTROL_HAVE_TFHE_CLOUD=1
        V0ID_GPU_FHE_ENABLED=1)
    target_compile_definitions(v0id-local-control PRIVATE
        V0ID_LOCAL_CONTROL_HAVE_TFHE_CLOUD=1)

    if(TARGET v0id-tfhe-cuda-sidecar)
        add_dependencies(v0id-local-control v0id-tfhe-cuda-sidecar)
    endif()

    set_target_properties(v0id-local-control PROPERTIES
        BUILD_RPATH "${CMAKE_BINARY_DIR}/tfhe-cuda-target/release")

    if(UNIX AND NOT APPLE)
        target_link_options(v0id-local-control PRIVATE -Wl,--no-as-needed)
    endif()

    message(STATUS
        "V0ID local control: remote encrypted TFHE submission ENABLED")
endfunction()

# V0idTfheCuda.cmake registered its deferred setup first. This second deferred
# hook therefore runs after the TFHE sidecar/imported target has been created and
# after the top-level CMakeLists has declared v0id_control.
cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}"
    CALL v0id_finish_tfhe_remote_control_setup)
