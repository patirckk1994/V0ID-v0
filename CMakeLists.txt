cmake_minimum_required(VERSION 3.20)
project(v0id LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenFHE CONFIG REQUIRED)
find_package(OpenSSL 3 REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")

include_directories(
    ${OPENMP_INCLUDES}
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/third-party/include
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)

link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})

if(OpenFHE_SHARED)
    link_libraries(${OpenFHE_SHARED_LIBRARIES})
else()
    link_libraries(${OpenFHE_STATIC_LIBRARIES})
endif()

add_executable(v0id src/main.cpp)
target_link_libraries(v0id PRIVATE OpenSSL::Crypto)

if(UNIX AND NOT APPLE)
    target_link_options(v0id PRIVATE -Wl,--no-as-needed)
endif()
