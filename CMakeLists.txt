cmake_minimum_required(VERSION 3.25)
project(minBp VERSION 1.0.0 LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wno-unused-parameter
)
find_path(KVM_INCLUDE_DIR linux/kvm.h
        PATHS /usr/include /usr/local/include
        REQUIRED
)

message(STATUS "KVM headers found at: ${KVM_INCLUDE_DIR}")
file(GLOB_RECURSE KVM_HEADERS CONFIGURE_DEPENDS
        ${CMAKE_SOURCE_DIR}/include/*.h
        ${CMAKE_SOURCE_DIR}/include/*.hpp
)

add_library(kvm_hypervisor_lib STATIC)

target_sources(kvm_hypervisor_lib
        PRIVATE
        src/KvmSystem.cpp
        src/VirtualMachine.cpp
        src/VCpu.cpp
        src/MemoryRegion.cpp
        src/InstructionTrapper.cpp
        src/CpuidHandler.cpp
        src/IoPortHandler.cpp
        src/MsrHandler.cpp
        src/MmioHandler.cpp
        src/VmiAgent.cpp
        src/EventDispatcher.cpp
        src/GuestLoader.cpp

        PUBLIC
        FILE_SET HEADERS
        BASE_DIRS ${CMAKE_SOURCE_DIR}/include
        FILES ${KVM_HEADERS}
)

target_include_directories(kvm_hypervisor_lib
        PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${KVM_INCLUDE_DIR}
)

add_executable(kvm_hypervisor src/main.cpp)

target_link_libraries(kvm_hypervisor
        PRIVATE
        kvm_hypervisor_lib
)

option(MINBP_BUILD_TESTS "Build minBp unit tests" ON)

if (MINBP_BUILD_TESTS)
    enable_testing()

    FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_subdirectory(tests)
endif()