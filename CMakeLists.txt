cmake_minimum_required(VERSION 3.25)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS OFF)

if (WIN32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "")
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "")
endif()

set(HASHER_BUILD_DIR ${CMAKE_SOURCE_DIR}/hasher-build)
option(NULLGATE_BUILD_SAMPLE "Build sample" OFF)
option(NULLGATE_CROSSCOMPILE
    "Crosscompile from linux to windows(uses mingw)" OFF)
option(NULLGATE_DEPRECATED_HASHER
    "Compile the hasher which is unnecessary for v1.2.0" OFF)

message("┌─ Nullgate options ─────────────────────")
message("│ NULLGATE_BUILD_SAMPLE        : ${NULLGATE_BUILD_SAMPLE}")
message("│ NULLGATE_CROSSCOMPILE        : ${NULLGATE_CROSSCOMPILE}")
message("│ NULLGATE_DEPRECATED_HASHER   : ${NULLGATE_DEPRECATED_HASHER}")
message("└────────────────────────────────────────")

if (NULLGATE_CROSSCOMPILE)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
    set(CMAKE_ASM_COMPILER x86_64-w64-mingw32-g++)
endif()

if (WIN32)
    project(nullgate CXX ASM_MASM)
else()
    project(nullgate CXX ASM)
endif()

project(sample)

# Nullgate
if (WIN32)
    add_library(nullgate
        ./src/nullgate/syscalls_masm.asm
        ./src/nullgate/syscalls.cpp
        ./src/nullgate/obfuscation.cpp
        ./include/nullgate/syscalls.hpp
        ./include/nullgate/obfuscation.hpp
    )
else()
    add_library(nullgate
        ./src/nullgate/syscalls.S
        ./src/nullgate/syscalls.cpp
        ./src/nullgate/obfuscation.cpp
        ./include/nullgate/syscalls.hpp
        ./include/nullgate/obfuscation.hpp
    )
endif()

target_include_directories(nullgate
    PUBLIC ./include/
)

target_compile_features(nullgate
    PUBLIC cxx_std_23
)

string(RANDOM LENGTH 8 KEY)
target_compile_definitions(nullgate
    PUBLIC NULLGATE_KEY=${KEY}
)

if (WIN32)
    target_compile_options(nullgate
        PUBLIC /MT
    )
else()
    target_link_options(nullgate
        PUBLIC -static
    )

    target_compile_options(nullgate
        PRIVATE -s -O3
    )
endif()


if(NULLGATE_BUILD_SAMPLE)
    add_executable(sample
        ./src/sample/sample.cpp
    )

    target_include_directories(sample
        PRIVATE ./include/
    )

    target_link_libraries(sample
        PRIVATE nullgate
    )

    if (NOT WIN32)
        target_compile_options(sample
            PRIVATE -s -O3
        )
    endif()
endif()

if (NULLGATE_DEPRACTED_HASHER)
    include(ExternalProject)

    ExternalProject_Add(hasher
        PREFIX ${PROJECT_SOURCE_DIR}/src/hasher
        SOURCE_DIR ${PROJECT_SOURCE_DIR}/src/hasher
        BINARY_DIR ${HASHER_BUILD_DIR}
        DOWNLOAD_DIR ${HASHER_BUILD_DIR}
        TMP_DIR ${HASHER_BUILD_DIR}
        STAMP_DIR ${HASHER_BUILD_DIR}
        INSTALL_COMMAND ""
    )
endif()

