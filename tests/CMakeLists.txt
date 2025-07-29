#cmake_minimum_required(VERSION 3.25)

#add_subdirectory(.. ${PROJECT_BINARY_DIR}/nullgate)

include(CTest)
add_executable(xor xor.cpp)
target_link_libraries(xor PRIVATE nullgate)
add_test(NAME xor COMMAND wine xor.exe)
