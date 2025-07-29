include(CTest)
add_executable(xor xor.cpp)
target_link_libraries(xor PRIVATE nullgate)

if (NULLGATE_CROSSCOMPILE)
    add_test(NAME xor COMMAND wine xor.exe)
else()
    add_test(NAME xor COMMAND xor.exe)
endif()
