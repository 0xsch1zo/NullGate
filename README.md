# NullGate
This project implements a comfortable and modern way to use the NTAPI functions using indirect syscalls, coupled with the [FreshyCalls](https://github.com/crummie5/FreshyCalls) method with a little twist for dynamic syscall number retrieval.
It also uses a technique that I haven't seen being metioned to bypass windows defender's memory scanning. It also implements a classic PoC process injector.

## Demo
![Demonstration of the sample](./assets/demo.gif)

## Usage

The usage is pretty straight forward, here is a snippet demonstrating the main functionality:
```cpp
nullgate::syscalls syscalls;
typedef NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress,
                 _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize)
                     _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType, _In_ ULONG PageProtection);

auto status = syscalls.SCall<NtAllocateVirtualMemory>(
      nullgate::obfuscation::fnv1Const("NtAllocateVirtualMemory"), processHandle,
      &buf, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
There's builtin typesafety. You just need to provide the definiton of the nt function that you want to call! You can easily get that from [ntdoc](https://ntdoc.m417z.com/). This is the recommended way to use the lib.<br><br>
For people who don't like c++ templating black magic or something the previous interface is still available:
```cpp
auto status = syscalls.Call(nullgate::obfuscation::fnv1Const("NtAllocateVirtualMemory"),
                         processHandle, (PVOID)&buf, (ULONG_PTR)0, &regionSize,
                         (ULONG)(MEM_RESERVE | MEM_COMMIT), (ULONG)PAGE_EXECUTE_READWRITE);
```
Using this interface you <b>need</b> to cast the arguments to the right type, not doing this may cause [problems](https://github.com/0xsch1zo/NullGate/issues/2). <br><br>
The `fnv1Const` method brings the joys of modern C++ to the maldev world. It is a `consteval` function, so it is guaranteed that it will get evaluated at compile time, replacing the readable function name with a fnv1 hash.<br><br>
There is also a runtime equivalent called `fnv1Runtime` but of course it doesn't add the benefit of having our function names obfuscated. It is used by the implementation to check which function inside of ntdll to get the syscall number of.<br><br>
There are routines that can xor encrypt/decrypt(multibyte key) and base64 encode/decode your payload or some message:
```cpp
if (!NT_SUCCESS(status))
    throw std::runtime_error(
        nullgate::obfuscation::xorDecode("BQkEI1c0dkJ4LU4naSJhGCcIFSNWej5YeD5DNmkzM"
                               "x8lAwI8H3o3VzEmTjdpNCgELlxR") +
        std::to_string(status));
```
The key for now is `FfqO3ZQ6XJ+SICAp`. 
A hasher is also provided, after building the project, the binary will be accessible at `hasher-build/`(Before 1.1.2 it's `<build_dir>/_deps/nullgate-build/src/hasher`). 
On windows it will probably be nested beneath a bunch of directories like `Release`, but it will be somewhere there.
Just pipe something into it and it will spit out a base64 encoded and xored string.<br><br>

To ease the encryption of shellcode a special functon is provided:
```cpp
auto decryptedShellcode =
      nullgate::obfuscation::hex2bin(nullgate::obfuscation::xorDecode(encryptedShellcode))
```
The `hex2bin` function just turns a hex string into a vector of bytes, thanks to this you can just pipe the shellcode from msfvenom with the `-f hex` flag straight into the hasher and not have worry about the special characters.

### Adding nullgate to your project
CMake FetchContent is supported. Here is an example of a simple CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.25)

include(FetchContent)

FetchContent_Declare(nullgate
    GIT_REPOSITORY https://github.com/0xsch1zo/NullGate
    GIT_TAG 1.1.3
)

FetchContent_MakeAvailable(nullgate)

project(test)

add_executable(test
    main.cpp
)

target_link_libraries(test
    PRIVATE nullgate
)
```
The linking is done statically so you don't have to worry about symbols being visible.
## Build
To build the sample use `-DNULLGATE_BUILD_SAMPLE=ON`. 
If you built nullgate directly it will be accessible at `<build_dir>/sample.exe`, if you built it as a dependency at `<build_dir>/_deps/nullgate-build/sample.exe`. 
On windows because the build destinations are weird, it will probably be at the same base directories of locations of samples but probably nested a bunch more.
It takes a PID that you want to inject shellcode into as an argument.
> [!WARNING]
> If you are using linux you need to have the mingw crosscompiler installed. On Arch for example you can do `pacman -S mingw-w64-gcc`. Then use the `-DNULLGATE_CROSSCOMPILE=ON` option to set mingw as the default compiler for the relevant parts of the program.
```
git clone https://github.com/0xsch1zo/NullGate
cd NullGate
cmake . -B build -DNULLGATE_BUILD_SAMPLE=ON
cmake --build build/
```

## Windows defender memory scan bypass
The core of the issue is that when we call `NtCreateRemoteThreadEx` or `NtCreateProcess`, a memory scan gets triggered and our signatured as hell msfvenom payload gets detected.

### How to bypass that?
A known solution is to first when calling `NtAllocateVirtualMemory` set the page permissions as `PAGE_NOACCESS`, then create the thread in a suspended state. 
When windows defender will scan the memory of our process it will fail to do that.
We can then resume the execution of our thread with `NtResumeThread`.
This works, but what if a more competent security solution is being used? What would it do? 
It would of course just use `VirtualProtect` to change the permissions of our page and detect msfvenom. 
To bypass that I changed the strategy a bit. Instead of setting the page as `PAGE_NOACCESS`, during our first write to the memory of the process we can just put some junk data into the process(Yes it is required, or I'm just too stupid to find a way to get it working wihout this). 
Then we create a thread in suspended state. 
After that we write to the process our desired shellcode and finally we resume the thread using `NtResumeThread`. 
With this technique we don't have to worry about our memory being accessed after the call to `NtCreateThreadEx` because there is nothing in there. 
Only after the fact the decrypted shellcode is written and the execution is resumed.

## Credits:
- To [@ElephantSe4l](https://github.com/ElephantSe4l) and [@MarioBartolome](https://github.com/MarioBartolome) for a great method of dynamic syscall number retrieval and generally the whole project from which I've taken great inspiration of of.
- To [@cr-0w](https://github.com/cr-0w) for the amazing [blog post](https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/indirect-syscalls) and [video](https://www.youtube.com/watch?v=-M2_mZg_2Ew) discussing direct and indirect syscalls.
- To [bordergate](https://www.bordergate.co.uk/) for the [article](https://www.bordergate.co.uk/windows-defender-memory-scanning-evasion/) that describes the initial method of bypass.
