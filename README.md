# NullGate
This project implements a comfortable and modern way to use the NTAPI functions using indirect syscalls, coupled with the [FreshyCalls](https://github.com/crummie5/FreshyCalls) method with a little twist for dynamic syscall number retrieval.
It also uses a technique that I haven't seen being mentioned to bypass windows defender's memory scanning. 
The project implements a classic PoC process injector using the library.
Convenient functions for encryption are also available.

## Demo
![Demonstration of the sample](./assets/demo.gif)

## Usage
> [!NOTE]
> The following examples will use `namespace ng = nullgate` 

### Syscalls
The usage is pretty straight forward, here is a snippet demonstrating the main functionality:
```cpp
ng::syscalls syscalls;
typedef NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress,
                 _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize)
                     _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType, _In_ ULONG PageProtection);

NTSTATUS status = syscalls.SCall<NtAllocateVirtualMemory>(
      ng::obfuscation::fnv1Const("NtAllocateVirtualMemory"), processHandle,
      &buf, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
There's builtin type-safety. 
You just need to provide the definition of the nt function that you want to call! You can easily get that from [ntdoc](https://ntdoc.m417z.com/).
This is the <b>recommended</b> way to use the lib.
#### The previous non-deprecated interface
For people who don't like c++ templating black magic or something the previous interface is still available:
```cpp
NTSTATUS status = syscalls.Call(ng::obfuscation::fnv1Const("NtAllocateVirtualMemory"),
                         processHandle, (PVOID)&buf, (ULONG_PTR)0, &regionSize,
                         (ULONG)(MEM_RESERVE | MEM_COMMIT), (ULONG)PAGE_EXECUTE_READWRITE);
```
Using this interface you <b>need</b> to cast the arguments to the right type, not doing this may cause [problems](https://github.com/0xsch1zo/NullGate/issues/2). 

### Encryption/hashing
#### Hashing ntapi calls
```cpp
constexpr uint64_t hash = ng::obfuscation::fnv1Const("NtAllocateVirtualMemory");
```
The previously demonstrated `fnv1Const` method brings the joys of modern C++ to the maldev world. It is a `consteval` function, so it is guaranteed that it will get evaluated at compile time, replacing the readable function name with a fnv1 hash.<br><br>
There is also a runtime equivalent called `fnv1Runtime` but of course it doesn't add the benefit of having our function names obfuscated. It is used by the implementation to check which function inside of ntdll to get the syscall number of.
#### General xor encryption

There are three routines for xor "encryption":
##### xorConst
```cpp
constexpr ng::obfuscation::ConstData xored = ng::obfuscation::xorConst("some string");
std::cout << xored.string();
```
Possible output:
```
<Y:-E&X0
```
This routine similarly to the `fnv1Const` function, is evaluated at compiler time, so `"some string"` will never appear in the binary, because the string will be stored in its encrypted form.
But hey we need to actually make use of that data! `ConstData` is a thin wrapper around raw bytes that is of constant size. 
It has two methods `raw()` and `string()`.
`raw()` returns an `std::vector<unsigned char>` and `string` as the name suggests returns an `std::string`.
> [!NOTE]
> If you need to construct `ConstData` directly with a string literal use `std::to_array` to construct an intermediate array passed down to `ConstData`. 
> Please note however that with this approach `ConstData` will be storing the additional null character of the literal.

Of course we need a way to decrypt this and use it, which is the next function we will cover.

##### xorRuntime
`xorRuntime` is the second routine that is available.
As the name suggests it is the runtime equivalent of `xorConst`.
Please note that it doesn't have to only be used for decryption it works both ways, although using it for encryption doesn't have the benefits of obfuscating the string at compile time.
```cpp
ng::obfuscation::ConstData xored = ng::obfuscation::xorConst("some string");
ng::obfuscation::ConstData data = ng::obfuscation::xorRuntime(xored);
assert(data.string() == "some string");

std::string dynamicString = "some data of dynamic size";
auto dynamicData = ng::obfuscation::DynamicData(dynamicString);
auto xoredDynamic = ng::obfuscation::xorRuntime(dynamicData);
auto unxoredDynamic = ng::obfuscation::xorRuntime(xoredDynamic);
assert(unxoredDynamic.string() == dynamicString);
```
`DynamicData` has the same methods as `ConstData` with some added constructors for interoperability, and as the name suggests can be of size not known at compile time.
`xorRuntime` accepts both `DynamicData` and `ConstData`.

##### xorRuntimeDecrypted
While we could always decrypt at runtime by first calling `xorConst` and passing the result to `xorRuntime` that's kind of tedious
Here comes the solution to this problem, the cherry on top which is `xorRuntimeDecrypted` it is a handy function for string literals that don't need to be operated on while they're in the encrypted state.
It encrypts the string literal at compile time and then decrypts it at runtime all in one call. Isn't it cool!.
```cpp
ng::obfuscation::ConstData text = ng::obfuscation::xorRuntimeDecrypted<"some string">();
assert(data.string() == "some string");
```
##### The key
Now someone might say everything is great but where is the key? In nullgate 1.2 the key gets randomly generated per each fresh build made!(meaning the cmake command is run)
This reduces the chance of getting signatured even more.

### Adding nullgate to your project
CMake FetchContent is supported. Here is an example of a simple CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.25)

include(FetchContent)

FetchContent_Declare(nullgate
    GIT_REPOSITORY https://github.com/0xsch1zo/NullGate
    GIT_TAG 1.2.0 
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
> If you are using linux you need to have the mingw cross-compiler installed. On Arch for example you can do `pacman -S mingw-w64-gcc`. Then use the `-DNULLGATE_CROSSCOMPILE=ON` option to set mingw as the default compiler.
```
git clone https://github.com/0xsch1zo/NullGate
cd NullGate
cmake . -B build -DNULLGATE_BUILD_SAMPLE=ON
cmake --build build/
```
It is also recommended to strip the resulting binary to decrease the possibility of detection

### Deprecated hashser(versions 1.1.3 and below)
It can be built using the `-DNULLGATE_DEPRECATED_HASHER` flag.

## Windows defender memory scan bypass
The core of the issue is that when we call `NtCreateRemoteThreadEx` or `NtCreateProcess`, a memory scan gets triggered and our signatured as hell msfvenom payload gets detected.

### How to bypass that?
A known solution is to first when calling `NtAllocateVirtualMemory` set the page permissions as `PAGE_NOACCESS`, then create the thread in a suspended state. 
When windows defender will scan the memory of our process it will fail to do that.
We can then resume the execution of our thread with `NtResumeThread`.
This works, but what if a more competent security solution is being used? What would it do? 
It would of course just use `VirtualProtect` to change the permissions of our page and detect msfvenom. 
To bypass that I changed the strategy a bit. Instead of setting the page as `PAGE_NOACCESS`, during our first write to the memory of the process we can just put some junk data into the process(Yes it is required, or I'm just too stupid to find a way to get it working without this). 
Then we create a thread in suspended state. 
After that we write to the process our desired shellcode and finally we resume the thread using `NtResumeThread`. 
With this technique we don't have to worry about our memory being accessed after the call to `NtCreateThreadEx` because there is nothing in there. 
Only after the fact the decrypted shellcode is written and the execution is resumed.

## Acknowledgments:
- To [@ElephantSe4l](https://github.com/ElephantSe4l) and [@MarioBartolome](https://github.com/MarioBartolome) for a great method of dynamic syscall number retrieval and generally the whole project from which I've taken great inspiration of of.
- To [@cr-0w](https://github.com/cr-0w) for the amazing [blog post](https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/indirect-syscalls) and [video](https://www.youtube.com/watch?v=-M2_mZg_2Ew) discussing direct and indirect syscalls.
- To [bordergate](https://www.bordergate.co.uk/) for the [article](https://www.bordergate.co.uk/windows-defender-memory-scanning-evasion/) that describes the initial method of bypass.

## Disclaimer
This library was made for academic purposes only. The authors are not responsible for what is given to this library and therefore we are exempt from any liability arising from the misuse of it.
