#include <cstring>
#include <nullgate/obfuscation.hpp>
#include <nullgate/syscalls.hpp>
#include <stdexcept>
#include <winternl.h>

extern "C" NTSTATUS NTAPI nullgate_trampoline(void *, ...);

namespace nullgate {

#ifndef NDEBUG
#define NULLGATE_DEBUG
#endif

syscalls::syscalls() {
  populateStubs();
  populateSyscalls();
}

NTSTATUS NTAPI (*const syscalls::nullgate_trampoline)(syscallArgs *, ...) =
    reinterpret_cast<decltype(syscalls::nullgate_trampoline)>(
        &::nullgate_trampoline); // insanity

using ob = obfuscation;

void syscalls::populateStubs() {
  PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
  // ntdll is always the first module after the executable to be loaded
  const auto ntdllLdrEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
      // NIGHTMARE NIGHTMARE NIGHTMARE
      CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink->Flink,
                        LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
  const auto ntdllBase = reinterpret_cast<PBYTE>(ntdllLdrEntry->DllBase);

  const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdllBase);
  // e_lfanew points to ntheaders(microsoft's great naming)
  const auto ntHeaders =
      reinterpret_cast<PIMAGE_NT_HEADERS>(ntdllBase + dosHeaders->e_lfanew);
  const auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      ntdllBase +
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress);

  const auto functionsTable =
      reinterpret_cast<PDWORD>(ntdllBase + exportDir->AddressOfFunctions);
  const auto namesTable =
      reinterpret_cast<PDWORD>(ntdllBase + exportDir->AddressOfNames);
  const auto ordinalsTable =
      reinterpret_cast<PWORD>(ntdllBase + exportDir->AddressOfNameOrdinals);

  for (DWORD i{}; i < exportDir->NumberOfNames; i++) {
    std::string realFuncName =
        reinterpret_cast<const char *>(ntdllBase + namesTable[i]);

    if (realFuncName.starts_with(ob::xorRuntimeDecrypted<"Zw">().string())) {
      auto funcAddr = reinterpret_cast<PDWORD>(
          ntdllBase + functionsTable[ordinalsTable[i]]);
      const auto funcName =
          ob::xorRuntimeDecrypted<"Nt">().string() + realFuncName.substr(2);
      stubMap.emplace(funcAddr, funcName);
    }
  }
}

void syscalls::populateSyscalls() {
  unsigned int syscallNo{};
  for (const auto &stub : stubMap)
    syscallNoMap.emplace(stub.second, syscallNo++);
}

DWORD syscalls::getSyscallNumber(const std::string &funcName) {
  if (!syscallNoMap.contains(funcName))
#ifdef NULLGATE_DEBUG
    throw std::runtime_error(
        ob::xorRuntimeDecrypted<"Function not found">().string() + funcName);
#else
    throw std::runtime_error("");
#endif

  return syscallNoMap.at(funcName);
}

DWORD syscalls::getSyscallNumber(uint64_t funcNameHash) {
  for (const auto &ntFuncPair : syscallNoMap) {
    if (obfuscation::fnv1Runtime(ntFuncPair.first.c_str()) == funcNameHash)
      return ntFuncPair.second;
  }

#ifdef NULLGATE_DEBUG
  throw std::runtime_error(
      ob::xorRuntimeDecrypted<"Function hash not found">().string() +
      std::to_string(funcNameHash));
#else
  throw std::runtime_error("");
#endif
}

uintptr_t syscalls::getSyscallInstrAddr() {
  auto stubBase = reinterpret_cast<PBYTE>((*stubMap.begin()).first);
  const int maxStubSize = 32; // I have no idea if it can be larger
  const BYTE syscallOpcode[] = {0x0F, 0x05, 0xC3}; // syscall; ret
  for (int i{}; i < maxStubSize; i++) {
    if (memcmp(syscallOpcode, stubBase + i, sizeof(syscallOpcode)) == 0)
      return reinterpret_cast<uintptr_t>(stubBase + i);
  }
#ifdef NULLGATE_DEBUG
  throw std::runtime_error(
      ob::xorRuntimeDecrypted<"Couldn't find a syscall instruction">()
          .string());
#else
  throw std::runtime_error("");
#endif
}

} // namespace nullgate
