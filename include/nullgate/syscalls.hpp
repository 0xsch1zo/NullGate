#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <nullgate/obfuscation.hpp>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <windows.h>

namespace nullgate {

class syscalls {
private:
  struct syscallArgs {
    size_t syscallNo;
    uintptr_t syscallAddr;
    uintptr_t firstArg;
  };
  static NTSTATUS NTAPI (*const nullgate_trampoline)(syscallArgs *, ...);

private:
  std::map<PDWORD, std::string> stubMap;
  std::unordered_map<std::string, DWORD> syscallNoMap;
  void populateStubs();
  void populateSyscalls();
  DWORD getSyscallNumber(const std::string &func);
  DWORD getSyscallNumber(uint64_t funcNameHash);
  uintptr_t getSyscallInstrAddr();

  template <std::size_t N, typename... Args>
  static constexpr auto split_pack(Args &&...args) {
    static_assert(N < sizeof...(Args),
                  "N needs to be smaller than the parameter pack itself");
    return []<std::size_t... I, std::size_t... J>(std::index_sequence<I...>,
                                                  std::index_sequence<J...>,
                                                  std::tuple<Args &&...> t) {
      return std::pair{std::make_tuple(std::get<I>(t)...),
                       std::make_tuple(std::get<N + J>(t)...)};
    }(std::make_index_sequence<N>{},
           std::make_index_sequence<sizeof...(Args) - N>{},
           std::forward_as_tuple(std::forward<Args>(args)...));
  }

  template <typename... Args>
  static NTSTATUS NTAPI trampoline(size_t syscallNo, uintptr_t syscallAddr,
                                   Args &&...args) {
    // NIGHTMARE NIGHTMARE NIGHTMARE
    syscallArgs sargs;
    if constexpr (sizeof...(Args) >= 1) {
      auto &&firstArg =
          std::get<0>(std::forward_as_tuple(std::forward<Args>(args)...));
      sargs = syscallArgs{.syscallNo = syscallNo,
                          .syscallAddr = syscallAddr,
                          .firstArg = (uintptr_t)firstArg};
    } else {
      sargs = syscallArgs{.syscallNo = syscallNo,
                          .syscallAddr = syscallAddr,
                          .firstArg = reinterpret_cast<uintptr_t>(nullptr)};
    }

    if constexpr (sizeof...(Args) > 1) {
      auto &&[first, rest] = split_pack<1>(std::forward<Args>(args)...);
      return std::apply(
          [&](auto &&...args) { return nullgate_trampoline(&sargs, args...); },
          rest);
    } else {
      return nullgate_trampoline(&sargs);
    }
  }

  // Either forwards args perferctly or if they're not compatible casts them
  // to the right type
  template <typename To, typename T> auto forwardCast(T &&t) -> To {
    using ForwardedType = decltype(std::forward<T>(t));

    static_assert(
        !(std::is_rvalue_reference_v<To> &&
          std::is_lvalue_reference_v<ForwardedType>),
        "Error: Cannot bind an rvalue reference to an lvalue reference.");
    static_assert(
        !(std::is_lvalue_reference_v<To> &&
          std::is_rvalue_reference_v<ForwardedType>),
        "Error: Cannot bind an lvalue reference to an rvalue reference.");

    return static_cast<To>(std::forward<T>(t));
  }

public:
  explicit syscalls();

  // WARNING: this function does not cast parameters to the right type.
  // Meaning if the function being called expects `size_t` and `int` is passed
  // there could be serious issues. It is recommended to use SCall.
  template <typename... Args>
  NTSTATUS Call(const std::string &funcName, Args... args) {
    auto syscallNo = getSyscallNumber(funcName);
    auto syscallAddr = getSyscallInstrAddr();
    return trampoline(syscallNo, syscallAddr, std::forward<Args>(args)...);
  }

  // WARNING: this function does not cast parameters to the right type.
  // Meaning if the function being called expects `size_t` and `int` is passed
  // there could be serious issues. It is recommended to use SCall.
  template <typename... Args>
  NTSTATUS Call(Args... args, uint64_t funcNameHash) {
    auto syscallNo = getSyscallNumber(funcNameHash);
    auto syscallAddr = getSyscallInstrAddr();
    return trampoline(syscallNo, syscallAddr, std::forward<Args>(args)...);
  }

  /// @brief Checks if function is callable with the passed arguments, cast
  /// the arguments to an accepted type. If you get a long as hell template
  /// error that's probably because you used wrong arguments for the function
  /// you specified. If not please report.
  /// @param func Typedef of a function needs to be called
  /// @param funcName name of the nt function
  /// @param args arguments of the nt function
  template <typename func, typename... Ts>
    requires std::invocable<func, Ts...>
  NTSTATUS SCall(const std::string &funcName, Ts &&...args) {
    return [&]<typename R, typename... Args>
      requires std::same_as<R, NTSTATUS>
    (std::type_identity<R(Args...)>,
     auto &&...forwardedArgs) { // auto&& because cannot inject other
                                // templated types into a templated
                                // lambda
      auto syscallNo = getSyscallNumber(funcName);
      auto syscallAddr = getSyscallInstrAddr();
      return trampoline(syscallNo, syscallAddr,
                        forwardCast<Args>(std::forward<Ts>(forwardedArgs))...);
    }(std::type_identity<func>{}, std::forward<Ts>(args)...);
  }

  /// @brief Checks if function is callable with the passed arguments, cast
  /// the arguments to an accepted type. If you get a long as hell template
  /// error that's probably because you used wrong arguments for the function
  /// you specified. If not please report.
  /// @param func Typedef of a function needs to be called
  /// @param funcNameHash fnv1 hash of the name of the nt function
  /// @param args arguments of the nt function
  template <typename func, typename... Ts>
    requires std::invocable<func, Ts &&...>
  NTSTATUS SCall(uint64_t funcNameHash, Ts &&...args) {
    return [&]<typename R, typename... Args>
      requires std::same_as<R, NTSTATUS>
    (std::type_identity<R(Args...)>,
     auto &&...forwardedArgs) { // auto&& because cannot inject other
                                // templated types into a templated
                                // lambda
      auto syscallNo = getSyscallNumber(funcNameHash);
      auto syscallAddr = getSyscallInstrAddr();
      return trampoline(syscallNo, syscallAddr,
                        forwardCast<Args>(std::forward<Ts>(forwardedArgs))...);
    }(std::type_identity<func>{}, std::forward<Ts>(args)...);
  }
};

} // namespace nullgate
