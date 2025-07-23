#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

[[deprecated("Deprecated in favour of xorCrypt which is consteval and "
             "generates a random key every time a fresh build is made")]]
inline const std::string KEY = "FfqO3ZQ6XJ+SICAp";

namespace nullgate {

#define INNER_TO_STRING(x) #x
#define TO_STRING(x) INNER_TO_STRING(x)

class obfuscation {
public:
  template <class T, std::size_t N>
  struct decayable_array : public std::array<T, N> {
    constexpr operator const T *() const { return this->data(); }

    constexpr operator std::string_view() const {
      return std::string_view(this->data());
    }
  };

  // TODO: make this more declarative
  template <std::size_t N>
  static consteval decayable_array<char, N> xorConst(const char (&str)[N]) {
    constexpr std::string_view key = TO_STRING(NULLGATE_KEY);
    decayable_array<char, N> encoded{};
    for (size_t i{}; i < N - 1; i++) {
      encoded.at(i) = str[i] ^ key.at(i % key.length());
    }
    return encoded;
  }

  static std::string xorRuntime(std::string_view str);

  static inline consteval uint64_t fnv1Const(const char *str) {
    const uint64_t fnvOffsetBasis = 14695981039346656037U;
    const uint64_t fnvPrime = 1099511628211;
    uint64_t hash = fnvOffsetBasis;
    char c{};
    while ((c = *str++)) {
      hash *= fnvPrime;
      hash ^= c;
    }
    return hash;
  }

  // Don't use for hardcoded strings, the string won't be obfuscated
  static uint64_t fnv1Runtime(const char *str);

  [[deprecated("Deprecated in favour of xorCrypt which is consteval and "
               "generates a random key every time a fresh build is made")]]
  static std::string xorEncode(const std::string &in);

  [[deprecated("Deprecated in favour of xorCrypt which is consteval and "
               "generates a random key every time a fresh build is made")]]
  static std::string xorDecode(const std::string &in);

  [[deprecated("Deprecated in favour of xorCrypt which is consteval and "
               "generates a random key every time a fresh build is made")]]
  static std::vector<unsigned char> hex2bin(const std::string &hexString);

private:
  [[deprecated("Deprecated in favour of xorCrypt which is consteval and "
               "generates a random key every time a fresh build is made")]]
  static std::string base64Encode(const std::string &in);

  [[deprecated("Deprecated in favour of xorCrypt which is consteval and "
               "generates a random key every time a fresh build is made")]]
  static std::string base64Decode(const std::string &in);

  [[deprecated("Deprecated in favour of xorCrypt which is consteval and "
               "generates a random key every time a fresh build is made")]]
  static std::string xorHash(const std::string &str);

  [[deprecated("Deprecated in favour of xorCrypt which is consteval and "
               "generates a random key every time a fresh build is made")]]
  static uint8_t char2int(char c);
};

} // namespace nullgate
