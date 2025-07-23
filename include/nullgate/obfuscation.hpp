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
  using DataUnit = char;

  template <std::size_t N> class ConstData : public std::array<DataUnit, N> {
  public:
    std::vector<unsigned char> raw() const {
      return std::vector<unsigned char>(this->begin(), this->end());
    }
    std::string string() const {
      return std::string(this->begin(), this->end());
    }
  };

  class RuntimeData : public std::vector<DataUnit> {
  public:
    std::vector<unsigned char> raw() const {
      return std::vector<unsigned char>(this->begin(), this->end());
    }
    std::string string() const {
      return std::string(this->begin(), this->end());
    }
  };

  // TODO: make this more declarative
  template <std::size_t N>
  static consteval ConstData<N> xorConst(const DataUnit (&data)[N]) {
    constexpr std::string_view key = TO_STRING(NULLGATE_KEY);
    ConstData<N> encoded{};
    for (size_t i{}; i < N; i++) {
      encoded.at(i) = data[i] ^ key.at(i % key.length());
    }
    return encoded;
  }

  template <std::size_t N> static RuntimeData xorRuntime(ConstData<N> data) {
    constexpr std::string_view key = TO_STRING(NULLGATE_KEY);
    RuntimeData container{};
    for (int i{}; i < data.size(); i++)
      container.push_back(data.at(i) ^ key.at(i % key.length()));
    return container;
  }

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
}; // namespace nullgate

} // namespace nullgate
