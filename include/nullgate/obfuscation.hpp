#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

inline const std::string KEY = "FfqO3ZQ6XJ+SICAp";

namespace nullgate {

#define INNER_TO_STRING(x) #x
#define TO_STRING(x) INNER_TO_STRING(x)

class obfuscation {
private:
  template <std::size_t N> struct LiteralString {
    consteval LiteralString(const char (&s)[N]) {
      static_assert(N >= 1, "String literal should be at least of size 1 "
                            "counting the null character");
      std::copy(s, s + N, &inner[0]);
    }

    static constexpr std::size_t size = N - 1;
    char inner[N]{};
  };

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
    RuntimeData() = default;

    RuntimeData(std::string data)
        : std::vector<DataUnit>(data.begin(), data.end()) {}

    RuntimeData(std::vector<unsigned char> data)
        : std::vector<DataUnit>(data.begin(), data.end()) {}

    std::vector<unsigned char> raw() const {
      return std::vector<unsigned char>(this->begin(), this->end());
    }
    std::string string() const {
      return std::string(this->begin(), this->end());
    }
  };

  template <std::size_t N>
  static consteval ConstData<N - 1> xorConst(const char (&data)[N]) {
    static_assert(N >= 1, "String literal should be at least of size 1 "
                          "counting the null character");
    constexpr std::string_view key = TO_STRING(NULLGATE_KEY);
    ConstData<N - 1> encoded{};
    auto iter = std::views::zip(std::views::iota(0ULL, encoded.size()), data);
    std::ranges::transform(iter, encoded.begin(), xorElement);
    return encoded;
  }

  template <std::size_t N> static RuntimeData xorRuntime(ConstData<N> data) {
    RuntimeData container{};
    container.reserve(data.size());
    auto iter = std::views::enumerate(data);
    std::ranges::transform(iter, std::back_inserter(container), xorElement);
    return container;
  }

  static RuntimeData xorRuntime(RuntimeData data) {
    RuntimeData container{};
    container.reserve(data.size());
    auto iter = std::views::zip(std::views::iota(0ULL), data);
    std::ranges::transform(iter, std::back_inserter(container), xorElement);
    return container;
  }

  template <LiteralString literal> static RuntimeData xorRuntimeDecrypted() {
    constexpr auto xored = xorConst(literal.inner);
    return xorRuntime(xored);
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

  [[deprecated(
      "Deprecated in favour of xorConst, xorRuntime and xorRuntimeDecrypted")]]
  static std::string xorEncode(const std::string &in);

  [[deprecated(
      "Deprecated in favour of xorConst, xorRuntime and xorRuntimeDecrypted")]]
  static std::string xorDecode(const std::string &in);

  [[deprecated(
      "Deprecated in favour of xorConst, xorRuntime and xorRuntimeDecrypted")]]
  static std::vector<unsigned char> hex2bin(const std::string &hexString);

private:
  static constexpr char xorElement(std::tuple<size_t, char> indexed_element) {
    constexpr std::string_view key = TO_STRING(NULLGATE_KEY);
    auto [index, element] = indexed_element;
    return element ^ key.at(index % key.length());
  }

  static std::string base64Encode(const std::string &in);

  static std::string base64Decode(const std::string &in);

  static std::string xorHash(const std::string &str);

  static uint8_t char2int(char c);
};

} // namespace nullgate
