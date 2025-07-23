#include <cstdint>
#include <nullgate/obfuscation.hpp>
#include <stdexcept>
#include <string>
#include <vector>

namespace nullgate {

uint64_t obfuscation::fnv1Runtime(const char *str) {
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

std::string obfuscation::xorHash(const std::string &str) {
  std::string output;
  output.reserve(str.length());
  for (int i{}; i < str.length(); i++)
    output.push_back(str.at(i) ^ KEY.at(i % KEY.length()));
  return output;
}

std::string obfuscation::base64Encode(const std::string &in) {
  std::string out;

  int val = 0, valb = -6;
  for (unsigned char c : in) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
              [(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            [((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}

std::string obfuscation::base64Decode(const std::string &in) {
  // table from '+' to 'z'
  const uint8_t lookup[] = {
      62,  255, 62,  255, 63,  52,  53, 54, 55, 56, 57, 58, 59, 60, 61, 255,
      255, 0,   255, 255, 255, 255, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
      10,  11,  12,  13,  14,  15,  16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
      255, 255, 255, 255, 63,  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
      36,  37,  38,  39,  40,  41,  42, 43, 44, 45, 46, 47, 48, 49, 50, 51};
  static_assert(sizeof(lookup) == 'z' - '+' + 1);

  std::string out;
  int val = 0, valb = -8;
  for (uint8_t c : in) {
    if (c < '+' || c > 'z')
      break;
    c -= '+';
    if (lookup[c] >= 64)
      break;
    val = (val << 6) + lookup[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::string obfuscation::xorEncode(const std::string &in) {
  return base64Encode(xorHash(in));
}

std::string obfuscation::xorDecode(const std::string &in) {
  return xorHash(base64Decode(in));
}

uint8_t obfuscation::char2int(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  throw std::invalid_argument(std::string("Character is not a hex number: ") +
                              c);
}

std::vector<unsigned char> obfuscation::hex2bin(const std::string &hexString) {
  std::vector<unsigned char> byteArray;
  byteArray.reserve(hexString.size() / 2);
  for (int i{}; i < hexString.size(); i += 2) {
    byteArray.emplace_back(16 * char2int(hexString.at(i)) +
                           char2int(hexString.at(i + 1)));
  }
  return byteArray;
}

} // namespace nullgate
