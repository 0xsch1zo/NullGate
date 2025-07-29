#include <iostream>
#include <nullgate/obfuscation.hpp>
#include <string>
#include <vector>

[[deprecated("hasher is deprecated in favour of xorConst, xorRuntime and "
             "xorRuntimeDecrypted")]]
int main() {
  std::vector<std::string> input;
  while (std::cin.good()) {
    input.emplace_back();
    std::getline(std::cin, input.back());
    if (input.back().empty())
      input.pop_back();
  }

  for (const auto &querry : input)
    std::cout << querry << ": " << nullgate::obfuscation::xorEncode(querry)
              << "\n";
}
