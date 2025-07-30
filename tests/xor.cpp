#include <format>
#include <iostream>
#include <nullgate/obfuscation.hpp>
#include <stdexcept>

using namespace nullgate;
using ob = obfuscation;

constexpr static const char testStr[] = "testing testing testing";
constexpr static std::string_view testStrView = testStr;

template <typename T, typename U>
void comp(T left, U right, std::string_view func) {
  if (left != right) {
    throw std::runtime_error(std::format(
        "in func: {}: \nleft: {}\t right: {}\n\tleft size:{}\n\tright size:{}",
        func, left, right, left.size(), right.size()));
  }
}

void testXorConst() {
  auto xored = ob::xorConst(testStr);
  auto unxored = ob::xorRuntime(xored).string();
  comp(unxored, testStrView, __FUNCTION__);

  auto xoredRuntime = ob::xorRuntime(ob::DynamicData(testStr));
  comp(xored.raw(), xoredRuntime.raw(), __FUNCTION__);
}

void testXorRuntime() {
  auto xored = ob::xorRuntime(ob::DynamicData(testStr));
  auto unxored = ob::xorRuntime(xored);

  comp(unxored.string(), testStrView, __FUNCTION__);

  ob::ConstData xored1 = ob::xorRuntime(ob::ConstData(std::to_array(testStr)));
  ob::ConstData unxored1 = ob::xorRuntime(xored1);

  comp(unxored1.string().substr(0, unxored1.size() - 1), testStrView,
       __FUNCTION__);
}

void testXorRuntimeDecrypted() {
  // I'm going insane
  auto allegedTestStr =
      ob::xorRuntimeDecrypted<"testing testing testing">(); // msvc is so
                                                            // goddamn stupid
  comp(allegedTestStr.string(), testStrView, __FUNCTION__);
}

int main() {
  testXorConst();
  testXorRuntime();
  testXorRuntimeDecrypted();
}
