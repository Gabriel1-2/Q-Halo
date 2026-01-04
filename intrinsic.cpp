#include <immintrin.h>
#include <intrin.h>
#include <iostream>


int main() {
  std::cout << "Intrinsic Test" << std::endl;
  unsigned __int64 a = 123456789012345ULL;
  unsigned __int64 b = 987654321098765ULL;
  unsigned __int64 hi;
  unsigned __int64 lo = _umul128(a, b, &hi);
  std::cout << "Result: " << lo << " " << hi << std::endl;
  return 0;
}
