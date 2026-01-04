#include "src/bigint.hpp"
#include "src/fp.hpp"
#include "src/fp2.hpp"
#include "src/utils.hpp"
#include <iomanip>
#include <iostream>


using namespace crypto;

struct ParamsSmall {
  static constexpr size_t N_LIMBS = 1;
  static constexpr BigInt<1> p() {
    // p = 19 (0x13). 3 mod 4.
    return BigInt<1>(19);
  }
  // R = 2^64 mod 19
  // 2^64 mod 19.
  // 2^4 = 16 = -3.
  // 2^64 = (2^4)^16 = (-3)^16 = 3^16.
  // ...
  // Let's use the dynamic R2 calculator logic copied from params.hpp
  static BigInt<1> R2() {
    static const BigInt<1> val = []() {
      BigInt<1> r(1);
      BigInt<1> p_val = p();
      for (size_t i = 0; i < 64 * 2; ++i) { // 2*64 bits
        Word carry = BigInt<1>::add(r, r, r);
        if (carry || BigInt<1>::compare(r, p_val) >= 0) {
          BigInt<1>::sub(r, r, p_val);
        }
      }
      return r;
    }();
    return val;
  }
  static constexpr uint64_t mu() {
    // -p^-1 mod 2^64.
    // p = 19.
    // 19 * x = -1 mod 2^64.
    // 19 * x = -1.
    // This is tricky manually.
    // BUT Fp::mul depends on correct mu.
    // Let's calculate it.
    // p^-1 mod 2^64.
    // using extended  Euclid or Newton.
    // For small p=19, we can just find inverse.
    // 19 * x = 1 mod 2^64 => x = 9707474720993093227 ?
    // Actually, let's implement mu calculation loop.
    uint64_t y = 1;
    // Newton iteration for inverse mod 2^64: x_new = x*(2 - p*x)
    for (int i = 0; i < 6; ++i) {
      y = y * (2 - 19 * y);
    }
    return -y;
  }
};

int main() {
  using FpT = Fp<ParamsSmall>;
  std::cerr << "Debug Small Prime p=19" << std::endl;
  std::cerr << "R2 = " << ParamsSmall::R2().limbs[0] << std::endl;

  // Test 1: 1 * 1 = 1
  FpT one = FpT::mont_one();
  FpT check = FpT::mul(one, one);
  std::cerr << "1*1 = " << check.data().limbs[0] << " (Raw Montgomery)"
            << std::endl;
  // To check value, we need from_mont.
  // from_mont(x) = mul(x, 1).
  // We need 1 in integer form.
  FpT raw_one;
  raw_one.val.limbs[0] = 1; // This is 1*R^-1
  FpT real_val = FpT::mul(check, raw_one);
  std::cerr << "1*1 decoded = " << real_val.data().limbs[0] << std::endl;

  // Test 2: 2 * 3 = 6
  BigInt<1> b2(2);
  FpT f2(b2);
  f2 = FpT::mul(f2, FpT(ParamsSmall::R2())); // to mont
  BigInt<1> b3(3);
  FpT f3(b3);
  f3 = FpT::mul(f3, FpT(ParamsSmall::R2()));

  FpT f6 = FpT::mul(f2, f3);
  FpT real_6 = FpT::mul(f6, raw_one);
  std::cerr << "2*3 decoded = " << real_6.data().limbs[0] << std::endl;

  // Test 3: Sqrt(4) = 2 or 17 (-2)
  // 4 is valid.
  // 2^2 = 4.
  // sqrt(4) should be 2.
  BigInt<1> b4(4);
  FpT f4(b4);
  f4 = FpT::mul(f4, FpT(ParamsSmall::R2()));
  FpT sqrt4 = FpT::sqrt(f4);
  FpT real_sqrt = FpT::mul(sqrt4, raw_one);
  std::cerr << "sqrt(4) decoded = " << real_sqrt.data().limbs[0] << std::endl;

  if (real_sqrt.data().limbs[0] == 2 || real_sqrt.data().limbs[0] == 17) {
    std::cerr << "PASS SQRT" << std::endl;
  } else {
    std::cerr << "FAIL SQRT" << std::endl;
  }

  // Test 4: Sqrt(5). 5 is QR mod 19?
  // 1, 4, 9, 16, 5 (9=3^2, 16=4^2, 25=6, 36=17, 49=11, 64=7, 81=5).
  // Yes 9^2 = 81 = 4*19 + 5.
  // So sqrt(5) = 9 or 10.
  BigInt<1> b5(5);
  FpT f5(b5);
  f5 = FpT::mul(f5, FpT(ParamsSmall::R2()));
  FpT sqrt5 = FpT::sqrt(f5);
  FpT real_sqrt5 = FpT::mul(sqrt5, raw_one);
  std::cerr << "sqrt(5) decoded = " << real_sqrt5.data().limbs[0] << std::endl;

  return 0;
}
