#pragma once

#include "utils.hpp"
#include <cstring>

namespace crypto {

template <size_t N> class BigInt {
public:
  static constexpr size_t NUM_LIMBS = N;
  std::array<Word, N> limbs;

  constexpr BigInt() : limbs{0} {}
  constexpr BigInt(Word w) : limbs{0} { limbs[0] = w; }

  // Add two BigInts, return carry (0 or 1)
  FORCE_INLINE static Word add(BigInt<N> &r, const BigInt<N> &a,
                               const BigInt<N> &b) {
    unsigned char carry = 0;
    for (size_t i = 0; i < N; ++i) {
      carry = _addcarry_u64(carry, a.limbs[i], b.limbs[i], &r.limbs[i]);
    }
    return carry;
  }

  // Subtract two BigInts, return borrow (0 or 1)
  FORCE_INLINE static Word sub(BigInt<N> &r, const BigInt<N> &a,
                               const BigInt<N> &b) {
    unsigned char borrow = 0;
    for (size_t i = 0; i < N; ++i) {
      borrow = _subborrow_u64(borrow, a.limbs[i], b.limbs[i], &r.limbs[i]);
    }
    return borrow;
  }

  // Single precision mul add: (hi, lo) = a * b + c
  FORCE_INLINE static void mul_add(Word &hi, Word &lo, Word a, Word b, Word c) {
    unsigned char carry = 0;
    Word prod_lo, prod_hi;
    prod_lo = _umul128(a, b, &prod_hi);
    carry = _addcarry_u64(0, prod_lo, c, &lo);
    _addcarry_u64(carry, prod_hi, 0, &hi);
  }

  // Single precision mul add with carry: (hi, lo) = a * b + c + carry_in
  FORCE_INLINE static void mul_add_carry(Word &hi, Word &lo, Word a, Word b,
                                         Word c, Word carry_in) {
    Word prod_lo, prod_hi;
    prod_lo = _umul128(a, b, &prod_hi);
    unsigned char c1 = _addcarry_u64(0, prod_lo, c, &lo);
    unsigned char c2 = _addcarry_u64(c1, lo, carry_in, &lo);
    _addcarry_u64(c2, prod_hi, 0, &hi);
  }

  FORCE_INLINE Word &operator[](size_t i) { return limbs[i]; }
  FORCE_INLINE const Word &operator[](size_t i) const { return limbs[i]; }

  static int compare(const BigInt<N> &a, const BigInt<N> &b) {
    for (int i = N - 1; i >= 0; --i) {
      if (a.limbs[i] > b.limbs[i])
        return 1;
      if (a.limbs[i] < b.limbs[i])
        return -1;
    }
    return 0;
  }

  bool is_zero() const {
    Word acc = 0;
    for (size_t i = 0; i < N; ++i)
      acc |= limbs[i];
    return acc == 0;
  }

  bool get_bit(size_t bit) const {
    if (bit >= N * 64)
      return false;
    return (limbs[bit / 64] >> (bit % 64)) & 1;
  }

  // Print for debugging
  void print() const {
    std::cout << "0x";
    for (int i = N - 1; i >= 0; --i) {
      std::cout << std::hex << std::setw(16) << std::setfill('0') << limbs[i];
    }
    std::cout << std::dec << std::endl;
  }
};

} // namespace crypto
