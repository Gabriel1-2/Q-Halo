#pragma once

#include "bigint.hpp"
#include "params.hpp"

namespace crypto {

template <typename P> class Fp {
public:
  static constexpr size_t N = P::N_LIMBS;
  BigInt<N> val;

  constexpr Fp() : val() {}
  constexpr Fp(const BigInt<N> &v) : val(v) {}

  static Fp zero() { return Fp(BigInt<N>()); }
  static Fp one() {
    return Fp(P::R2());
  } // R^2 * 1 * R^-1 = R = 1 in Montgomery? No.
  // 1 in Montgomery is 1 * R mod p. R^2 is R*R.
  // from_int(1) = mul(1, R2).
  // We need a helper to init constants efficiently.
  // For now, assume users construct Fp correctly or use a helper.

  // Helper: Convert integer 1 to Montgomery domain
  static Fp mont_one() {
    // We need R mod p.
    // R^2 is available. mul(1, R2) -> 1 * R^2 * R^-1 = R. Correct.
    // We need '1' as BigInt.
    BigInt<N> one_bi;
    one_bi.limbs[0] = 1;
    return mul(Fp(one_bi), Fp(P::R2()));
  }

  // Convert from integer (assumes input < p) -> Montgomery domain
  // In real usage, this would be mul(R2, v)
  // We'll implement direct conversion later or assume input is already in
  // domain for internal ops? Usually: from_int(x) = mul(x, R^2)

  // Raw access
  const BigInt<N> &data() const { return val; }

  // Convert integer value to Montgomery form: x -> x*R mod p
  Fp to_montgomery() const {
    // mul(this, R^2) -> x * R^2 * R^-1 = xR
    return mul(*this, Fp(P::R2()));
  }

  // Convert from Montgomery form back to integer: xR -> x
  Fp from_montgomery() const {
    // mul(xR, 1) -> xR * 1 * R^-1 = x
    BigInt<N> one_bi;
    one_bi.limbs[0] = 1;
    return mul(*this, Fp(one_bi));
  }

  // Montgomery Multiplication: c = a * b * R^-1 mod p
  static Fp mul(const Fp &a, const Fp &b) {
    BigInt<N> r;
    // Product buffer 2N words?
    // For perf, we usually interleave mul and red.
    // CIOS Algorithm or just product + reduction.
    // Let's implement Product-Scanning or similar.
    // For simplicity and clarity + perf:
    // 1. Full 128-bit mul for limbs.

    // We need a temporary 2N+1 buffer or just 2N.
    Word T[2 * N] = {0};

    // 1. T = A * B
    for (size_t i = 0; i < N; ++i) {
      Word carry = 0;
      for (size_t j = 0; j < N; ++j) {
        // T[i+j] += a[i]*b[j] + carry
        Word p_lo, p_hi;
        p_lo = _umul128(a.val[i], b.val[j], &p_hi);

        // Compute p_lo + carry + T[i+j], track overflow to new carry
        unsigned __int128 sum = (unsigned __int128)p_lo + carry + T[i + j];
        T[i + j] = (Word)sum;
        carry = p_hi + (Word)(sum >> 64);
      }
      T[i + N] = carry;
    }

    // 2. Reduction
    // m = T * mu mod R (which is 2^64 here, word by word)
    Word mu = P::mu();
    Word p[N];
    auto p_bi = P::p();
    for (int k = 0; k < N; ++k)
      p[k] = p_bi.limbs[k];

    for (size_t i = 0; i < N; ++i) {
      Word m = T[i] * mu;

      Word carry = 0;
      for (size_t j = 0; j < N; ++j) {
        Word p_lo, p_hi;
        p_lo = _umul128(m, p[j], &p_hi);

        // Compute p_lo + carry + T[i+j], track overflow to new carry
        unsigned __int128 sum = (unsigned __int128)p_lo + carry + T[i + j];
        T[i + j] = (Word)sum;
        carry = p_hi + (Word)(sum >> 64);
      }

      unsigned char end_c = _addcarry_u64(0, T[i + N], carry, &T[i + N]);
      for (size_t idx = i + N + 1; end_c && idx < 2 * N; ++idx) {
        end_c = _addcarry_u64(end_c, T[idx], 0, &T[idx]);
      }
    }

    // result is in T[N...2N-1]
    // We need to copy to r
    for (size_t i = 0; i < N; ++i)
      r.limbs[i] = T[i + N];

    // Conditional subtraction: if r >= p, r = r - p
    if (BigInt<N>::compare(r, p_bi) >= 0) {
      BigInt<N>::sub(r, r, p_bi);
    }

    return Fp(r);
  }

  static Fp add(const Fp &a, const Fp &b) {
    Fp r;
    Word carry = BigInt<N>::add(r.val, a.val, b.val);
    if (carry || BigInt<N>::compare(r.val, P::p()) >= 0) {
      BigInt<N>::sub(r.val, r.val, P::p());
    }
    return r;
  }

  static Fp sqr(const Fp &a) {
    return mul(a, a); // TODO: Optimize
  }

  static Fp pow(const Fp &base, const BigInt<N> &exp) {
    Fp res = mont_one();
    Fp b = base;
    for (size_t i = 0; i < N * 64; ++i) {
      if (exp.get_bit(i)) {
        res = mul(res, b);
      }
      b = sqr(b);
    }
    return res;
  }

  FORCE_INLINE static Fp inv(const Fp &a) {
    // a^(p-2)
    BigInt<N> p_minus_2 = P::p();
    // Subtract 2
    BigInt<N> two;
    two.limbs[0] = 2;
    BigInt<N>::sub(p_minus_2, p_minus_2, two);
    return pow(a, p_minus_2);
  }

  static Fp sub(const Fp &a, const Fp &b) {
    Fp r;
    Word borrow = BigInt<N>::sub(r.val, a.val, b.val);
    if (borrow) {
      BigInt<N>::add(r.val, r.val, P::p());
    }
    return r;
  }

  static Fp sqrt(const Fp &a) {
    // p = 3 mod 4 for SIKE p434 (p = 2^e * 3^f - 1, since 2^e is large multiple
    // of 4, p = -1 = 3 mod 4). sqrt(a) = a^((p+1)/4)
    BigInt<N> p = P::p();
    BigInt<N> one;
    one.limbs[0] = 1;
    BigInt<N>::add(p, p, one); // p+1
    // divide by 4.
    // shift right 2.
    // p is 2^216..., so p+1 = 2^216...
    // shifting is easy.
    // Let's implement generic shift right or just / 4 logic for BigInt.
    // For now, since BigInt doesn't have shift, I will implement a quick shift
    // or division. Actually, BigInt uses u64 limbs. We can iterate.
    int carry = 0;
    for (int i = N - 1; i >= 0; --i) {
      uint64_t v = p.limbs[i];
      uint64_t next_carry = v & 3;
      p.limbs[i] = (v >> 2) | ((uint64_t)carry << 62);
      carry = next_carry;
    }
    return pow(a, p);
  }

  void print() const { val.print(); }
};

} // namespace crypto
