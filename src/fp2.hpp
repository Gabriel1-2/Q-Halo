#pragma once

#include "fp.hpp"

namespace crypto {

template <typename P> struct Fp2 {
  using FpT = Fp<P>;
  FpT c0, c1; // c0 + c1 * i

  constexpr Fp2() : c0(), c1() {}
  constexpr Fp2(const FpT &a, const FpT &b) : c0(a), c1(b) {}

  static Fp2 zero() { return Fp2(FpT::zero(), FpT::zero()); }
  static Fp2 one() {
    return Fp2(FpT::mont_one(), FpT::zero());
  } // mont_one is 1*R
  static Fp2 mont_one() { return one(); } // Alias for Polynomial interface

  bool is_zero() const { return c0.data().is_zero() && c1.data().is_zero(); }

  static Fp2 add(const Fp2 &a, const Fp2 &b) {
    return Fp2(FpT::add(a.c0, b.c0), FpT::add(a.c1, b.c1));
  }

  static Fp2 sub(const Fp2 &a, const Fp2 &b) {
    return Fp2(FpT::sub(a.c0, b.c0), FpT::sub(a.c1, b.c1));
  }

  static Fp2 mul(const Fp2 &a, const Fp2 &b) {
    // (a0 + a1*i) * (b0 + b1*i)
    // = a0b0 - a1b1 + (a0b1 + a1b0)*i
    // Karatsuba?
    // t0 = a0*b0, t1 = a1*b1, t2 = (a0+a1)*(b0+b1)
    // real = t0 - t1
    // imag = t2 - t0 - t1
    // Cost: 3 muls

    FpT t0 = FpT::mul(a.c0, b.c0);
    FpT t1 = FpT::mul(a.c1, b.c1);
    FpT sum_a = FpT::add(a.c0, a.c1);
    FpT sum_b = FpT::add(b.c0, b.c1);
    FpT t2 = FpT::mul(sum_a, sum_b); // (a0+a1)(b0+b1)

    FpT real = FpT::sub(t0, t1);

    // imag = t2 - t0 - t1
    FpT imag = FpT::sub(t2, t0);
    imag = FpT::sub(imag, t1);

    return Fp2(real, imag);
  }

  static Fp2 sqr(const Fp2 &a) {
    // (a0 + a1*i)^2 = (a0^2 - a1^2) + 2a0a1*i
    // = (a0+a1)(a0-a1) + 2a0a1*i
    // Cost: 2 muls

    FpT t0 = FpT::add(a.c0, a.c1);
    FpT t1 = FpT::sub(a.c0, a.c1);

    FpT real = FpT::mul(t0, t1); // a0^2 - a1^2

    FpT two = FpT::add(FpT::mont_one(), FpT::mont_one()); // 2
    // Or just add(a, a)

    FpT t2 = FpT::mul(a.c0, a.c1);
    FpT imag = FpT::add(t2, t2); // 2a0a1

    return Fp2(real, imag);
  }

  static Fp2 inv(const Fp2 &a) {
    // (a0 - a1*i) / (a0^2 + a1^2)
    FpT t0 = FpT::sqr(a.c0);
    FpT t1 = FpT::sqr(a.c1);
    FpT denom = FpT::add(t0, t1);
    FpT invDe = FpT::inv(denom);

    FpT real = FpT::mul(a.c0, invDe);
    FpT neg_c1 = FpT::sub(FpT::zero(), a.c1); // -c1
    FpT imag = FpT::mul(neg_c1, invDe);

    return Fp2(real, imag);
  }

  static Fp2 sqrt(const Fp2 &u) {
    // Special case for Real input (u1 == 0) to avoid failures in generic
    // formula
    if (u.c1.data().is_zero()) {
      // u = u0.
      // sqrt(u0) is either real (if u0 is QR) or purely imaginary (if u0 is not
      // QR).
      FpT r = FpT::sqrt(u.c0);
      FpT r2 = FpT::sqr(r);

      // Check if r^2 == u0
      bool match = true;
      for (size_t i = 0; i < P::N_LIMBS; ++i)
        if (r2.val.limbs[i] != u.c0.val.limbs[i])
          match = false;

      if (match) {
        return Fp2(r, FpT::zero());
      }

      // Try imaginary: sqrt(u0) = i * sqrt(-u0)
      // Check if -u0 is QR.
      FpT neg_u0 = FpT::sub(FpT::zero(), u.c0);
      r = FpT::sqrt(neg_u0);
      r2 = FpT::sqr(r);

      match = true;
      for (size_t i = 0; i < P::N_LIMBS; ++i)
        if (r2.val.limbs[i] != neg_u0.val.limbs[i])
          match = false;

      if (match) {
        return Fp2(FpT::zero(), r);
      }

      // No root
      return Fp2(FpT::zero(), FpT::zero());
    }

    // sqrt(u0 + u1*i)
    // alpha = u0^2 + u1^2
    // gamma = sqrt(alpha)
    // delta = (u0 + gamma) / 2
    // if delta is sqr in Fp:
    //    x = sqrt(delta)
    //    y = u1 / (2x)
    // else:
    //    delta = (u0 - gamma) / 2   <-- this logic depends on p mod 4 and
    //    choosing gamma x = sqrt(delta) y = u1 / (2x) ?? No.
    //
    // Standard alg:
    // gamma = sqrt(u0^2 + u1^2)
    // delta = (u0 + gamma) * inv2
    // x = sqrt(delta)
    // if x^2 != delta (not QR), then:
    //    delta = (u0 - gamma) * inv2  (actually usually -delta?)
    //    ...

    FpT t0 = FpT::sqr(u.c0);
    FpT t1 = FpT::sqr(u.c1);
    FpT alpha = FpT::add(t0, t1);
    FpT gamma = FpT::sqrt(alpha); // Assuming alpha is QR. (x^2+y^2 always QR in
                                  // Fp2? Norm is in Fp).

    FpT two = FpT::add(FpT::mont_one(), FpT::mont_one());
    FpT inv2 = FpT::inv(two);

    FpT delta = FpT::mul(FpT::add(u.c0, gamma), inv2);
    FpT x = FpT::sqrt(delta);

    // Check if x^2 == delta
    FpT x_sq = FpT::sqr(x);
    // Compare BigInts
    bool is_qr = true;
    for (int i = 0; i < FpT::N; ++i)
      if (x_sq.val.limbs[i] != delta.val.limbs[i])
        is_qr = false;

    if (!is_qr) {
      // Try delta2 = (u0 - gamma) * inv2
      delta = FpT::mul(FpT::sub(u.c0, gamma), inv2);
      x = FpT::sqrt(delta);
    }

    // Now x is real part.
    // y = u1 * inv(2x)
    FpT two_x = FpT::add(x, x);
    FpT y = FpT::mul(u.c1, FpT::inv(two_x));

    return Fp2(x, y);
  }

  void print() const {
    std::cout << "(";
    c0.print();
    std::cout << " + ";
    c1.print();
    std::cout << "*i)";
  }
};

} // namespace crypto
