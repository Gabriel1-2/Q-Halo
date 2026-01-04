#pragma once

#include "fp2.hpp"
#include <iostream>

namespace crypto {

// Extended Projective Point for Twisted Edwards Curves
// Coordinates: (X : Y : Z : T) where x = X/Z, y = Y/Z, and T = XY/Z
// T coordinate enables faster addition without inversions
template <typename Config> struct EdwardsPointExt {
  using Fp2T = Fp2<Config>;
  Fp2T X, Y, Z, T;

  // Identity point: (0 : 1 : 1 : 0)
  static EdwardsPointExt identity() {
    EdwardsPointExt p;
    p.X = Fp2T::zero();
    p.Y = Fp2T::one();
    p.Z = Fp2T::one();
    p.T = Fp2T::zero();
    return p;
  }

  // Convert from affine (x, y) to extended projective
  static EdwardsPointExt from_affine(const Fp2T &x, const Fp2T &y) {
    EdwardsPointExt p;
    p.X = x;
    p.Y = y;
    p.Z = Fp2T::one();
    p.T = Fp2T::mul(x, y);
    return p;
  }

  // Convert to affine (x, y) - requires one inversion
  void to_affine(Fp2T &x, Fp2T &y) const {
    Fp2T Z_inv = Fp2T::inv(Z);
    x = Fp2T::mul(X, Z_inv);
    y = Fp2T::mul(Y, Z_inv);
  }

  // Check if point is identity (Z-normalized check)
  bool is_identity() const {
    // Check if X == 0 and Y == Z (identity is (0:1:1:0))
    return X.is_zero() && !Y.is_zero();
  }
};

// Optimized Twisted Edwards Curve with Extended Projective Coordinates
// Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
// Using formulas from Hisil et al. "Twisted Edwards Curves Revisited"
template <typename Config> class TwistedEdwardsFast {
public:
  using Fp2T = Fp2<Config>;
  using Point = EdwardsPointExt<Config>;

  Fp2T a; // Edwards parameter a (typically -1 or other small value)
  Fp2T d; // Edwards parameter d

  // Constructor with direct Edwards parameters
  TwistedEdwardsFast(const Fp2T &a_in, const Fp2T &d_in) : a(a_in), d(d_in) {}

  // Constructor from Montgomery curve coefficients
  // Montgomery: By^2 = x^3 + Ax^2 + x
  // Edwards: a = (A+2)/B, d = (A-2)/B
  TwistedEdwardsFast(const Fp2T &A, const Fp2T &B, bool from_mont) {
    Fp2T two;
    two.c0.val.limbs[0] = 2;
    two.c0 = two.c0.to_montgomery();

    Fp2T A_plus_2 = Fp2T::add(A, two);
    Fp2T A_minus_2 = Fp2T::sub(A, two);
    Fp2T B_inv = Fp2T::inv(B);

    a = Fp2T::mul(A_plus_2, B_inv);
    d = Fp2T::mul(A_minus_2, B_inv);
  }

  // Extended Unified Addition (works for all cases including doubling)
  // Cost: 8M + 1S + 1D (or 9M + 1D with mul instead of sqr)
  // From Hisil et al. 2008, Section 3.1
  //
  // Input: (X1:Y1:Z1:T1), (X2:Y2:Z2:T2)
  // Output: (X3:Y3:Z3:T3)
  Point Add(const Point &P, const Point &Q) const {
    // A = X1 * X2
    Fp2T A = Fp2T::mul(P.X, Q.X);
    // B = Y1 * Y2
    Fp2T B = Fp2T::mul(P.Y, Q.Y);
    // C = d * T1 * T2
    Fp2T T1T2 = Fp2T::mul(P.T, Q.T);
    Fp2T C = Fp2T::mul(d, T1T2);
    // D = Z1 * Z2
    Fp2T D = Fp2T::mul(P.Z, Q.Z);

    // E = (X1 + Y1) * (X2 + Y2) - A - B
    Fp2T X1_plus_Y1 = Fp2T::add(P.X, P.Y);
    Fp2T X2_plus_Y2 = Fp2T::add(Q.X, Q.Y);
    Fp2T E = Fp2T::mul(X1_plus_Y1, X2_plus_Y2);
    E = Fp2T::sub(E, A);
    E = Fp2T::sub(E, B);

    // F = D - C
    Fp2T F = Fp2T::sub(D, C);
    // G = D + C
    Fp2T G = Fp2T::add(D, C);
    // H = B - a*A
    Fp2T aA = Fp2T::mul(a, A);
    Fp2T H = Fp2T::sub(B, aA);

    // X3 = E * F
    // Y3 = G * H
    // T3 = E * H
    // Z3 = F * G
    Point R;
    R.X = Fp2T::mul(E, F);
    R.Y = Fp2T::mul(G, H);
    R.T = Fp2T::mul(E, H);
    R.Z = Fp2T::mul(F, G);

    return R;
  }

  // Dedicated Doubling Formula (slightly faster than unified Add)
  // Cost: 4M + 4S + 1D
  // From Hisil et al. 2008, Section 3.2
  Point Double(const Point &P) const {
    // A = X1^2
    Fp2T A = Fp2T::mul(P.X, P.X);
    // B = Y1^2
    Fp2T B = Fp2T::mul(P.Y, P.Y);
    // C = 2 * Z1^2
    Fp2T Z2 = Fp2T::mul(P.Z, P.Z);
    Fp2T C = Fp2T::add(Z2, Z2);
    // D = a * A
    Fp2T D = Fp2T::mul(a, A);
    // E = (X1 + Y1)^2 - A - B
    Fp2T XplusY = Fp2T::add(P.X, P.Y);
    Fp2T E = Fp2T::mul(XplusY, XplusY);
    E = Fp2T::sub(E, A);
    E = Fp2T::sub(E, B);
    // G = D + B
    Fp2T G = Fp2T::add(D, B);
    // F = G - C
    Fp2T F = Fp2T::sub(G, C);
    // H = D - B
    Fp2T H = Fp2T::sub(D, B);

    // X3 = E * F
    // Y3 = G * H
    // T3 = E * H
    // Z3 = F * G
    Point R;
    R.X = Fp2T::mul(E, F);
    R.Y = Fp2T::mul(G, H);
    R.T = Fp2T::mul(E, H);
    R.Z = Fp2T::mul(F, G);

    return R;
  }

  // Scalar Multiplication using Double-and-Add with Projective Coordinates
  // Only ONE inversion at the end (instead of 2 per operation)
  // Cost: ~log2(k) doubles + HW(k) adds + 1 final inversion
  Point ScalarMul(const Point &P, const BigInt<Config::N_LIMBS> &k) const {
    // Handle zero scalar
    if (k.is_zero()) {
      return Point::identity();
    }

    Point R = Point::identity();
    Point Q = P;

    // Double-and-add (right-to-left)
    for (size_t i = 0; i < Config::N_LIMBS * 64; ++i) {
      if (k.get_bit(i)) {
        R = Add(R, Q);
      }
      Q = Double(Q);
    }

    return R;
  }

  // Scalar multiplication for small scalars (64-bit)
  Point ScalarMul64(const Point &P, uint64_t k) const {
    if (k == 0)
      return Point::identity();
    if (k == 1)
      return P;

    Point R = Point::identity();
    Point Q = P;

    while (k > 0) {
      if (k & 1) {
        R = Add(R, Q);
      }
      Q = Double(Q);
      k >>= 1;
    }

    return R;
  }

  // Normalize point to affine coordinates (single inversion)
  static void Normalize(Point &P) {
    if (P.Z.is_zero())
      return; // Point at infinity

    Fp2T Z_inv = Fp2T::inv(P.Z);
    P.X = Fp2T::mul(P.X, Z_inv);
    P.Y = Fp2T::mul(P.Y, Z_inv);
    P.T = Fp2T::mul(P.X, P.Y);
    P.Z = Fp2T::one();
  }

  // Check if two points are equal (projective comparison)
  static bool PointsEqual(const Point &P, const Point &Q) {
    // P == Q iff X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
    Fp2T X1Z2 = Fp2T::mul(P.X, Q.Z);
    Fp2T X2Z1 = Fp2T::mul(Q.X, P.Z);
    Fp2T Y1Z2 = Fp2T::mul(P.Y, Q.Z);
    Fp2T Y2Z1 = Fp2T::mul(Q.Y, P.Z);

    return Fp2T::equal(X1Z2, X2Z1) && Fp2T::equal(Y1Z2, Y2Z1);
  }
};

} // namespace crypto
