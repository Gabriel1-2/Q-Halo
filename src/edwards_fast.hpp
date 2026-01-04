#pragma once

#include "fp2.hpp"
#include <iostream>
#include <vector>

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
    // Note: Z can be anything non-zero.
    // If X=0, Y=Z, T=0 then it is identity.
    return X.is_zero() && !Z.is_zero() && Fp2T::equal(Y, Z);
  }
};

// Optimized Twisted Edwards Curve with Extended Projective Coordinates
// Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
template <typename Config> class TwistedEdwardsFast {
public:
  using Fp2T = Fp2<Config>;
  using Point = EdwardsPointExt<Config>;

  Fp2T a; // Edwards parameter a
  Fp2T d; // Edwards parameter d

  // Constructor with direct Edwards parameters
  TwistedEdwardsFast(const Fp2T &a_in, const Fp2T &d_in) : a(a_in), d(d_in) {}

  // Default constructor
  TwistedEdwardsFast() {}

  // Constructor from Montgomery curve coefficients
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

  // Extended Unified Addition
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

  // Dedicated Doubling Formula
  Point Double(const Point &P) const {
    Fp2T A = Fp2T::mul(P.X, P.X);
    Fp2T B = Fp2T::mul(P.Y, P.Y);
    Fp2T Z2 = Fp2T::mul(P.Z, P.Z);
    Fp2T C = Fp2T::add(Z2, Z2); // 2Z^2
    Fp2T D = Fp2T::mul(a, A);
    Fp2T XplusY = Fp2T::add(P.X, P.Y);
    Fp2T E = Fp2T::mul(XplusY, XplusY);
    E = Fp2T::sub(E, A);
    E = Fp2T::sub(E, B);
    Fp2T G = Fp2T::add(D, B);
    Fp2T F = Fp2T::sub(G, C);
    Fp2T H = Fp2T::sub(D, B);

    Point R;
    R.X = Fp2T::mul(E, F);
    R.Y = Fp2T::mul(G, H);
    R.T = Fp2T::mul(E, H);
    R.Z = Fp2T::mul(F, G);

    return R;
  }

  // Standard Scalar Multiplication (Double-and-Add)
  Point ScalarMul(const Point &P, const BigInt<Config::N_LIMBS> &k) const {
    if (k.is_zero())
      return Point::identity();

    Point R = Point::identity();
    Point Q = P; // 2^i * P

    // Scan bits
    for (size_t i = 0; i < Config::N_LIMBS * 64; ++i) {
      if (k.get_bit(i)) {
        R = Add(R, Q);
      }
      Q = Double(Q);
    }
    return R;
  }

  Point ScalarMul64(const Point &P, uint64_t k) const {
    if (k == 0)
      return Point::identity();
    if (k == 1)
      return P;
    Point R = Point::identity();
    Point Q = P;
    while (k > 0) {
      if (k & 1)
        R = Add(R, Q);
      Q = Double(Q);
      k >>= 1;
    }
    return R;
  }

  static void Normalize(Point &P) {
    if (P.Z.is_zero())
      return;
    Fp2T Z_inv = Fp2T::inv(P.Z);
    P.X = Fp2T::mul(P.X, Z_inv);
    P.Y = Fp2T::mul(P.Y, Z_inv);
    P.T = Fp2T::mul(P.X, P.Y);
    P.Z = Fp2T::one();
  }

  static bool PointsEqual(const Point &P, const Point &Q) {
    Fp2T X1Z2 = Fp2T::mul(P.X, Q.Z);
    Fp2T X2Z1 = Fp2T::mul(Q.X, P.Z);
    Fp2T Y1Z2 = Fp2T::mul(P.Y, Q.Z);
    Fp2T Y2Z1 = Fp2T::mul(Q.Y, P.Z);
    return Fp2T::equal(X1Z2, X2Z1) && Fp2T::equal(Y1Z2, Y2Z1);
  }
};

// Fixed-Base Comb Optimization Helper
// W = Window width (e.g., 8).
template <typename Config, int W> class FixedBaseComb {
  using Curve = TwistedEdwardsFast<Config>;
  using Point = typename Curve::Point;
  using Scalar = BigInt<Config::N_LIMBS>;

  Curve curve;
  std::vector<Point> table; // Precomputed table of size 2^W
  int num_windows;
  int spacing; // d

public:
  FixedBaseComb(const Curve &c, const Point &base) : curve(c) {
    // Parameter setup
    int total_bits = Config::N_LIMBS * 64;
    // spacing d = ceil(total_bits / W)
    spacing = (total_bits + W - 1) / W;
    // But for N=7 (448 bits), W=8 => d=56 exactly.

    // Precompute Basis Points: B[j] = 2^(j*spacing) * base
    // We need W basis points.
    std::vector<Point> basis;
    basis.reserve(W);
    Point P = base;

    // Use standard doubling to reach initial positions
    for (int j = 0; j < W; ++j) {
      basis.push_back(P);
      // Advance P by 'spacing' doublings
      if (j < W - 1) { // Skip last
        for (int k = 0; k < spacing; ++k) {
          P = curve.Double(P);
        }
      }
    }

    // Precompute Table T[val] for val in 0..2^W-1
    // T[val] = sum_{j=0}^{W-1} (bit_j(val) ? basis[j] : 0)
    size_t table_size = 1 << W;
    table.resize(table_size);

    table[0] = Point::identity(); // val=0 -> identity

    for (size_t val = 1; val < table_size; ++val) {
      // Can build iteratively: T[val] = T[val - msb] + basis[msb]
      // Or just naive sum
      Point acc = Point::identity();
      bool first = true;
      for (int j = 0; j < W; ++j) {
        if ((val >> j) & 1) {
          if (first) {
            acc = basis[j];
            first = false;
          } else {
            acc = curve.Add(acc, basis[j]);
          }
        }
      }
      table[val] = acc;
    }
  }

  // Constant-time(ish) scalar mul using comb
  Point Mul(const Scalar &k) const {
    Point R = Point::identity();

    // Loop from spacing-1 down to 0
    for (int i = spacing - 1; i >= 0; --i) {
      R = curve.Double(R);

      // Construct index
      // index = sum_{j=0}^{W-1} k[i + j*spacing] * 2^j
      uint32_t index = 0;
      for (int j = 0; j < W; ++j) {
        int bit_pos = i + j * spacing;
        if (k.get_bit(bit_pos)) {
          index |= (1 << j);
        }
      }

      // Add table entry
      if (index != 0) {
        // Optimization: if R is identity, just assign?
        // Extended Add handles identity well.
        R = curve.Add(R, table[index]);
      }
    }
    return R;
  }
};

} // namespace crypto
