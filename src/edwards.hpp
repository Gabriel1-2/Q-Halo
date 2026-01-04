#pragma once

#include "fp2.hpp"
#include <iostream>

namespace crypto {

// Twisted Edwards Point: (X, Y)
// Curve: a*X^2 + Y^2 = 1 + d*X^2*Y^2
template <typename Config> struct EdwardsPoint {
  Fp2<Config> X, Y;

  static EdwardsPoint identity() {
    EdwardsPoint p;
    p.X = Fp2<Config>::zero();
    p.Y = Fp2<Config>::one(); // Edwards identity is (0, 1)
    return p;
  }
};

// Twisted Edwards Curve with Complete Addition Formulas
// Curve: a*x^2 + y^2 = 1 + d*x^2*y^2
template <typename Config> class TwistedEdwards {
public:
  using Fp2T = Fp2<Config>;
  using Point = EdwardsPoint<Config>;

  Fp2T a; // Edwards parameter a
  Fp2T d; // Edwards parameter d

  // Construct from Montgomery coefficients A and B
  // Montgomery: By^2 = x^3 + Ax^2 + x
  // Edwards equivalents: a = (A + 2) / B, d = (A - 2) / B
  TwistedEdwards(const Fp2T &A, const Fp2T &B) {
    Fp2T two;
    two.c0.val.limbs[0] = 2;

    Fp2T A_plus_2 = Fp2T::add(A, two);
    Fp2T A_minus_2 = Fp2T::sub(A, two);
    Fp2T B_inv = Fp2T::inv(B);

    a = Fp2T::mul(A_plus_2, B_inv);
    d = Fp2T::mul(A_minus_2, B_inv);

    std::cout << "Edwards Curve: a*x^2 + y^2 = 1 + d*x^2*y^2" << std::endl;
    std::cout << "  a = ";
    a.print();
    std::cout << "  d = ";
    d.print();
  }

  // Direct constructor with Edwards parameters
  TwistedEdwards(const Fp2T &a_in, const Fp2T &d_in, bool) : a(a_in), d(d_in) {}

  // Deterministic Map to Edwards Curve
  // Given a seed, find a valid point on the curve.
  // Algorithm: Set y = seed, solve for x^2 = (1 - y^2) / (a - d*y^2)
  // If square root exists, return point. Otherwise increment seed and retry.
  Point MapToEdwards(uint64_t seed) const {
    Fp2T one = Fp2T::one();

    for (uint64_t attempt = seed; attempt < seed + 100; ++attempt) {
      Fp2T y;
      y.c0.val.limbs[0] = attempt % 19; // Keep in field for small params

      // Compute y^2
      Fp2T y2 = Fp2T::mul(y, y);

      // Numerator: 1 - y^2
      Fp2T num = Fp2T::sub(one, y2);

      // Denominator: a - d*y^2
      Fp2T d_y2 = Fp2T::mul(d, y2);
      Fp2T den = Fp2T::sub(a, d_y2);

      // Check for division by zero
      if (den.c0.val.limbs[0] == 0 && den.c1.val.limbs[0] == 0) {
        continue; // Skip this y
      }

      // x^2 = num / den
      Fp2T x2 = Fp2T::mul(num, Fp2T::inv(den));

      // Try to compute square root
      // For Fp2, sqrt is complex. For small field demo, we can brute-force.
      // Check if x2 is a quadratic residue by trying all values.

      bool found = false;
      Fp2T x;
      for (uint64_t i = 0; i < 19 && !found; ++i) {
        x.c0.val.limbs[0] = i;
        x.c1.val.limbs[0] = 0;
        Fp2T test = Fp2T::mul(x, x);
        if (test.c0.val.limbs[0] == x2.c0.val.limbs[0] &&
            test.c1.val.limbs[0] == x2.c1.val.limbs[0]) {
          found = true;
        }
      }

      if (found) {
        // Verify point is on curve: a*x^2 + y^2 =? 1 + d*x^2*y^2
        Fp2T x2_final = Fp2T::mul(x, x);
        Fp2T lhs = Fp2T::add(Fp2T::mul(a, x2_final), y2);
        Fp2T rhs = Fp2T::add(one, Fp2T::mul(d, Fp2T::mul(x2_final, y2)));

        if (lhs.c0.val.limbs[0] == rhs.c0.val.limbs[0]) {
          Point p;
          p.X = x;
          p.Y = y;
          std::cout << "MapToEdwards(" << seed
                    << "): Found valid point at y=" << attempt % 19
                    << std::endl;
          return p;
        }
      }
    }

    // Fallback: return identity if no point found
    std::cout << "MapToEdwards(" << seed
              << "): No valid point found, returning identity" << std::endl;
    return Point::identity();
  }

  // Complete Unified Addition Formula
  // Works for all cases: P + Q, P + P (doubling), P + O, etc.
  //
  // X3 = (X1*Y2 + Y1*X2) / (1 + d*X1*X2*Y1*Y2)
  // Y3 = (Y1*Y2 - a*X1*X2) / (1 - d*X1*X2*Y1*Y2)
  Point Add(const Point &P, const Point &Q) const {
    // Compute common terms
    Fp2T X1Y2 = Fp2T::mul(P.X, Q.Y);
    Fp2T Y1X2 = Fp2T::mul(P.Y, Q.X);
    Fp2T Y1Y2 = Fp2T::mul(P.Y, Q.Y);
    Fp2T X1X2 = Fp2T::mul(P.X, Q.X);

    // X1*X2*Y1*Y2
    Fp2T X1X2Y1Y2 = Fp2T::mul(X1X2, Fp2T::mul(P.Y, Q.Y));

    // d * X1X2Y1Y2
    Fp2T d_term = Fp2T::mul(d, X1X2Y1Y2);

    // a * X1X2
    Fp2T a_X1X2 = Fp2T::mul(a, X1X2);

    // Numerators
    Fp2T num_X = Fp2T::add(X1Y2, Y1X2);   // X1*Y2 + Y1*X2
    Fp2T num_Y = Fp2T::sub(Y1Y2, a_X1X2); // Y1*Y2 - a*X1*X2

    // Denominators
    Fp2T one = Fp2T::one();
    Fp2T den_X = Fp2T::add(one, d_term); // 1 + d*X1*X2*Y1*Y2
    Fp2T den_Y = Fp2T::sub(one, d_term); // 1 - d*X1*X2*Y1*Y2

    // Result
    Point R;
    R.X = Fp2T::mul(num_X, Fp2T::inv(den_X));
    R.Y = Fp2T::mul(num_Y, Fp2T::inv(den_Y));

    return R;
  }

  // Double a point (uses Add since formulas are unified)
  Point Double(const Point &P) const { return Add(P, P); }

  // Scalar multiplication using double-and-add
  Point ScalarMul(const Point &P, const BigInt<Config::N_LIMBS> &k) const {
    Point R = Point::identity();
    Point Q = P;

    // Simple double-and-add (left-to-right would be faster but this is clearer)
    for (size_t i = 0; i < Config::N_LIMBS * 64; ++i) {
      if (k.get_bit(i)) {
        R = Add(R, Q);
      }
      Q = Double(Q);
    }

    return R;
  }

  // Convert Montgomery point (x, y) to Edwards point (u, v)
  // u = x / y
  // v = (x - 1) / (x + 1)
  Point FromMontgomery(const Fp2T &x, const Fp2T &y) const {
    Point p;
    Fp2T one = Fp2T::one();

    p.X = Fp2T::mul(x, Fp2T::inv(y)); // u = x / y
    p.Y = Fp2T::mul(Fp2T::sub(x, one),
                    Fp2T::inv(Fp2T::add(x, one))); // v = (x-1)/(x+1)

    return p;
  }

  // Check if two points are equal
  static bool PointsEqual(const Point &P, const Point &Q) {
    for (size_t i = 0; i < Config::N_LIMBS; ++i) {
      if (P.X.c0.val.limbs[i] != Q.X.c0.val.limbs[i])
        return false;
      if (P.X.c1.val.limbs[i] != Q.X.c1.val.limbs[i])
        return false;
      if (P.Y.c0.val.limbs[i] != Q.Y.c0.val.limbs[i])
        return false;
      if (P.Y.c1.val.limbs[i] != Q.Y.c1.val.limbs[i])
        return false;
    }
    return true;
  }
};

// Birational Map between Montgomery and Edwards curves
// Montgomery: By^2 = x^3 + Ax^2 + x
// Edwards: a*x^2 + y^2 = 1 + d*x^2*y^2
template <typename Config> struct CurveMapper {
  using Fp2T = Fp2<Config>;
  using EdPoint = EdwardsPoint<Config>;

  // Montgomery point (u, v) with both coordinates
  struct MontPoint {
    Fp2T u, v;
  };

  // Mont -> Edwards (The Warp)
  // x = u / v
  // y = (u - 1) / (u + 1)
  static EdPoint MontToEdwards(const MontPoint &P) {
    EdPoint Q;
    Fp2T one = Fp2T::one();

    // x = u / v
    Q.X = Fp2T::mul(P.u, Fp2T::inv(P.v));

    // y = (u - 1) / (u + 1)
    Fp2T u_minus_1 = Fp2T::sub(P.u, one);
    Fp2T u_plus_1 = Fp2T::add(P.u, one);
    Q.Y = Fp2T::mul(u_minus_1, Fp2T::inv(u_plus_1));

    return Q;
  }

  // Edwards -> Mont (The Return)
  // u = (1 + y) / (1 - y)
  // v = u / x
  static MontPoint EdwardsToMont(const EdPoint &P) {
    MontPoint Q;
    Fp2T one = Fp2T::one();

    // u = (1 + y) / (1 - y)
    Fp2T one_plus_y = Fp2T::add(one, P.Y);
    Fp2T one_minus_y = Fp2T::sub(one, P.Y);
    Q.u = Fp2T::mul(one_plus_y, Fp2T::inv(one_minus_y));

    // v = u / x
    Q.v = Fp2T::mul(Q.u, Fp2T::inv(P.X));

    return Q;
  }

  // Check if two Montgomery points are equal (x-coord only for simplicity)
  static bool MontPointsEqualX(const MontPoint &P, const MontPoint &Q) {
    for (size_t i = 0; i < Config::N_LIMBS; ++i) {
      if (P.u.c0.val.limbs[i] != Q.u.c0.val.limbs[i])
        return false;
      if (P.u.c1.val.limbs[i] != Q.u.c1.val.limbs[i])
        return false;
    }
    return true;
  }
};

} // namespace crypto
