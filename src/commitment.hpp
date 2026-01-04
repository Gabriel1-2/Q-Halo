#pragma once

#include "edwards.hpp"
#include "fp2.hpp"
#include <iostream>

namespace crypto {

// Pedersen Commitment using Twisted Edwards Curve
// C = [value] * G + [blind] * H
template <typename Config> class PedersenCommitment {
public:
  using Fp2T = Fp2<Config>;
  using Curve = TwistedEdwards<Config>;
  using Point = typename Curve::Point;

private:
  Curve curve;
  Point G; // Generator 1
  Point H; // Generator 2 (must be independent of G for hiding)

public:
  // Initialize with Edwards curve derived from Montgomery (A=6, B=1)
  PedersenCommitment()
      : curve([]() {
          Fp2T A, B;
          A.c0.val.limbs[0] = 6;
          B.c0.val.limbs[0] = 1;
          return Curve(A, B);
        }()) {
    // Generate G and H using MapToEdwards for valid on-curve points
    G = curve.MapToEdwards(1);
    H = curve.MapToEdwards(2);

    std::cout << "Pedersen (Edwards) Setup:" << std::endl;
    std::cout << "  G = (";
    G.X.print();
    std::cout << ", ";
    G.Y.print();
    std::cout << ")" << std::endl;
    std::cout << "  H = (";
    H.X.print();
    std::cout << ", ";
    H.Y.print();
    std::cout << ")" << std::endl;
  }

  // Commit to a value with a blinding factor
  // C = [value] * G + [blind] * H
  Point Commit(uint64_t value, uint64_t blind) const {
    BigInt<Config::N_LIMBS> val_scalar;
    val_scalar.limbs[0] = value;

    BigInt<Config::N_LIMBS> blind_scalar;
    blind_scalar.limbs[0] = blind;

    // [value] * G
    Point vG = curve.ScalarMul(G, val_scalar);

    // [blind] * H
    Point bH = curve.ScalarMul(H, blind_scalar);

    // C = vG + bH (Edwards complete addition!)
    return curve.Add(vG, bH);
  }

  // Overload for Fp2T inputs
  Point Commit(const Fp2T &value, const Fp2T &blind) const {
    return Commit(value.c0.val.limbs[0], blind.c0.val.limbs[0]);
  }

  // Add two commitment points (Edwards addition)
  Point AddCommitments(const Point &C1, const Point &C2) const {
    return curve.Add(C1, C2);
  }

  // Scalar multiply a commitment point
  Point ScalarMul(const Point &C, uint64_t scalar) const {
    BigInt<Config::N_LIMBS> s;
    s.limbs[0] = scalar;
    return curve.ScalarMul(C, s);
  }

  // Homomorphic fold: C_folded = C1 + [r] * C2
  Point FoldCommitments(const Point &C1, const Point &C2, uint64_t r) const {
    Point rC2 = ScalarMul(C2, r);
    return curve.Add(C1, rC2);
  }

  // Check if two points are equal
  static bool PointsEqual(const Point &P, const Point &Q) {
    return Curve::PointsEqual(P, Q);
  }

  const Point &getG() const { return G; }
  const Point &getH() const { return H; }
  const Curve &getCurve() const { return curve; }
};

} // namespace crypto
