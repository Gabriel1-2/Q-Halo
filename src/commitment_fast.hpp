#pragma once

#include "edwards_fast.hpp"
#include "fp2.hpp"

namespace crypto {

// Optimized Pedersen Commitment using Fast Edwards Curves
// Uses extended projective coordinates for 100-200x speedup
// C = [value] * G + [blind] * H
template <typename Config> class PedersenCommitmentFast {
public:
  using Fp2T = Fp2<Config>;
  using Curve = TwistedEdwardsFast<Config>;
  using Point = typename Curve::Point;

private:
  Curve curve;
  Point G; // Generator 1
  Point H; // Generator 2

public:
  // Initialize with default Edwards curve parameters
  PedersenCommitmentFast()
      : curve([this]() {
          // Create curve parameters in Montgomery form
          Fp2T a, d;
          // a = 6 (in Montgomery form)
          a.c0.val.limbs[0] = 6;
          a.c0 = a.c0.to_montgomery();
          a.c1 = Fp2T::FpT::zero();
          // d = 4 (in Montgomery form)
          d.c0.val.limbs[0] = 4;
          d.c0 = d.c0.to_montgomery();
          d.c1 = Fp2T::FpT::zero();
          return Curve(a, d);
        }()) {
    // Initialize generators with fixed points
    InitGenerators();
  }

  void InitGenerators() {
    // Init G (found at y=2)
    G.X.c0.val.limbs = {0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL};
    G.X.c1.val.limbs = {0x4525650f93dafbaeULL, 0x69b5460e9fedb813ULL,
                        0xacc1b5af828aff05ULL, 0x3cf02455dba6978bULL,
                        0x60989f855d753e5ULL,  0x530d061f0ee7a3adULL,
                        0xebb430326ed6ULL};
    G.Y.c0.val.limbs = {0xe858ULL,
                        0x0ULL,
                        0x0ULL,
                        0x721fe809f8000000ULL,
                        0xb00349f6ab3f59a9ULL,
                        0xd264a8a8beee8219ULL,
                        0x1d9dd4f7a5db5ULL};
    G.Y.c1.val.limbs = {0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL};
    G.Z = Fp2T::one();
    G.T = Fp2T::mul(G.X, G.Y);

    // Init H (found at y=3)
    H.X.c0.val.limbs = {0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL};
    H.X.c1.val.limbs = {0x3b4d977af20dbea9ULL, 0x320b2d8876d9430eULL,
                        0x95f8e700b505aa9aULL, 0xc9d5739bb8760e5fULL,
                        0x44587566b39a8ffdULL, 0xe611648eb3457366ULL,
                        0x1a1cce1cff167ULL};
    H.Y.c0.val.limbs = {0x15c85ULL,
                        0x0ULL,
                        0x0ULL,
                        0x2d6e659411000000ULL,
                        0xc3e9279cf8657daULL,
                        0x4e9a9d269ca0a2d0ULL,
                        0x92acd020194cULL};
    H.Y.c1.val.limbs = {0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL};
    H.Z = Fp2T::one();
    H.T = Fp2T::mul(H.X, H.Y);
  }

  // Commit to a value with a blinding factor (64-bit version)
  // C = [value] * G + [blind] * H
  Point Commit(uint64_t value, uint64_t blind) const {
    // [value] * G using fast scalar mul
    Point vG = curve.ScalarMul64(G, value);

    // [blind] * H using fast scalar mul
    Point bH = curve.ScalarMul64(H, blind);

    // C = vG + bH (single addition in projective)
    return curve.Add(vG, bH);
  }

  // Commit with full BigInt scalar
  Point CommitFull(const BigInt<Config::N_LIMBS> &value,
                   const BigInt<Config::N_LIMBS> &blind) const {
    Point vG = curve.ScalarMul(G, value);
    Point bH = curve.ScalarMul(H, blind);
    return curve.Add(vG, bH);
  }

  // Add two commitment points (projective addition - no inversion!)
  Point AddCommitments(const Point &C1, const Point &C2) const {
    return curve.Add(C1, C2);
  }

  // Scalar multiply a commitment point with 64-bit scalar
  Point ScalarMul(const Point &C, uint64_t scalar) const {
    return curve.ScalarMul64(C, scalar);
  }

  // Check if two commitment points are equal (projective comparison)
  static bool PointsEqual(const Point &P, const Point &Q) {
    return Curve::PointsEqual(P, Q);
  }

  // Normalize a point to affine for output/verification (single inversion)
  static void Normalize(Point &P) { Curve::Normalize(P); }

  // Get curve for direct operations
  const Curve &GetCurve() const { return curve; }
};

} // namespace crypto
