#pragma once

#include "curve.hpp"
#include "isogeny.hpp"

namespace crypto {

template <typename Config> class FoldingScheme {
public:
  using Curve = MontgomeryCurve<Config>;
  using FullPoint = typename Curve::FullPoint;
  using PointProj = PointProj<Config>;
  using Fp2T = Fp2<Config>;
  using BigIntT = BigInt<Config::N_LIMBS>;

  struct Witness {
    FullPoint P;
    FullPoint Q;
  };

  // BatchFold: P_new = w1.P + [r]w2.P, Q_new = w1.Q + [r]w2.Q
  static Witness BatchFold(const Witness &w1, const Witness &w2,
                           const BigIntT &r, const Fp2T &A) {
    // scalar mul w2.P
    FullPoint rP2 = Curve::scalar_mul(w2.P, r, A);
    FullPoint rQ2 = Curve::scalar_mul(w2.Q, r, A);

    // Add to w1
    FullPoint P_new = Curve::add_affine(w1.P, rP2, A);
    FullPoint Q_new = Curve::add_affine(w1.Q, rQ2, A);

    return Witness{P_new, Q_new};
  }

  template <typename VeluT>
  static bool VerifyBatch(const Witness &w_folded, const VeluT &phi) {
    // phi(P) == Q?
    // Convert P to proj
    PointProj P_proj;
    P_proj.X = w_folded.P.X;
    P_proj.Z = w_folded.P.Z;

    PointProj Q_computed = P_proj;
    phi.Eval(Q_computed); // In-place eval

    // Check Q_computed == w_folded.Q (Projective)
    // Q_computed.X / Q_computed.Z == w_folded.Q.X / w_folded.Q.Z
    // Q_computed.X * w_folded.Q.Z == Q_computed.Z * w_folded.Q.X

    Fp2T lhs = Fp2T::mul(Q_computed.X, w_folded.Q.Z);
    Fp2T rhs = Fp2T::mul(Q_computed.Z, w_folded.Q.X);

    // Compare bitwise
    for (size_t i = 0; i < Config::N_LIMBS; ++i) {
      if (lhs.c0.val.limbs[i] != rhs.c0.val.limbs[i])
        return false;
      if (lhs.c1.val.limbs[i] != rhs.c1.val.limbs[i])
        return false;
    }
    return true;
  }
};

} // namespace crypto
