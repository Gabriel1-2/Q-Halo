#pragma once

#include "analyzer.hpp"
#include <iostream>
#include <vector>


namespace crypto {

template <typename Config> class RelaxedIsogenyFolder {
  using Fp2T = Fp2<Config>;
  using Poly = Polynomial<Fp2T>;

public:
  struct RelaxedWitness {
    Fp2T j_start;
    Fp2T j_end;
    Fp2T u; // Slack variable: Phi(j_start, j_end) = u

    static RelaxedWitness zero() {
      return {Fp2T::zero(), Fp2T::zero(), Fp2T::zero()};
    }
  };

  // Verify: Phi2(j_start, j_end) == u
  static bool verify(const std::vector<Poly> &coeffs_y,
                     const RelaxedWitness &w) {
    Fp2T val = Phi2Analyzer<Config>::eval_phi(coeffs_y, w.j_start, w.j_end);

    // Check val == w.u
    // (val - u).is_zero()
    Fp2T diff = Fp2T::sub(val, w.u);

    bool ok = diff.c0.val.is_zero() && diff.c1.val.is_zero();
    /*
    std::cout << "Verification: ";
    if(ok) std::cout << "OK"; else std::cout << "FAIL";
    std::cout << std::endl;
    */
    return ok;
  }

  // Fold:
  // w_new = w1 + r * w2
  // u_new = u1 + r * u2 + E_cross
  static RelaxedWitness fold(const std::vector<Poly> &coeffs_y,
                             const RelaxedWitness &w1, const RelaxedWitness &w2,
                             const Fp2T &r) {
    // 1. Linearly fold the j-invariants
    Fp2T r_jstart2 = Fp2T::mul(r, w2.j_start);
    Fp2T r_jend2 = Fp2T::mul(r, w2.j_end);

    Fp2T j_start_new = Fp2T::add(w1.j_start, r_jstart2);
    Fp2T j_end_new = Fp2T::add(w1.j_end, r_jend2);

    // 2. Compute the Cross Term E_cross
    // E = Phi(w_new) - (Phi(w1) + r Phi(w2)) ???
    // Wait, definition of Relaxed Folding:
    // Ideal relation: Phi(w_new) = u_new
    // u_new := u1 + r*u2 + E
    // Where E such that equality holds.
    // So E = Phi(w_new) - (u1 + r*u2).
    // Since we assume w1, w2 are valid witnesses: u1=Phi(w1), u2=Phi(w2).
    // So E = Phi(w_new) - (Phi(w1) + r Phi(w2)).
    // Note: Nova usually has r^d factors, but for degree d constraints.
    // But here we just compute the shortage E explicitly.

    // Eval Phi(w_new)
    Fp2T phi_new =
        Phi2Analyzer<Config>::eval_phi(coeffs_y, j_start_new, j_end_new);

    // Eval Phi(w1)
    Fp2T phi1 = Phi2Analyzer<Config>::eval_phi(coeffs_y, w1.j_start, w1.j_end);

    // Eval Phi(w2)
    Fp2T phi2 = Phi2Analyzer<Config>::eval_phi(coeffs_y, w2.j_start, w2.j_end);

    // R * Phi(w2) -- Note: check if we need r^deg powers?
    // Standard folding: C(x+ry) = C(x) + r^d C(y) + CrossTerms.
    // If we define Relaxed Witness as satisfying C(w) = u.
    // Then we want C(w1+rw2) = u_new.
    // u_new = u1 + r^d u2 + E.
    // Then E = C(w1+rw2) - u1 - r^d u2.
    // Let's use linear accumulation for u if possible, i.e. u_new = u1 + r*u2 +
    // E. Then E = C(w1+rw2) - C(w1) - r*C(w2). This is perfectly valid as long
    // as we track u correctly.

    Fp2T r_phi2 = Fp2T::mul(r, phi2);

    Fp2T rhs = Fp2T::add(phi1, r_phi2);
    Fp2T error_term = Fp2T::sub(phi_new, rhs);

    // 3. Update u
    // u_new = u1 + r*u2 + error_term
    Fp2T r_u2 = Fp2T::mul(r, w2.u);
    Fp2T u_new = Fp2T::add(w1.u, r_u2);
    u_new = Fp2T::add(u_new, error_term);

    return RelaxedWitness{j_start_new, j_end_new, u_new};
  }
};

} // namespace crypto
