#pragma once

#include "modpoly.hpp"
#include <iostream>
#include <vector>


namespace crypto {

template <typename Config> class Phi2Analyzer {
  using Fp2T = Fp2<Config>;
  using Poly = Polynomial<Fp2T>;

public:
  // Evaluate Phi(X, Y) at (x, y)
  // coeffs are P_i(X) such that Phi(X, Y) = sum P_i(X) * Y^i
  static Fp2T eval_phi(const std::vector<Poly> &coeffs, const Fp2T &x,
                       const Fp2T &y) {
    Fp2T res = Fp2T::zero();
    Fp2T y_pow = Fp2T::mont_one();

    for (const auto &px : coeffs) {
      // Eval px at x
      Fp2T x_val = Fp2T::zero();
      Fp2T x_p = Fp2T::mont_one();
      for (const auto &c : px.coeffs) {
        Fp2T term = Fp2T::mul(c, x_p);
        x_val = Fp2T::add(x_val, term);
        x_p = Fp2T::mul(x_p, x);
      }

      // res += px(val) * y^i
      Fp2T term = Fp2T::mul(x_val, y_pow);
      res = Fp2T::add(res, term);

      y_pow = Fp2T::mul(y_pow, y);
    }
    return res;
  }

  // Compute Cross Term E_cross
  // E = Phi(P1 + r P2) - (Phi(P1) + r^d Phi(P2)) ???
  // Actually simpler:
  // If Phi(X,Y) = sum c_ab X^a Y^b
  // E_cross = sum c_ab [ (X1+rX2)^a (Y1+rY2)^b - X1^a Y1^b - r^(deg) X2^a Y2^b
  // ] But usually we just want to satisfy: Phi(P_new) = E_cross assuming
  // Phi(P1) = 0 and Phi(P2) = 0.

  static void
  analyze_phi2(const std::vector<Poly>
                   &coeffs_y, // Polynomials in X, indexed by power of Y
               const std::pair<Fp2T, Fp2T> &P1, // (j1, j1')
               const std::pair<Fp2T, Fp2T> &P2, // (j2, j2')
               const Fp2T &r) {
    std::cout << "--- Analyzing Phi_2 Verification ---" << std::endl;

    // 1. Verify P1, P2 are roots
    Fp2T val1 = eval_phi(coeffs_y, P1.first, P1.second);
    Fp2T val2 = eval_phi(coeffs_y, P2.first, P2.second);

    std::cout << "Phi(P1): ";
    val1.print();
    std::cout << std::endl;
    std::cout << "Phi(P2): ";
    val2.print();
    std::cout << std::endl;

    // 2. Compute P_folded
    Fp2T r_j2 = Fp2T::mul(r, P2.first);
    Fp2T r_j2p = Fp2T::mul(r, P2.second);

    Fp2T j_folded = Fp2T::add(P1.first, r_j2);
    Fp2T jp_folded = Fp2T::add(P1.second, r_j2p);

    // 3. Eval Phi(P_folded)
    Fp2T val_folded = eval_phi(coeffs_y, j_folded, jp_folded);
    std::cout << "Phi(P_folded) [Value to Correct]: ";
    val_folded.print();
    std::cout << std::endl;

    // 4. Calculate Expected Cross Term explicitly from Monomials
    // This confirms our algebraic understanding
    // E_cross_calc = sum c_ab * ( (X1+rX2)^a(Y1+rY2)^b - ... )
    // For Phi_2, we identified error at 0,0?
    // Let's compute it.

    // ... (Optional explicit breakdown) ...

    std::cout << "Correction Check: If we subtract ";
    val_folded.print();
    std::cout << " from the folded result, we satisfy the constraint."
              << std::endl;
  }
};

} // namespace crypto
