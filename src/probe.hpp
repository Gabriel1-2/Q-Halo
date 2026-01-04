#pragma once

#include "fp2.hpp"
#include <iomanip>
#include <iostream>
#include <vector>


namespace crypto {

template <typename Config> class LinearizationProbe {
  using Fp2T = Fp2<Config>;

public:
  // Generate all monomials X^a Y^b for 0 <= a, b <= max_degree
  static std::vector<Fp2T> eval_monomials(const Fp2T &x, const Fp2T &y,
                                          int max_degree) {
    std::vector<Fp2T> v;
    // Precompute powers of x and y
    std::vector<Fp2T> x_pows(max_degree + 1);
    std::vector<Fp2T> y_pows(max_degree + 1);

    x_pows[0] = Fp2T::mont_one();
    y_pows[0] = Fp2T::mont_one();

    for (int i = 1; i <= max_degree; ++i) {
      x_pows[i] = Fp2T::mul(x_pows[i - 1], x);
      y_pows[i] = Fp2T::mul(y_pows[i - 1], y);
    }

    for (int a = 0; a <= max_degree; ++a) {
      for (int b = 0; b <= max_degree; ++b) {
        // Monomial X^a Y^b
        Fp2T val = Fp2T::mul(x_pows[a], y_pows[b]);
        v.push_back(val);
      }
    }
    return v;
  }

  // Compute error term for folding
  // P1 = (j1, j1_prime)
  // P2 = (j2, j2_prime)
  // r = scalar
  static void compute_error(const std::pair<Fp2T, Fp2T> &P1,
                            const std::pair<Fp2T, Fp2T> &P2, const Fp2T &r,
                            int max_degree) {
    // P_ideal = P1 + r*P2
    Fp2T r_j2 = Fp2T::mul(r, P2.first);
    Fp2T r_j2_prime = Fp2T::mul(r, P2.second);

    Fp2T ideal_first = Fp2T::add(P1.first, r_j2);
    Fp2T ideal_second = Fp2T::add(P1.second, r_j2_prime);

    // v_ideal
    std::vector<Fp2T> v_ideal =
        eval_monomials(ideal_first, ideal_second, max_degree);

    // v_folded = v(P1) + r*v(P2)
    std::vector<Fp2T> v1 = eval_monomials(P1.first, P1.second, max_degree);
    std::vector<Fp2T> v2 = eval_monomials(P2.first, P2.second, max_degree);

    std::vector<Fp2T> v_folded;
    for (size_t i = 0; i < v1.size(); ++i) {
      Fp2T term = Fp2T::mul(r, v2[i]);
      term = Fp2T::add(v1[i], term);
      v_folded.push_back(term);
    }

    // Error = v_ideal - v_folded
    std::cout << "--- Error Structure (r=...) ---" << std::endl;
    bool found_error = false;
    int count = 0;
    for (int a = 0; a <= max_degree; ++a) {
      for (int b = 0; b <= max_degree; ++b) {
        int idx = a * (max_degree + 1) + b;
        Fp2T diff = Fp2T::sub(v_ideal[idx], v_folded[idx]);

        if (!diff.is_zero()) {
          found_error = true;
          // Print low degree errors
          if (a + b <= 4) {
            std::cout << "E[" << a << "," << b << "] != 0. ";
            // diff.print();
            std::cout << std::endl;
          }
          count++;
        }
      }
    }

    if (!found_error) {
      std::cout << "WOW! No error? Perfect linearity?" << std::endl;
    } else {
      std::cout << "Total non-zero error terms: " << count << " / "
                << v_ideal.size() << std::endl;
    }
  }
};

} // namespace crypto
