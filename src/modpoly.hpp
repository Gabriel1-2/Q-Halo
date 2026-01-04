#pragma once

#include "curve.hpp"
#include "fp2.hpp"
#include "isogeny.hpp"
#include "poly.hpp"
#include <random>
#include <vector>

namespace crypto {

template <typename Config> class ModularPolynomialGenerator {
  using FpT = Fp<Config>;
  using Fp2T = Fp2<Config>;
  using Poly = Polynomial<Fp2T>;
  using Point = PointProj<Config>;
  using Curve = MontgomeryCurve<Config>;
  using Iso = Isogeny<Config>;

public:
  // Helper: Find roots of polynomial over Fp2.
  // Supports brute force for small fields.
  static std::vector<Fp2T> find_roots(const std::vector<Fp2T> &poly_coeffs) {
    std::vector<Fp2T> roots;

    // Brute force check for small p
    // Fp2 size is p^2. For p=19, size=361. Very fast.
    // For larger p, this will hang.
    BigInt<Config::N_LIMBS> p_val = Config::p();
    if (p_val.limbs[0] > 1000) {
      std::cerr << "Warning: Brute force root finding on large field!"
                << std::endl;
      // Here we would need Cantor-Zassenhaus
      return roots;
    }

    uint64_t lim = p_val.limbs[0];
    for (uint64_t u0 = 0; u0 < lim; ++u0) {
      for (uint64_t u1 = 0; u1 < lim; ++u1) {
        BigInt<Config::N_LIMBS> b0, b1;
        b0.limbs[0] = u0;
        b1.limbs[0] = u1;
        FpT f0(b0);
        f0 = FpT::mul(f0, FpT(Config::R2()));
        FpT f1(b1);
        f1 = FpT::mul(f1, FpT(Config::R2()));
        Fp2T x(f0, f1);

        // Eval
        Fp2T val; // 0
        // Horner
        if (!poly_coeffs.empty()) {
          val = poly_coeffs.back();
          for (int k = (int)poly_coeffs.size() - 2; k >= 0; --k) {
            val = Fp2T::mul(val, x);
            val = Fp2T::add(val, poly_coeffs[k]);
          }
        }

        if (val.c0.data().is_zero() && val.c1.data().is_zero()) {
          roots.push_back(x);
        }
      }
    }
    return roots;
  }

  // Generate Phi_l(X, Y)
  // l = 2 or 3
  static std::vector<std::pair<Fp2T, Fp2T>> generate_phi(int l) {
    std::cout << "Generating Phi_" << l << "..." << std::endl;

    // Clear previous
    pairs_found.clear();

    // We need l+2 points for interpolation of degree l+1 polynomial (in Y).
    // Degree of Phi_l(X, Y) in Y is l+1.
    int required_points = l + 2;

    std::vector<std::pair<Fp2T, Poly>> data_points;

    // Random generator for A
    // Just deterministic scan for stability or random
    uint64_t seed = 1;

    while (data_points.size() < required_points) {
      seed++;
      // Generate valid A
      BigInt<Config::N_LIMBS> bA;
      bA.limbs[0] = seed;
      FpT fA(bA);
      fA = FpT::mul(fA, FpT(Config::R2()));
      Fp2T A(fA, FpT::zero()); // Real A for simplicity

      // Check if supersingular? Or generic.
      // Modular polynomials are valid for ALL curves.
      // Compute j
      Fp2T j_val = Curve::j_invariant(A);

      // Find Kernels
      std::vector<Fp2T> neighbors;

      if (l == 2) {
        // Roots of x(x^2 + Ax + 1)
        // x1 = 0.
        // x2, x3 roots of x^2 + Ax + 1.
        // We can solve quadratic directly without brute force.
        // x = (-A +/- sqrt(A^2 - 4))/2

        Fp2T A2 = Fp2T::sqr(A);
        Fp2T four;
        four.c0 = FpT(BigInt<Config::N_LIMBS>(4)).to_montgomery();
        Fp2T disc = Fp2T::sub(A2, four);
        Fp2T sqrt_disc = Fp2T::sqrt(disc);

        // If sqrt fails (non-QR and not handled), we skip
        // Our Fp2::sqrt handles everything now.

        Fp2T two;
        two.c0 = FpT(BigInt<Config::N_LIMBS>(2)).to_montgomery();
        Fp2T inv2 = Fp2T::inv(two);

        Fp2T negA = Fp2T::sub(Fp2T::zero(), A);
        Fp2T num1 = Fp2T::add(negA, sqrt_disc);
        Fp2T num2 = Fp2T::sub(negA, sqrt_disc);

        Fp2T r1 = Fp2T::mul(num1, inv2);
        Fp2T r2 = Fp2T::mul(num2, inv2);

        std::vector<Point> kernels;
        // (0:1)
        kernels.push_back(
            Point{Fp2T::zero(), Fp2T(FpT::mont_one(), FpT::zero())});
        // (r1:1)
        kernels.push_back(Point{r1, Fp2T(FpT::mont_one(), FpT::zero())});
        // (r2:1)
        kernels.push_back(Point{r2, Fp2T(FpT::mont_one(), FpT::zero())});

        // Compute 3 neighbors
        for (auto &K : kernels) {
          auto res = Iso::Compute2IsoCurve(K);
          // res is (A', C')
          Fp2T A_prime = res.first;
          Fp2T C_prime = res.second;
          Fp2T A_norm = Fp2T::mul(A_prime, Fp2T::inv(C_prime));
          Fp2T j_new = Curve::j_invariant(A_norm);
          neighbors.push_back(j_new);
        }
      } else if (l == 3) {
        // Roots of 3x^4 + 4Ax^3 + 6x^2 - 1
        // Use brute force finder
        std::vector<Fp2T> p_coeffs(5);
        // -1
        p_coeffs[0] =
            Fp2T::sub(Fp2T::zero(), Fp2T(FpT::mont_one(), FpT::zero()));
        p_coeffs[1] = Fp2T::zero();
        // 6
        p_coeffs[2] =
            Fp2T(FpT(BigInt<Config::N_LIMBS>(6)).to_montgomery(), FpT::zero());
        // 4A
        Fp2T four;
        four.c0 = FpT(BigInt<Config::N_LIMBS>(4)).to_montgomery();
        p_coeffs[3] = Fp2T::mul(four, A);
        // 3
        p_coeffs[4] =
            Fp2T(FpT(BigInt<Config::N_LIMBS>(3)).to_montgomery(), FpT::zero());

        std::vector<Fp2T> roots = find_roots(p_coeffs);

        if (roots.size() < 4) {
          // Not split? Skip this A.
          continue;
        }

        // Roots are x-coords of kernels.
        for (auto &x : roots) {
          Point K{x, Fp2T(FpT::mont_one(), FpT::zero())};
          Fp2T C_in = Fp2T(FpT::mont_one(), FpT::zero());
          auto res = Iso::Compute3IsoCurve(K, A, C_in);
          Fp2T A_norm = Fp2T::mul(res.first, Fp2T::inv(res.second));
          Fp2T j_new = Curve::j_invariant(A_norm);
          neighbors.push_back(j_new);
        }
      }

      // Construct Phi_l(X, j) = prod (X - neighbors)
      Poly uni_poly = Poly::one(Fp2T::mont_one());
      for (auto &neighbor : neighbors) {
        // (X - neighbor)
        Poly term = Poly::x(Fp2T::mont_one(), Fp2T::zero());
        Poly const_j(neighbor);
        term = Poly::sub(term, const_j);
        uni_poly = Poly::mul(uni_poly, term);
      }
      std::cout << "Data point " << data_points.size() << ": j=";
      j_val.print();
      std::cout << std::endl;
      std::cout << "UniPoly deg=" << uni_poly.coeffs.size() - 1 << std::endl;
      uni_poly.print("UP");

      data_points.push_back({j_val, uni_poly});

      // Save pairs (j, neighbor) for probe
      for (auto &n : neighbors) {
        pairs_found.push_back({j_val, n});
      }
    }

    // Bivariate Interpolation
    // Phi(X, Y) = sum_k c_k(Y) X^k
    // We have for each Y_i (=j_val), the polynomial P_i(X) = sum c_k(Y_i) X^k.
    // So for each coefficient index k, we have a list of pairs (Y_i,
    // coeff_k_of_P_i). We interpolate these to find c_k(Y).

    int deg_x = l + 1;                         // Expected degree
    std::vector<Poly> final_coeffs(deg_x + 1); // c_k(Y)

    for (int k = 0; k <= deg_x; ++k) {
      std::vector<std::pair<Fp2T, Fp2T>> points_for_k;
      for (auto &dp : data_points) {
        Fp2T y_val = dp.first;
        Poly &poly_x = dp.second;
        Fp2T coeff_val =
            (k < poly_x.coeffs.size()) ? poly_x.coeffs[k] : Fp2T::zero();
        points_for_k.push_back({y_val, coeff_val});
      }

      final_coeffs[k] = Poly::interpolate(points_for_k);
    }

    // We assume the caller handles the 2D structure.
    // We return a Polynomial in X, but coefficients are actually Polynomials in
    // Y? Or we flatten it? Let's print the result here and return just the
    // X-poly where coeffs are evaluated at Y=0? No. The task asks to "Print the
    // coefficients". I will print them.

    std::cout << "Phi_" << l << "(X, Y) Coefficients:" << std::endl;
    for (int k = 0; k <= deg_x; ++k) {
      std::cout << "Coeff of X^" << k << " (Polynomial in Y):" << std::endl;
      final_coeffs[k].print("   C");
    }

    // Store coeffs for analyzer
    phi_coeffs = final_coeffs;

    // Return the pairs found for the probe
    return pairs_found;
  }

  // Structure to hold just pairs for probe
  static std::vector<std::pair<Fp2T, Fp2T>> pairs_found;
  // Structure to hold coefficients for analyzer
  static std::vector<Poly> phi_coeffs;
};

template <typename Config>
std::vector<std::pair<typename ModularPolynomialGenerator<Config>::Fp2T,
                      typename ModularPolynomialGenerator<Config>::Fp2T>>
    ModularPolynomialGenerator<Config>::pairs_found;

template <typename Config>
std::vector<typename ModularPolynomialGenerator<Config>::Poly>
    ModularPolynomialGenerator<Config>::phi_coeffs;

} // namespace crypto
