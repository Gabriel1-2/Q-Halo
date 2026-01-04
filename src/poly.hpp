#pragma once

#include "fp2.hpp"
#include <cassert>
#include <iostream>
#include <vector>

namespace crypto {

template <typename CoeffT> class Polynomial {
public:
  std::vector<CoeffT> coeffs; // coeffs[i] is coefficient of x^i

  Polynomial() {}
  Polynomial(const std::vector<CoeffT> &c) : coeffs(c) {}
  Polynomial(size_t degree) : coeffs(degree + 1) {}

  // Initialize with single coefficient (constant polynomial)
  Polynomial(const CoeffT &c) { coeffs.push_back(c); }

  static Polynomial zero() { return Polynomial(); }
  static Polynomial one(const CoeffT &unity) { return Polynomial(unity); }
  static Polynomial x(const CoeffT &unity, const CoeffT &zero_val) {
    std::vector<CoeffT> c = {zero_val, unity};
    return Polynomial(c);
  }

  size_t degree() const {
    if (coeffs.empty())
      return 0;
    return coeffs.size() - 1;
  }

  // Evaluation at x
  CoeffT eval(const CoeffT &x) const {
    if (coeffs.empty())
      return CoeffT(); // Assume default init is 0
    CoeffT res = coeffs.back();
    for (int i = (int)coeffs.size() - 2; i >= 0; --i) {
      // res = res * x + coeffs[i]
      res = CoeffT::mul(res, x);
      res = CoeffT::add(res, coeffs[i]);
    }
    return res;
  }

  // Arithmetic
  static Polynomial add(const Polynomial &a, const Polynomial &b) {
    size_t max_deg = std::max(a.coeffs.size(), b.coeffs.size());
    std::vector<CoeffT> res_coeffs(max_deg);
    // Default init should be zero, but let's be safe if CoeffT doesn't default
    // to 0
    // ... Assuming CoeffT default ctor is 0 or we handle it.
    // Fp2 default ctor is 0.

    for (size_t i = 0; i < max_deg; ++i) {
      CoeffT v1 = (i < a.coeffs.size()) ? a.coeffs[i] : CoeffT(); // 0
      CoeffT v2 = (i < b.coeffs.size()) ? b.coeffs[i] : CoeffT(); // 0
      res_coeffs[i] = CoeffT::add(v1, v2);
    }
    // Normalize (remove trailing zeros)
    while (res_coeffs.size() > 1 &&
           res_coeffs.back().is_zero()) { // Assuming some is_zero check
      res_coeffs.pop_back();
    }
    return Polynomial(res_coeffs);
  }

  static Polynomial sub(const Polynomial &a, const Polynomial &b) {
    size_t max_deg = std::max(a.coeffs.size(), b.coeffs.size());
    std::vector<CoeffT> res_coeffs(max_deg);

    for (size_t i = 0; i < max_deg; ++i) {
      CoeffT v1 = (i < a.coeffs.size()) ? a.coeffs[i] : CoeffT();
      CoeffT v2 = (i < b.coeffs.size()) ? b.coeffs[i] : CoeffT();
      res_coeffs[i] = CoeffT::sub(v1, v2);
    }
    while (res_coeffs.size() > 1 &&
           res_coeffs.back().is_zero()) { // Need consistent is_zero
      res_coeffs.pop_back();
    }
    return Polynomial(res_coeffs);
  }

  static Polynomial mul(const Polynomial &a, const Polynomial &b) {
    if (a.coeffs.empty() || b.coeffs.empty())
      return Polynomial();
    size_t deg_a = a.coeffs.size() - 1;
    size_t deg_b = b.coeffs.size() - 1;
    std::vector<CoeffT> res_coeffs(deg_a + deg_b + 1); // Zero init

    for (size_t i = 0; i <= deg_a; ++i) {
      for (size_t j = 0; j <= deg_b; ++j) {
        CoeffT term = CoeffT::mul(a.coeffs[i], b.coeffs[j]);
        res_coeffs[i + j] = CoeffT::add(res_coeffs[i + j], term);
      }
    }
    return Polynomial(res_coeffs);
  }

  // Lagrange Interpolation
  // Points: (x, y) pairs
  static Polynomial
  interpolate(const std::vector<std::pair<CoeffT, CoeffT>> &points) {
    if (points.empty())
      return Polynomial();

    Polynomial result; // 0
    // Needs proper identity initialization for CoeffT (1 and 0)
    // We can extract 0 and 1 from the first point's types usually, or passed
    // in. Assuming CoeffT has static methods or we construct from scratch.
    // Actually, let's use the first point to allow generating 0/1.
    CoeffT one = CoeffT::mont_one(); // Assuming Fp/Fp2 interface
    CoeffT zero = CoeffT::zero();

    result = Polynomial(zero);

    for (size_t i = 0; i < points.size(); ++i) {
      CoeffT xi = points[i].first;
      CoeffT yi = points[i].second;

      // L_i(x) = product_{j!=i} (x - xj) / (xi - xj)
      Polynomial Li(one);
      CoeffT den = one;

      for (size_t j = 0; j < points.size(); ++j) {
        if (i == j)
          continue;
        CoeffT xj = points[j].first;

        // num = (x - xj)
        Polynomial term = Polynomial::x(one, zero); // x
        Polynomial const_xj(xj);
        term = sub(term, const_xj); // x - xj

        Li = mul(Li, term);

        // den = den * (xi - xj)
        CoeffT diff = CoeffT::sub(xi, xj);
        den = CoeffT::mul(den, diff);
      }

      // Li = Li * yi / den
      CoeffT den_inv = CoeffT::inv(den);
      CoeffT factor = CoeffT::mul(yi, den_inv);

      // Multiply poly by scalar
      for (auto &c : Li.coeffs) {
        c = CoeffT::mul(c, factor);
      }

      result = add(result, Li);
    }
    return result;
  }

  // Print helper
  void print(const std::string &name) const {
    std::cout << name << "(X) = ";
    for (int i = 0; i < coeffs.size(); ++i) {
      if (i > 0)
        std::cout << " + ";
      std::cout << "(";
      coeffs[i].print(); // Assuming CoeffT has print
      std::cout << ")*X^" << i;
    }
    std::cout << std::endl;
  }
};

} // namespace crypto
