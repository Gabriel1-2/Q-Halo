
#pragma once

#include "relaxed_folding.hpp"
#include "transcript.hpp" // Added for Transcript
#include <iostream>
#include <vector>

#ifdef __GNUC__
#define POPCOUNT_64 __builtin_popcountll
#elif _MSC_VER
#include <intrin.h>
#define POPCOUNT_64 __popcnt64
#else
inline int generic_popcount_64(uint64_t n) {
  int count = 0;
  while (n > 0) {
    n &= (n - 1);
    count++;
  }
  return count;
}
#define POPCOUNT_64 generic_popcount_64
#endif

namespace crypto {

template <typename Config> class RecursiveIsogenyManager {
  using Fp2T = Fp2<Config>;
  using Poly = Polynomial<Fp2T>;
  using Folder = RelaxedIsogenyFolder<Config>;
  using Witness = typename Folder::RelaxedWitness;
  using Transcript = Transcript<Config>; // Added for Transcript

public:
  static Witness
  run_stress_test(const std::vector<Poly> &coeffs_y,
                  const std::vector<std::pair<Fp2T, Fp2T>> &valid_pairs,
                  int iterations) {
    std::cout << "--- Starting Recursion Stress Test (" << iterations
              << " iters) [Fiat-Shamir] ---" << std::endl;

    if (valid_pairs.empty()) {
      std::cout << "No valid pairs to fold!" << std::endl;
      return Witness();
    }

    // 1. Initialize Accumulator
    auto p0 = valid_pairs[0];
    Witness accumulator = {p0.first, p0.second, Fp2T::zero()};

    // 2. Initialize Transcript
    Transcript transcript;
    transcript.Absorb(accumulator); // Bind initial state

    // Seed for choosing steps (this remains random/external, as the Prover
    // chooses the path) But the 'r' must be deterministic based on that
    // choice.
    uint64_t step_seed = 12345;

    for (int i = 0; i < iterations; ++i) {
      // Prover chooses next step
      int idx = (step_seed >> 16) % valid_pairs.size();
      step_seed = (step_seed * 6364136223846793005ULL + 1442695040888963407ULL);

      auto p_next = valid_pairs[idx];
      Witness w_next = {p_next.first, p_next.second, Fp2T::zero()};

      // Fiat-Shamir: Absorb the new witness component
      transcript.Absorb(w_next);

      // Squeeze Challenge r
      Fp2T r = transcript.Squeeze();

      // Ensure r is non-zero (unlikely but good practice)
      if (r.c0.val.limbs[0] == 0 && r.c1.val.limbs[0] == 0) {
        r.c0.val.limbs[0] = 1;
      }

      // Fold
      Witness acc_new = Folder::fold(coeffs_y, accumulator, w_next, r);

      // Verify
      if (!Folder::verify(coeffs_y, acc_new)) {
        std::cout << "Iter " << i << ": VERIFICATION FAILED!" << std::endl;
        return Witness();
      }

      // Log Slack
      std::cout << "Iter " << i << ": Verified [FS]. Slack u = ";
      acc_new.u.print();
      std::cout << std::endl;

      accumulator = acc_new;
    }

    std::cout << "--- Recursion Stress Test PASSED ---" << std::endl;
    return accumulator;
  }

  static int hamming_weight(const Fp2T &val) {
    int hw = 0;
    // Count bits in c0
    for (auto limb : val.c0.val.limbs) {
      // Check Config::N_LIMBS? Fp2T::FpT::N ??
      // We can just use standard popcount
      // Assumes uint64_t limbs
      hw += __builtin_popcountll(limb);
    }
    // Count bits in c1
    for (auto limb : val.c1.val.limbs) {
      hw += __builtin_popcountll(limb);
    }
    return hw;
  }

  static void
  run_error_analysis(const std::vector<Poly> &coeffs_y,
                     const std::vector<std::pair<Fp2T, Fp2T>> &valid_pairs,
                     int iterations) {
    std::cout << "--- Starting Error Growth Analysis (" << iterations
              << " steps) ---" << std::endl;
    std::cout << "Step,HammingWeight" << std::endl; // CSV Header

    if (valid_pairs.empty())
      return;

    // Init
    auto p0 = valid_pairs[0];
    Witness accumulator = {p0.first, p0.second, Fp2T::zero()};

    uint64_t seed = 99999;
    auto get_random_r = [&]() {
      seed = (seed * 6364136223846793005ULL + 1442695040888963407ULL);
      Fp2T r;
      r.c0.val.limbs[0] = seed % 19;
      if (r.c0.val.limbs[0] == 0)
        r.c0.val.limbs[0] = 1;
      return r;
    };

    for (int i = 1; i <= iterations; ++i) {
      int idx = (seed >> 16) % valid_pairs.size();
      auto p_next = valid_pairs[idx];
      Witness w_next = {p_next.first, p_next.second, Fp2T::zero()};

      Fp2T r = get_random_r();
      accumulator = Folder::fold(coeffs_y, accumulator, w_next, r);

      // Check specific steps requested or all? Use requested checkpoints
      // User asked: "Log ... at steps 1, 10, 100, 1000"
      // But also "Output: A simple CSV format".
      // Providing all data is better for "Hypothesis Check".
      // We will output all.

      int hw = hamming_weight(accumulator.u);
      std::cout << i << "," << hw << std::endl;
    }
  }
};

} // namespace crypto
