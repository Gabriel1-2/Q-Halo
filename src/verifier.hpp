#pragma once

#include "relaxed_folding.hpp"
#include <iostream>
#include <vector>


namespace crypto {

template <typename Config> class SmartContractVerifier {
  using Fp2T = Fp2<Config>;
  using Poly = Polynomial<Fp2T>;
  using Folder = RelaxedIsogenyFolder<Config>;
  using Witness = typename Folder::RelaxedWitness;

public:
  // Simulates an O(1) on-chain check
  // In a real contract, 'coeffs_y' would be hardcoded constants in the
  // bytecode.
  static bool verify_proof(const std::vector<Poly> &coeffs_y,
                           const Witness &final_witness) {
    std::cout << "--- Smart Contract Verifier ---" << std::endl;
    std::cout << "Gas Cost: O(1) (Independent of recursion steps)" << std::endl;

    // The on-chain logic is exactly the relaxed check:
    // Phi(j_start, j_end) == u

    bool result = Folder::verify(coeffs_y, final_witness);

    if (result) {
      std::cout << "VERIFICATION SUCCESS: Valid Isogeny Chain Proof."
                << std::endl;
    } else {
      std::cout << "VERIFICATION FAILURE: Invalid Proof." << std::endl;
    }

    return result;
  }
};

} // namespace crypto
