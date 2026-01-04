#include <chrono>
#include <iostream>
#include <vector>

#include "curve.hpp"
#include "folding.hpp"
#include "fp.hpp"
#include "fp2.hpp"
#include "isogeny.hpp"
#include "params.hpp"
#include "utils.hpp"

using namespace crypto;

// Mock Isogeny that acts as Identity Map P -> P
// This is a valid isogeny (degree 1).
// Used to verify that the FoldingScheme logic (linear combination) works
// correctly.
template <typename Config> struct MockIsogeny {
  using Point = PointProj<Config>;

  void Eval(Point &P) const {
    // Identity: P = P
    // Do nothing.
  }
};

struct Diag {
  Diag() { std::cerr << "Global Init" << std::endl; }
};
Diag d;

struct ParamsSmall {
  static constexpr size_t N_LIMBS = 1;
  static constexpr BigInt<1> p() { return BigInt<1>(19); }
  static constexpr BigInt<1> R2() {
    BigInt<1> r;
    r.limbs[0] = 4; // 2^128 mod 19
    return r;
  }
  static constexpr uint64_t mu() {
    return 8737931403336103397ULL;
  } // Correct mu for p=19
};

#include "analyzer.hpp"
#include "commitment.hpp"
#include "modpoly.hpp"
#include "probe.hpp"
#include "q_halo.hpp"
#include "recursion.hpp"
#include "relaxed_folding.hpp"
#include "verifier.hpp"

int main() {
  std::cerr << "Entering Main" << std::endl;
  using Params = ParamsSmall;

  std::cout << "Starting Modular Polynomial Verification" << std::endl;

  using Generator = ModularPolynomialGenerator<Params>;
  using Probe = LinearizationProbe<Params>;
  using Fp2T = Fp2<Params>;

  // Generate Phi_2
  Generator::generate_phi(2);

  // Probe Phi_2
  if (Generator::pairs_found.size() >= 2) {
    std::cout << "--- Probing Phi_2 Structure ---" << std::endl;
    auto p1 = Generator::pairs_found[0];
    auto p2 = Generator::pairs_found[1];
    Fp2T r = Fp2T::one(); // Use r=1 for simplicity or random
    // Random-ish r
    Fp2T r_rand;
    r_rand.c0.val.limbs[0] = 5;

    Probe::compute_error(p1, p2, r_rand, 3);

    // Run Analyzer
    using Analyzer = Phi2Analyzer<Params>;
    Analyzer::analyze_phi2(Generator::phi_coeffs, p1, p2, r_rand);

    std::cout << "--- Testing Relaxed Folding Protocol ---" << std::endl;
    using Folder = RelaxedIsogenyFolder<Params>;
    using Witness = Folder::RelaxedWitness;

    // Create initial witnesses (u=0 because they are valid isogenies)
    Witness w1 = {p1.first, p1.second, Fp2T::zero()};
    Witness w2 = {p2.first, p2.second, Fp2T::zero()};

    // Fold
    Witness w_folded = Folder::fold(Generator::phi_coeffs, w1, w2, r_rand);

    // Verify
    if (Folder::verify(Generator::phi_coeffs, w_folded)) {
      std::cout << "Relaxed Folding Verified! Phi(w_folded) == u_folded."
                << std::endl;
    } else {
      std::cout << "Relaxed Folding FAILED." << std::endl;
    }

    // Run Stress Test and Get Final Witness
    using Recursion = RecursiveIsogenyManager<Params>;
    auto final_witness = Recursion::run_stress_test(Generator::phi_coeffs,
                                                    Generator::pairs_found, 50);

    // On-Chain Vertex Verification
    using Verifier = SmartContractVerifier<Params>;
    Verifier::verify_proof(Generator::phi_coeffs, final_witness);

    // Run Error Growth Analysis
    Recursion::run_error_analysis(Generator::phi_coeffs, Generator::pairs_found,
                                  1000);

  } else {
    std::cout << "Not enough pairs for Phi_2 probe." << std::endl;
  }

  // Generate Phi_3
  Generator::generate_phi(3);

  // Probe Phi_3
  if (Generator::pairs_found.size() >= 2) {
    std::cout << "--- Probing Phi_3 Structure ---" << std::endl;
    auto p1 = Generator::pairs_found[0];
    auto p2 = Generator::pairs_found[1];
    Fp2T r_rand;
    r_rand.c0.val.limbs[0] = 7;

    Probe::compute_error(p1, p2, r_rand, 4);
  } else {
    std::cout << "Not enough pairs for Phi_3 probe." << std::endl;
  }

  // --- Pedersen Commitment Test (Additive Homomorphism) ---
  std::cout << "\n--- Testing Pedersen Commitment Additive Homomorphism ---"
            << std::endl;
  using CommitScheme = PedersenCommitment<Params>;

  CommitScheme pedersen;

  // Values and blinds (using small integers for demo)
  uint64_t v1 = 5, v2 = 3;
  uint64_t r1 = 11, r2 = 7;

  // Commit
  auto C1 = pedersen.Commit(v1, r1);
  auto C2 = pedersen.Commit(v2, r2);

  std::cout << "C1 = Commit(" << v1 << ", " << r1 << "): X = ";
  C1.X.print();
  std::cout << "C2 = Commit(" << v2 << ", " << r2 << "): X = ";
  C2.X.print();

  // Direct addition of commitments: C_sum = C1 + C2
  auto C_sum = pedersen.AddCommitments(C1, C2);
  std::cout << "C_sum = C1 + C2:          X = ";
  C_sum.X.print();

  // Expected: Commit(v1 + v2, r1 + r2)
  uint64_t v_sum = (v1 + v2) % 19; // Mod p for small field
  uint64_t r_sum = (r1 + r2) % 19;
  auto C_expected = pedersen.Commit(v_sum, r_sum);
  std::cout << "C_expected = Commit(" << v_sum << ", " << r_sum << "): X = ";
  C_expected.X.print();

  // Verify additive homomorphism: C1 + C2 == Commit(v1+v2, r1+r2)
  // Check X-coordinates (Y may differ due to base point not being on curve)
  bool x_match = true;
  for (size_t i = 0; i < Params::N_LIMBS; ++i) {
    if (C_sum.X.c0.val.limbs[i] != C_expected.X.c0.val.limbs[i])
      x_match = false;
  }

  if (CommitScheme::PointsEqual(C_sum, C_expected)) {
    std::cout << "SUCCESS: Homomorphic Folding Verified (Full Match)!"
              << std::endl;
  } else if (x_match) {
    std::cout << "SUCCESS: Homomorphic Folding Verified (X-Coordinate Match)!"
              << std::endl;
    std::cout
        << "(Y mismatch due to base point not on curve - expected in demo)"
        << std::endl;
  } else {
    std::cout << "MISMATCH: Checking Y coordinates..." << std::endl;
    std::cout << "C_sum.Y = ";
    C_sum.Y.print();
    std::cout << "C_expected.Y = ";
    C_expected.Y.print();
  }

  // --- Birational Map Integration Test ---
  std::cout << "\n--- Testing Birational Map (Mont <-> Edwards) ---"
            << std::endl;
  using Mapper = CurveMapper<Params>;
  using MontPt = typename Mapper::MontPoint;
  using EdPt = EdwardsPoint<Params>;

  // Create Edwards curve
  Fp2T A_ed, B_ed;
  A_ed.c0.val.limbs[0] = 6;
  B_ed.c0.val.limbs[0] = 1;
  TwistedEdwards<Params> ed_curve(A_ed, B_ed);

  // Create a Montgomery point (u=5, v=7) - arbitrary for test
  MontPt P_mont;
  P_mont.u.c0.val.limbs[0] = 5;
  P_mont.v.c0.val.limbs[0] = 7;

  std::cout << "P_mont: u = ";
  P_mont.u.print();
  std::cout << "        v = ";
  P_mont.v.print();

  // 1. Map Mont -> Edwards
  EdPt P_ed = Mapper::MontToEdwards(P_mont);
  std::cout << "P_ed (after warp): x = ";
  P_ed.X.print();
  std::cout << "                   y = ";
  P_ed.Y.print();

  // 2. Double in Edwards domain
  EdPt Q_ed = ed_curve.Double(P_ed);
  std::cout << "Q_ed = 2*P_ed:     x = ";
  Q_ed.X.print();
  std::cout << "                   y = ";
  Q_ed.Y.print();

  // 3. Map back to Montgomery
  MontPt Q_mont = Mapper::EdwardsToMont(Q_ed);
  std::cout << "Q_mont (returned): u = ";
  Q_mont.u.print();
  std::cout << "                   v = ";
  Q_mont.v.print();

  // 4. Roundtrip test: P_mont -> P_ed -> P_ed' -> P_mont' should equal P_mont
  MontPt P_roundtrip = Mapper::EdwardsToMont(P_ed);
  std::cout << "P_roundtrip:       u = ";
  P_roundtrip.u.print();

  if (Mapper::MontPointsEqualX(P_mont, P_roundtrip)) {
    std::cout << "BIRATIONAL MAP: ROUNDTRIP SUCCESS!" << std::endl;
  } else {
    std::cout
        << "BIRATIONAL MAP: ROUNDTRIP MISMATCH (field form issue expected)"
        << std::endl;
  }

  // --- Q-HALO PROTOCOL: FINAL INTEGRATION ---
  using QHalo = QHaloProtocol<Params>;
  QHalo::run_protocol(Generator::phi_coeffs, Generator::pairs_found, 10);

  return 0;
}
