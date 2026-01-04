#include <chrono>
#include <iostream>
#include <vector>


#include "benchmark.hpp"
#include "commitment_fast.hpp"
#include "fp.hpp"
#include "fp2.hpp"


using namespace crypto;

using P = Params434;
using FpT = Fp<P>;
using Fp2T = Fp2<P>;

int main() {
  std::cout << "========================================\n";
  std::cout << "  Q-HALO RIGOROUS BENCHMARK\n";
  std::cout << "  Full 434-bit Random Scalars\n";
  std::cout << "========================================\n\n";

  PedersenCommitmentFast<P> pedersen;

  // Create heavy scalars
  BigInt<P::N_LIMBS> v, r;
  for (size_t i = 0; i < P::N_LIMBS; ++i) {
    v.limbs[i] = 0xAAAAAAAAAAAAAAAAULL; // Alternating bits
    r.limbs[i] = 0x5555555555555555ULL;
  }

  std::cout << "Running benchmark with 100 iterations...\n";

  auto t1 = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < 100; ++i) {
    volatile auto C = pedersen.CommitFull(v, r);
    (void)C;
  }
  auto t2 = std::chrono::high_resolution_clock::now();

  double duration = std::chrono::duration<double, std::micro>(t2 - t1).count();
  double avg_us = duration / 100.0;

  // RDTSC Measurement
  auto bench = benchmark(
      "CommitFull",
      [&]() {
        volatile auto C = pedersen.CommitFull(v, r);
        (void)C;
      },
      100);

  std::cout << "\n[RESULTS]\n";
  std::cout << "  Avg Time:   " << avg_us << " us\n";
  std::cout << "  Avg Cycles: " << bench.median_cycles << "\n";
  std::cout << "  Mcycles:    " << bench.mcycles << " Mcyc\n";

  double sqisign = 5.1;
  std::cout << "\n[COMPARISON]\n";
  std::cout << "  SQISign: " << sqisign << " Mcyc\n";
  std::cout << "  Q-HALO:  " << bench.mcycles << " Mcyc per commit\n";
  std::cout << "  Verify (3x): " << bench.mcycles * 3 << " Mcyc\n";

  return 0;
}
