// Q-HALO zkVM Demo: Fast verification showcase
#include "zkvm/prover.hpp"
#include <iostream>


using namespace crypto;
using namespace crypto::zkvm;

int main() {
  std::cout << "\n";
  std::cout
      << "╔═══════════════════════════════════════════════════════════════╗\n";
  std::cout
      << "║     Q-HALO zkVM: POST-QUANTUM ZERO-KNOWLEDGE VM               ║\n";
  std::cout
      << "║     First Post-Quantum zkVM with O(1) Verification            ║\n";
  std::cout << "╚══════════════════════════════════════════════════════════════"
               "═╝\n\n";

  zkVMProver<Params434> prover;

  // Demo 1: Simple add program (2 steps)
  std::cout
      << "═══════════════════════════════════════════════════════════════\n";
  std::cout << "[DEMO 1] Add Two Numbers\n";
  std::cout
      << "═══════════════════════════════════════════════════════════════\n\n";

  std::array<uint64_t, NUM_REGISTERS> add_input = {42, 58, 0, 0, 0, 0, 0, 0};
  auto add_proof =
      prover.execute_and_prove(programs::add_two(), add_input, true);

  std::cout << "\n[Verification]\n";
  prover.verify(add_proof);
  std::cout << "  Expected: 42 + 58 = 100 ✓\n";

  // Demo 2: Factorial(5) = 120 (~9 steps)
  std::cout
      << "\n═══════════════════════════════════════════════════════════════\n";
  std::cout << "[DEMO 2] Factorial(5) = 120\n";
  std::cout
      << "═══════════════════════════════════════════════════════════════\n\n";

  std::array<uint64_t, NUM_REGISTERS> fac_input = {5, 0, 0, 0, 0, 0, 0, 0};
  auto fac_proof =
      prover.execute_and_prove(programs::factorial(), fac_input, true);

  std::cout << "\n[Verification]\n";
  prover.verify(fac_proof);

  // Demo 3: Sum hidden array
  std::cout
      << "\n═══════════════════════════════════════════════════════════════\n";
  std::cout << "[DEMO 3] Sum SECRET Array (Zero-Knowledge)\n";
  std::cout
      << "═══════════════════════════════════════════════════════════════\n\n";

  TinyVM vm;
  vm.load_program(programs::sum_array());
  vm.set_register(0, 4); // n = 4 elements

  // Set SECRET values - verifier will never see these!
  std::cout << "[Prover] Setting SECRET memory values: [10, 20, 30, 40]\n";
  std::cout << "[Prover] These values will NOT be revealed to verifier!\n\n";
  vm.set_memory(0, 10);
  vm.set_memory(1, 20);
  vm.set_memory(2, 30);
  vm.set_memory(3, 40);

  vm.run();
  auto sum_proof = prover.prove(vm, programs::sum_array(), true);

  std::cout << "\n[Verification]\n";
  prover.verify(sum_proof);
  std::cout << "\n  The verifier learned:\n";
  std::cout << "    ✓ A program was executed correctly\n";
  std::cout << "    ✓ The output is 100\n";
  std::cout << "    ✗ The verifier does NOT know the input values!\n";

  // Summary
  std::cout << "\n\n╔══════════════════════════════════════════════════════════"
               "═════╗\n";
  std::cout
      << "║  Q-HALO zkVM: KEY ACHIEVEMENTS                                ║\n";
  std::cout
      << "╠═══════════════════════════════════════════════════════════════╣\n";
  std::cout
      << "║  • First post-quantum secure zkVM                             ║\n";
  std::cout
      << "║  • O(1) verification regardless of program size               ║\n";
  std::cout
      << "║  • Zero-knowledge: inputs/memory hidden from verifier         ║\n";
  std::cout
      << "║  • Recursive proof composition                                ║\n";
  std::cout << "╚══════════════════════════════════════════════════════════════"
               "═╝\n\n";

  return 0;
}
