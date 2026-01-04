#pragma once

#include "opcodes.hpp"
#include <array>
#include <iomanip>
#include <iostream>
#include <vector>


namespace crypto {
namespace zkvm {

// =============================================================================
// TinyVM: A Minimal Virtual Machine for Zero-Knowledge Proofs
// =============================================================================
// Features:
// - 8 general-purpose 64-bit registers (r0-r7)
// - 256 memory cells (64-bit each)
// - Execution trace recording for ZK proof generation
// - Deterministic execution (same inputs → same trace)
// =============================================================================

constexpr size_t NUM_REGISTERS = 8;
constexpr size_t MEMORY_SIZE = 256;
constexpr size_t MAX_STEPS = 10000;

// Execution state snapshot (for proof generation)
struct VMState {
  uint64_t pc;                              // Program counter
  std::array<uint64_t, NUM_REGISTERS> regs; // Registers
  uint64_t memory_hash;                     // Hash of memory state

  VMState() : pc(0), memory_hash(0) { regs.fill(0); }

  bool operator==(const VMState &other) const {
    return pc == other.pc && regs == other.regs;
  }
};

// Single execution step (witness for ZK proof)
struct ExecutionStep {
  VMState before;
  Instruction instr;
  VMState after;

  // Memory access (if any)
  bool has_mem_read = false;
  bool has_mem_write = false;
  uint64_t mem_addr = 0;
  uint64_t mem_value = 0;
};

// The Virtual Machine
class TinyVM {
private:
  std::array<uint64_t, NUM_REGISTERS> registers;
  std::array<uint64_t, MEMORY_SIZE> memory;
  std::vector<Instruction> program;
  uint64_t pc;
  bool halted;

  // Execution trace (for ZK proof generation)
  std::vector<ExecutionStep> trace;

public:
  TinyVM() : pc(0), halted(false) {
    registers.fill(0);
    memory.fill(0);
  }

  // Load a program
  void load_program(const std::vector<Instruction> &prog) {
    program = prog;
    pc = 0;
    halted = false;
    trace.clear();
  }

  // Set initial register values
  void set_register(uint8_t reg, uint64_t value) {
    if (reg < NUM_REGISTERS) {
      registers[reg] = value;
    }
  }

  // Set initial memory values
  void set_memory(uint8_t addr, uint64_t value) {
    if (addr < MEMORY_SIZE) {
      memory[addr] = value;
    }
  }

  // Get register value
  uint64_t get_register(uint8_t reg) const {
    return (reg < NUM_REGISTERS) ? registers[reg] : 0;
  }

  // Get memory value
  uint64_t get_memory(uint8_t addr) const {
    return (addr < MEMORY_SIZE) ? memory[addr] : 0;
  }

  // Get current state snapshot
  VMState get_state() const {
    VMState s;
    s.pc = pc;
    s.regs = registers;
    // Simple memory hash for now
    s.memory_hash = 0;
    for (size_t i = 0; i < MEMORY_SIZE; ++i) {
      s.memory_hash ^= memory[i] * (i + 1);
    }
    return s;
  }

  // Execute single instruction
  bool step() {
    if (halted || pc >= program.size()) {
      return false;
    }

    ExecutionStep step_record;
    step_record.before = get_state();
    step_record.instr = program[pc];

    const Instruction &instr = program[pc];
    bool jumped = false;

    switch (instr.opcode) {
    case Opcode::ADD:
      registers[instr.rd] = registers[instr.rs1] + registers[instr.rs2];
      break;

    case Opcode::SUB:
      registers[instr.rd] = registers[instr.rs1] - registers[instr.rs2];
      break;

    case Opcode::MUL:
      registers[instr.rd] = registers[instr.rs1] * registers[instr.rs2];
      break;

    case Opcode::DIV:
      if (registers[instr.rs2] != 0) {
        registers[instr.rd] = registers[instr.rs1] / registers[instr.rs2];
      }
      break;

    case Opcode::MOD:
      if (registers[instr.rs2] != 0) {
        registers[instr.rd] = registers[instr.rs1] % registers[instr.rs2];
      }
      break;

    case Opcode::AND:
      registers[instr.rd] = registers[instr.rs1] & registers[instr.rs2];
      break;

    case Opcode::OR:
      registers[instr.rd] = registers[instr.rs1] | registers[instr.rs2];
      break;

    case Opcode::XOR:
      registers[instr.rd] = registers[instr.rs1] ^ registers[instr.rs2];
      break;

    case Opcode::SHL:
      registers[instr.rd] = registers[instr.rs1] << (registers[instr.rs2] & 63);
      break;

    case Opcode::SHR:
      registers[instr.rd] = registers[instr.rs1] >> (registers[instr.rs2] & 63);
      break;

    case Opcode::LOAD: {
      uint8_t addr = registers[instr.rs1] % MEMORY_SIZE;
      registers[instr.rd] = memory[addr];
      step_record.has_mem_read = true;
      step_record.mem_addr = addr;
      step_record.mem_value = memory[addr];
      break;
    }

    case Opcode::STORE: {
      uint8_t addr = registers[instr.rs1] % MEMORY_SIZE;
      memory[addr] = registers[instr.rs2];
      step_record.has_mem_write = true;
      step_record.mem_addr = addr;
      step_record.mem_value = registers[instr.rs2];
      break;
    }

    case Opcode::LOADI:
      registers[instr.rd] = instr.rs1;
      break;

    case Opcode::JMP:
      pc = (pc + (int8_t)instr.rd) % program.size();
      jumped = true;
      break;

    case Opcode::JZ:
      if (registers[instr.rs1] == 0) {
        pc = (pc + (int8_t)instr.rd) % program.size();
        jumped = true;
      }
      break;

    case Opcode::JNZ:
      if (registers[instr.rs1] != 0) {
        pc = (pc + (int8_t)instr.rd) % program.size();
        jumped = true;
      }
      break;

    case Opcode::EQ:
      registers[instr.rd] =
          (registers[instr.rs1] == registers[instr.rs2]) ? 1 : 0;
      break;

    case Opcode::LT:
      registers[instr.rd] =
          (registers[instr.rs1] < registers[instr.rs2]) ? 1 : 0;
      break;

    case Opcode::GT:
      registers[instr.rd] =
          (registers[instr.rs1] > registers[instr.rs2]) ? 1 : 0;
      break;

    case Opcode::HALT:
      halted = true;
      break;

    case Opcode::NOP:
    default:
      break;
    }

    if (!jumped) {
      pc++;
    }

    step_record.after = get_state();
    trace.push_back(step_record);

    return !halted;
  }

  // Run until halt or max steps
  size_t run(size_t max_steps = MAX_STEPS) {
    size_t steps = 0;
    while (step() && steps < max_steps) {
      steps++;
    }
    return steps;
  }

  // Get execution trace (for ZK proof generation)
  const std::vector<ExecutionStep> &get_trace() const { return trace; }

  // Print execution trace
  void print_trace() const {
    std::cout << "=== Execution Trace (" << trace.size() << " steps) ===\n";
    for (size_t i = 0; i < trace.size(); ++i) {
      const auto &s = trace[i];
      std::cout << std::setw(4) << i << ": " << s.instr.to_string();

      // Show register changes
      for (size_t r = 0; r < NUM_REGISTERS; ++r) {
        if (s.before.regs[r] != s.after.regs[r]) {
          std::cout << "  [r" << r << ": " << s.before.regs[r] << " -> "
                    << s.after.regs[r] << "]";
        }
      }
      std::cout << "\n";
    }
  }

  // Print current state
  void print_state() const {
    std::cout << "PC: " << pc << (halted ? " (HALTED)" : "") << "\n";
    std::cout << "Registers:";
    for (size_t i = 0; i < NUM_REGISTERS; ++i) {
      std::cout << " r" << i << "=" << registers[i];
    }
    std::cout << "\n";
  }

  bool is_halted() const { return halted; }
  size_t get_pc() const { return pc; }
};

// =============================================================================
// Demo Programs
// =============================================================================

namespace programs {

// Fibonacci: Compute fib(n) where n is in r0, result in r1
inline std::vector<Instruction> fibonacci() {
  return {
      // r0 = n (input)
      // r1 = fib(n-1), r2 = fib(n-2), r3 = temp, r4 = counter
      Instruction::LoadI(1, 0), // r1 = 0 (fib(0))
      Instruction::LoadI(2, 1), // r2 = 1 (fib(1))
      Instruction::LoadI(4, 0), // r4 = 0 (counter)

      // Loop start (pc=3)
      Instruction::Lt(5, 4, 0), // r5 = (counter < n) ? 1 : 0
      Instruction::Jz(5, 6),    // if r5==0, exit loop (jump +6)

      Instruction::Add(3, 1, 2),         // r3 = r1 + r2
      Instruction::Add(1, 2, 0),         // r1 = r2 (shift: remove "+ 0" hack)
      Instruction(Opcode::ADD, 1, 2, 2), // r1 = r2
      Instruction::Add(2, 3, 0),         // r2 = r3
      Instruction(Opcode::ADD, 2, 3, 3), // r2 = r3
      Instruction::LoadI(6, 1),          // r6 = 1
      Instruction::Add(4, 4, 6),         // counter++
      Instruction::Jmp(-9),              // jump back to loop start

      // End (pc=13)
      Instruction::Halt(),
  };
}

// Simple: Just add two numbers
inline std::vector<Instruction> add_two() {
  return {
      // r0 = a, r1 = b, result in r2
      Instruction::Add(2, 0, 1), // r2 = r0 + r1
      Instruction::Halt(),
  };
}

// Factorial: Compute n! where n is in r0, result in r1
inline std::vector<Instruction> factorial() {
  return {
      // r0 = n (input)
      // r1 = result, r2 = counter, r5 = const 1, r6 = comparison
      Instruction::LoadI(1, 1), // r1 = 1 (result)
      Instruction::LoadI(2, 1), // r2 = 1 (counter)
      Instruction::LoadI(5, 1), // r5 = 1 (constant)

      // Loop (pc=3)
      Instruction::Gt(6, 2, 0), // r6 = (counter > n) ? 1 : 0
      Instruction::Jnz(6, 5),   // if r6!=0, exit loop (jump +5)

      Instruction::Mul(1, 1, 2), // result *= counter
      Instruction::Add(2, 2, 5), // counter++
      Instruction::Jmp(-5),      // back to loop

      // End (pc=8)
      Instruction::Halt(),
  };
}

// Sum array: Sum values in memory[0..n-1], n in r0, result in r1
inline std::vector<Instruction> sum_array() {
  return {
      // r0 = n, r1 = sum, r2 = index, r3 = temp, r5 = const 1
      Instruction::LoadI(1, 0), // r1 = 0 (sum)
      Instruction::LoadI(2, 0), // r2 = 0 (index)
      Instruction::LoadI(5, 1), // r5 = 1

      // Loop (pc=3)
      Instruction::Lt(6, 2, 0), // r6 = (index < n) ? 1 : 0
      Instruction::Jz(6, 5),    // if r6==0, exit

      Instruction::Load(3, 2),   // r3 = mem[r2]
      Instruction::Add(1, 1, 3), // sum += r3
      Instruction::Add(2, 2, 5), // index++
      Instruction::Jmp(-6),      // back to loop

      // End (pc=9)
      Instruction::Halt(),
  };
}

} // namespace programs

} // namespace zkvm
} // namespace crypto
