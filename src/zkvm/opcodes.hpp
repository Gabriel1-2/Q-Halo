#pragma once

#include <cstdint>
#include <string>

namespace crypto {
namespace zkvm {

// =============================================================================
// TinyVM Instruction Set
// =============================================================================
// A minimal but complete instruction set for demonstrating zkVM capabilities.
//
// Design goals:
// - Simple enough to implement ZK proofs for each instruction
// - Rich enough to express real computations (loops, conditionals, arithmetic)
// - Memory-safe with bounds checking
// =============================================================================

enum class Opcode : uint8_t {
  // Arithmetic
  ADD = 0x01, // ADD  rd, rs1, rs2   ; rd = rs1 + rs2
  SUB = 0x02, // SUB  rd, rs1, rs2   ; rd = rs1 - rs2
  MUL = 0x03, // MUL  rd, rs1, rs2   ; rd = rs1 * rs2
  DIV = 0x04, // DIV  rd, rs1, rs2   ; rd = rs1 / rs2
  MOD = 0x05, // MOD  rd, rs1, rs2   ; rd = rs1 % rs2

  // Bitwise
  AND = 0x10, // AND  rd, rs1, rs2   ; rd = rs1 & rs2
  OR = 0x11,  // OR   rd, rs1, rs2   ; rd = rs1 | rs2
  XOR = 0x12, // XOR  rd, rs1, rs2   ; rd = rs1 ^ rs2
  SHL = 0x13, // SHL  rd, rs1, rs2   ; rd = rs1 << rs2
  SHR = 0x14, // SHR  rd, rs1, rs2   ; rd = rs1 >> rs2

  // Memory
  LOAD = 0x20,  // LOAD rd, [addr]     ; rd = mem[addr]
  STORE = 0x21, // STORE [addr], rs    ; mem[addr] = rs
  LOADI = 0x22, // LOADI rd, imm       ; rd = immediate value

  // Control Flow
  JMP = 0x30,  // JMP  offset         ; pc += offset
  JZ = 0x31,   // JZ   rs, offset     ; if rs==0, pc += offset
  JNZ = 0x32,  // JNZ  rs, offset     ; if rs!=0, pc += offset
  CALL = 0x33, // CALL offset         ; push pc, jump to offset
  RET = 0x34,  // RET                 ; pop pc, return

  // Comparison
  EQ = 0x40, // EQ   rd, rs1, rs2   ; rd = (rs1 == rs2) ? 1 : 0
  LT = 0x41, // LT   rd, rs1, rs2   ; rd = (rs1 < rs2) ? 1 : 0
  GT = 0x42, // GT   rd, rs1, rs2   ; rd = (rs1 > rs2) ? 1 : 0

  // System
  HALT = 0xFF, // HALT                ; stop execution
  NOP = 0x00,  // NOP                 ; do nothing
};

// Instruction encoding: 32-bit fixed width
// [opcode:8][rd:8][rs1:8][rs2_or_imm:8]
struct Instruction {
  Opcode opcode;
  uint8_t rd;  // Destination register (0-7)
  uint8_t rs1; // Source register 1
  uint8_t rs2; // Source register 2 OR immediate value

  Instruction() : opcode(Opcode::NOP), rd(0), rs1(0), rs2(0) {}

  Instruction(Opcode op, uint8_t d, uint8_t s1, uint8_t s2)
      : opcode(op), rd(d), rs1(s1), rs2(s2) {}

  // Convenience constructors
  static Instruction Add(uint8_t rd, uint8_t rs1, uint8_t rs2) {
    return Instruction(Opcode::ADD, rd, rs1, rs2);
  }

  static Instruction Sub(uint8_t rd, uint8_t rs1, uint8_t rs2) {
    return Instruction(Opcode::SUB, rd, rs1, rs2);
  }

  static Instruction Mul(uint8_t rd, uint8_t rs1, uint8_t rs2) {
    return Instruction(Opcode::MUL, rd, rs1, rs2);
  }

  static Instruction LoadI(uint8_t rd, uint8_t imm) {
    return Instruction(Opcode::LOADI, rd, imm, 0);
  }

  static Instruction Load(uint8_t rd, uint8_t addr_reg) {
    return Instruction(Opcode::LOAD, rd, addr_reg, 0);
  }

  static Instruction Store(uint8_t addr_reg, uint8_t rs) {
    return Instruction(Opcode::STORE, 0, addr_reg, rs);
  }

  static Instruction Jz(uint8_t rs, int8_t offset) {
    return Instruction(Opcode::JZ, (uint8_t)offset, rs, 0);
  }

  static Instruction Jnz(uint8_t rs, int8_t offset) {
    return Instruction(Opcode::JNZ, (uint8_t)offset, rs, 0);
  }

  static Instruction Jmp(int8_t offset) {
    return Instruction(Opcode::JMP, (uint8_t)offset, 0, 0);
  }

  static Instruction Lt(uint8_t rd, uint8_t rs1, uint8_t rs2) {
    return Instruction(Opcode::LT, rd, rs1, rs2);
  }

  static Instruction Eq(uint8_t rd, uint8_t rs1, uint8_t rs2) {
    return Instruction(Opcode::EQ, rd, rs1, rs2);
  }

  static Instruction Gt(uint8_t rd, uint8_t rs1, uint8_t rs2) {
    return Instruction(Opcode::GT, rd, rs1, rs2);
  }

  static Instruction Halt() { return Instruction(Opcode::HALT, 0, 0, 0); }

  // Get string representation
  std::string to_string() const {
    switch (opcode) {
    case Opcode::ADD:
      return "ADD r" + std::to_string(rd) + ", r" + std::to_string(rs1) +
             ", r" + std::to_string(rs2);
    case Opcode::SUB:
      return "SUB r" + std::to_string(rd) + ", r" + std::to_string(rs1) +
             ", r" + std::to_string(rs2);
    case Opcode::MUL:
      return "MUL r" + std::to_string(rd) + ", r" + std::to_string(rs1) +
             ", r" + std::to_string(rs2);
    case Opcode::LOADI:
      return "LOADI r" + std::to_string(rd) + ", " + std::to_string(rs1);
    case Opcode::LOAD:
      return "LOAD r" + std::to_string(rd) + ", [r" + std::to_string(rs1) + "]";
    case Opcode::STORE:
      return "STORE [r" + std::to_string(rs1) + "], r" + std::to_string(rs2);
    case Opcode::JZ:
      return "JZ r" + std::to_string(rs1) + ", " + std::to_string((int8_t)rd);
    case Opcode::JNZ:
      return "JNZ r" + std::to_string(rs1) + ", " + std::to_string((int8_t)rd);
    case Opcode::JMP:
      return "JMP " + std::to_string((int8_t)rd);
    case Opcode::LT:
      return "LT r" + std::to_string(rd) + ", r" + std::to_string(rs1) + ", r" +
             std::to_string(rs2);
    case Opcode::EQ:
      return "EQ r" + std::to_string(rd) + ", r" + std::to_string(rs1) + ", r" +
             std::to_string(rs2);
    case Opcode::HALT:
      return "HALT";
    case Opcode::NOP:
      return "NOP";
    default:
      return "UNKNOWN";
    }
  }
};

} // namespace zkvm
} // namespace crypto
