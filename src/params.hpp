#pragma once

#include "bigint.hpp"

namespace crypto {

// SIKEp434 parameters
// p = 2^216 * 3^137 - 1
// 434 bits -> 7 words of 64 bits (448 bits)

struct Params434 {
  static constexpr size_t N_LIMBS = 7;

  // Prime p = 2^216 * 3^137 - 1
  // Hex:
  // 0x2341f271773446cfc5fd681c520567bc65c783158aea3fdc1767ae2ffffffffffffffffffffffffffffffffffffffffffffffffffffff
  static constexpr BigInt<N_LIMBS> p() {
    BigInt<N_LIMBS> p_val;
    // Little-endian 64-bit limbs
    p_val.limbs[0] = 0xFFFFFFFFFFFFFFFFULL;
    p_val.limbs[1] = 0xFFFFFFFFFFFFFFFFULL;
    p_val.limbs[2] = 0xFFFFFFFFFFFFFFFFULL;
    p_val.limbs[3] = 0xFDC1767AE2FFFFFFULL;
    p_val.limbs[4] = 0x7BC65C783158AEA3ULL;
    p_val.limbs[5] = 0x6CFC5FD681C52056ULL;
    p_val.limbs[6] = 0x0002341F27177344ULL;
    return p_val;
  }

  // Precomputed R^2 mod p where R = 2^448
  // Computed via Python: R2 = (2^448)^2 mod p
  static constexpr BigInt<N_LIMBS> R2() {
    BigInt<N_LIMBS> r;
    r.limbs[0] = 0x28E55B65DCD69B30ULL;
    r.limbs[1] = 0xACEC7367768798C2ULL;
    r.limbs[2] = 0xAB27973F8311688DULL;
    r.limbs[3] = 0x175CC6AF8D6C7C0BULL;
    r.limbs[4] = 0xABCD92BF2DDE347EULL;
    r.limbs[5] = 0x69E16A61C7686D9AULL;
    r.limbs[6] = 0x000025A89BCDD12AULL;
    return r;
  }

  // Montgomery constant mu = -p^-1 mod 2^64
  static constexpr uint64_t mu() {
    // calculated from p[0]
    // p[0] = 0xFFFFFFFFFFFFFFFF = -1 mod 2^64
    // p^-1 = -1
    // -p^-1 = 1
    return 1ULL;
    // Wait, if p = -1 mod 2^64, then p*(-1) = 1 mod 2^64. So p^-1 = -1.
    // mu = -(-1) = 1.
    // This is correct for p ending in all Fs.
  }
};

} // namespace crypto
