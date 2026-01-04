#pragma once

#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <array>
#include <iostream>
#include <iomanip>
#include <intrin.h> // For _addcarry_u64, _subborrow_u64 on Windows

namespace crypto {

    // Force inline for critical functions
    #define FORCE_INLINE __forceinline

    using Word = uint64_t;
    constexpr size_t WORD_BITS = 64;
    constexpr size_t WORD_BYTES = 8;

} // namespace crypto
