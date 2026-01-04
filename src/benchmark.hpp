#pragma once

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>


#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

namespace crypto {

// RDTSC-based cycle counter for accurate benchmarking
// This matches the methodology used by SQISign and other PQC implementations
class CycleCounter {
public:
  static inline uint64_t rdtsc() {
#ifdef _MSC_VER
    return __rdtsc();
#else
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#endif
  }

  static inline void cpuid_fence() {
#ifdef _MSC_VER
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
#else
    __asm__ __volatile__("cpuid" ::: "eax", "ebx", "ecx", "edx");
#endif
  }

  // Start measurement with serialization
  static inline uint64_t start() {
    cpuid_fence();
    return rdtsc();
  }

  // End measurement with serialization
  static inline uint64_t stop() {
    uint64_t cycles = rdtsc();
    cpuid_fence();
    return cycles;
  }
};

// Benchmark result structure
struct BenchmarkResult {
  std::string name;
  uint64_t min_cycles;
  uint64_t max_cycles;
  uint64_t median_cycles;
  double avg_cycles;
  double mcycles;    // Megacycles (cycles / 1,000,000)
  size_t size_bytes; // For signature size comparisons
};

// Run a benchmark N times and compute statistics
template <typename Func>
BenchmarkResult benchmark(const std::string &name, Func func,
                          int iterations = 100, size_t size = 0) {
  std::vector<uint64_t> samples;
  samples.reserve(iterations);

  // Warmup
  for (int i = 0; i < 10; ++i) {
    func();
  }

  // Actual measurements
  for (int i = 0; i < iterations; ++i) {
    uint64_t start = CycleCounter::start();
    func();
    uint64_t end = CycleCounter::stop();
    samples.push_back(end - start);
  }

  // Compute statistics
  std::sort(samples.begin(), samples.end());

  BenchmarkResult result;
  result.name = name;
  result.min_cycles = samples.front();
  result.max_cycles = samples.back();
  result.median_cycles = samples[iterations / 2];
  result.avg_cycles =
      std::accumulate(samples.begin(), samples.end(), 0.0) / iterations;
  result.mcycles = result.median_cycles / 1000000.0;
  result.size_bytes = size;

  return result;
}

// Print benchmark results in a formatted table
inline void print_benchmark_table(const std::vector<BenchmarkResult> &results) {
  std::cout << "\n" << std::string(80, '=') << "\n";
  std::cout << "                    BENCHMARK RESULTS (RDTSC Cycles)\n";
  std::cout << std::string(80, '=') << "\n";
  std::cout << std::left << std::setw(25) << "Operation" << std::right
            << std::setw(12) << "Median" << std::setw(12) << "Min"
            << std::setw(12) << "Max" << std::setw(10) << "Mcycles"
            << std::setw(10) << "Size"
            << "\n";
  std::cout << std::string(80, '-') << "\n";

  for (const auto &r : results) {
    std::cout << std::left << std::setw(25) << r.name << std::right
              << std::setw(12) << r.median_cycles << std::setw(12)
              << r.min_cycles << std::setw(12) << r.max_cycles << std::setw(10)
              << std::fixed << std::setprecision(3) << r.mcycles;
    if (r.size_bytes > 0) {
      std::cout << std::setw(10) << r.size_bytes;
    } else {
      std::cout << std::setw(10) << "-";
    }
    std::cout << "\n";
  }
  std::cout << std::string(80, '=') << "\n";
}

// Competition comparison table
inline void print_comparison_table() {
  std::cout << "\n" << std::string(80, '=') << "\n";
  std::cout << "                    COMPARISON: Q-HALO vs PQC SIGNATURES\n";
  std::cout << std::string(80, '=') << "\n";
  std::cout << std::left << std::setw(15) << "Scheme" << std::right
            << std::setw(15) << "Sign (Mcyc)" << std::setw(15)
            << "Verify (Mcyc)" << std::setw(15) << "Size (bytes)"
            << std::setw(20) << "Notes"
            << "\n";
  std::cout << std::string(80, '-') << "\n";

  // Published benchmarks (from papers/NIST submissions)
  std::cout << std::left << std::setw(15) << "Dilithium-2" << std::right
            << std::setw(15) << "0.89" << std::setw(15) << "0.29"
            << std::setw(15) << "2420" << std::setw(20) << "NIST Winner"
            << "\n";

  std::cout << std::left << std::setw(15) << "Falcon-512" << std::right
            << std::setw(15) << "8.6" << std::setw(15) << "0.08"
            << std::setw(15) << "666" << std::setw(20) << "NIST Winner"
            << "\n";

  std::cout << std::left << std::setw(15) << "SQISign-I" << std::right
            << std::setw(15) << "~3000" << std::setw(15) << "~50"
            << std::setw(15) << "177" << std::setw(20) << "Isogeny-based"
            << "\n";

  std::cout << std::left << std::setw(15) << "SQISign-II" << std::right
            << std::setw(15) << "~6000" << std::setw(15) << "~100"
            << std::setw(15) << "263" << std::setw(20) << "Isogeny-based"
            << "\n";

  std::cout << std::string(80, '-') << "\n";
  std::cout
      << "(Mcyc = Megacycles on Intel Haswell/Skylake, lower is better)\n";
  std::cout << std::string(80, '=') << "\n";
}

} // namespace crypto
