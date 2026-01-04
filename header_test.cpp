#include "src/curve.hpp"
#include "src/folding.hpp"
#include "src/fp.hpp"
#include "src/fp2.hpp"
#include "src/isogeny.hpp"
#include "src/params.hpp"
#include <iostream>


using namespace crypto;

struct Diag {
  Diag() { std::cerr << "Global Init Headers" << std::endl; }
};
Diag d;

int main() {
  std::cerr << "Main Headers" << std::endl;
  return 0;
}
