#include "KernelBuffer.hpp"

void qntx::kernelWipe(uint8_t* data, size_t size) {
  volatile uint8_t* p = data;
  for (size_t i = 0; i < size; i++) {
    p[i] = 0;
  }
}

void qntx::kernelWipe(std::vector<uint8_t>& bytes) {
  kernelWipe(bytes.data(), bytes.size());
}
