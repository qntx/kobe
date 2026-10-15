#pragma once

#include "HybridV1ProbeSpec.hpp"

namespace margelo::nitro::v1probe {

class HybridV1Probe final : public HybridV1ProbeSpec {
 public:
  HybridV1Probe() : HybridObject(TAG) {}

  std::shared_ptr<Promise<std::string>> run(
      const std::string& probe,
      const std::string& mode) override;

  void emit(const std::string& line) override;
};

} // namespace margelo::nitro::v1probe
