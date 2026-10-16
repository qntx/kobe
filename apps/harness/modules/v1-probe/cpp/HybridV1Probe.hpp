#pragma once

#include "HybridV1ProbeSpec.hpp"

#include <memory>
#include <mutex>

namespace margelo::nitro::v1probe {

struct KernelSession;

class HybridV1Probe final : public HybridV1ProbeSpec {
 public:
  HybridV1Probe() : HybridObject(TAG) {}
  ~HybridV1Probe() override {
    closeKernel();
  }

  std::shared_ptr<Promise<std::string>> run(
      const std::string& probe,
      const std::string& mode) override;

  std::shared_ptr<Promise<void>> openKernel(
      const std::string& probe,
      const std::string& mode) override;

  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> send(
      const std::shared_ptr<ArrayBuffer>& message) override;

  void closeKernel() override;

  void report(
      const std::string& probe,
      const std::string& mode,
      bool ok,
      const std::string& payload) override;

 private:
  // The single open kernel session (openKernel/send/closeKernel). Guards
  // session_ itself; KernelSession's own mutex guards its contents.
  std::mutex sessionMutex_;
  std::shared_ptr<KernelSession> session_;
};

} // namespace margelo::nitro::v1probe
