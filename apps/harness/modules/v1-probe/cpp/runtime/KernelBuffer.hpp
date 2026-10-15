#pragma once

#include <jsi/jsi.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace qntx {

namespace jsi = facebook::jsi;

// Read-only buffer over script bytes retained by shared_ptr; used for embedded
// bytecode, which Hermes may read lazily for the runtime's lifetime.
class VectorBuffer final : public jsi::Buffer {
 public:
  explicit VectorBuffer(std::shared_ptr<const std::vector<uint8_t>> bytes)
      : bytes_(std::move(bytes)) {}
  size_t size() const override {
    return bytes_->size();
  }
  const uint8_t* data() const override {
    return bytes_->data();
  }

 private:
  std::shared_ptr<const std::vector<uint8_t>> bytes_;
};

// Owning MutableBuffer; the runtime shares ownership of the byte storage.
class OwningBuffer final : public jsi::MutableBuffer {
 public:
  explicit OwningBuffer(std::vector<uint8_t> storage) : storage_(std::move(storage)) {}
  explicit OwningBuffer(size_t size) : storage_(size) {}
  size_t size() const override {
    return storage_.size();
  }
  uint8_t* data() override {
    return storage_.data();
  }

 private:
  std::vector<uint8_t> storage_;
};

} // namespace qntx
