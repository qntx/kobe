#pragma once

#include <jsi/jsi.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace qntx {

namespace jsi = facebook::jsi;

// Zeroes secret bytes without letting the optimizer elide the store.
void kernelWipe(uint8_t* data, size_t size);
void kernelWipe(std::vector<uint8_t>& bytes);

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

// Byte storage that always wipes itself on destruction. Move-only: a moved-from
// instance carries no bytes, so each live copy has exactly one wiper. Used for
// KDF inputs and outputs, where a dropped result must not linger in memory.
class SecretBytes {
 public:
  SecretBytes() = default;
  explicit SecretBytes(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}
  explicit SecretBytes(size_t size) : bytes_(size) {}
  SecretBytes(const uint8_t* data, size_t size) : bytes_(data, data + size) {}

  SecretBytes(const SecretBytes&) = delete;
  SecretBytes& operator=(const SecretBytes&) = delete;

  SecretBytes(SecretBytes&& other) noexcept = default;
  SecretBytes& operator=(SecretBytes&& other) noexcept {
    if (this != &other) {
      kernelWipe(bytes_);
      bytes_ = std::move(other.bytes_);
    }
    return *this;
  }

  ~SecretBytes() {
    kernelWipe(bytes_);
  }

  const uint8_t* data() const {
    return bytes_.data();
  }
  uint8_t* data() {
    return bytes_.data();
  }
  size_t size() const {
    return bytes_.size();
  }

 private:
  std::vector<uint8_t> bytes_;
};

// Owning MutableBuffer; the runtime shares ownership of the byte storage and
// the bytes are wiped when the last reference goes away, because these buffers
// back ArrayBuffers that can hold secrets.
class OwningBuffer final : public jsi::MutableBuffer {
 public:
  explicit OwningBuffer(std::vector<uint8_t> storage) : storage_(std::move(storage)) {}
  explicit OwningBuffer(size_t size) : storage_(size) {}
  ~OwningBuffer() override {
    kernelWipe(storage_);
  }
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
