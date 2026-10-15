#include "HybridV1Probe.hpp"

#include <NitroModules/InstallNitro.hpp>

#include "runtime/KernelRuntime.hpp"

#if __has_include("generated/probes.hpp")
#include "generated/probes.hpp"
#else
#error "generated/probes.hpp missing — run `bun run harness:bundles` at the repo root first"
#endif

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach.h>
#elif defined(__ANDROID__)
#include <android/log.h>
#include <unistd.h>
#endif

namespace margelo::nitro::v1probe {

namespace {

using Clock = std::chrono::steady_clock;

::hermes::vm::RuntimeConfig defaultConfig() {
  return ::hermes::vm::RuntimeConfig::Builder()
      .withMicrotaskQueue(true)
      .withEnableEval(false)
      .build();
}

// Mailbox between a KernelRuntime's hooks and the probe orchestrator thread.
struct Channel {
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<std::vector<uint8_t>> inbox;
  std::optional<std::string> error;

  void push(std::vector<uint8_t> bytes) {
    {
      std::lock_guard<std::mutex> lock(mutex);
      inbox.push_back(std::move(bytes));
    }
    cv.notify_all();
  }
  void fail(std::string message) {
    {
      std::lock_guard<std::mutex> lock(mutex);
      error = std::move(message);
    }
    cv.notify_all();
  }
  std::vector<uint8_t> take(Clock::time_point deadline) {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait_until(lock, deadline, [&] { return !inbox.empty() || error.has_value(); });
    if (!inbox.empty()) {
      auto bytes = std::move(inbox.front());
      inbox.pop_front();
      return bytes;
    }
    if (error.has_value()) {
      throw std::runtime_error(*error);
    }
    throw std::runtime_error("probe timed out waiting for kernel post");
  }
  std::string takeError(Clock::time_point deadline) {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait_until(lock, deadline, [&] { return error.has_value() || !inbox.empty(); });
    if (error.has_value()) {
      return *error;
    }
    if (!inbox.empty()) {
      throw std::runtime_error(
          "kernel posted instead of failing: " +
          std::string(inbox.front().begin(), inbox.front().end()));
    }
    throw std::runtime_error("probe timed out waiting for kernel failure");
  }
};

std::shared_ptr<qntx::KernelRuntime> startKernel(
    const ::hermes::vm::RuntimeConfig& config,
    const uint8_t* source,
    size_t sourceSize,
    const uint8_t* bytecode,
    size_t bytecodeSize,
    bool useBytecode,
    const std::shared_ptr<Channel>& channel,
    bool installNitro = false) {
  qntx::KernelScript script{
      useBytecode ? qntx::KernelScript::Kind::bytecode : qntx::KernelScript::Kind::source,
      useBytecode
          ? std::make_shared<const std::vector<uint8_t>>(bytecode, bytecode + bytecodeSize)
          : std::make_shared<const std::vector<uint8_t>>(source, source + sourceSize)};
  qntx::KernelRuntime::Hooks hooks;
  if (installNitro) {
    // Sync-only install: no Dispatcher, so Nitro exposes synchronous methods only.
    hooks.beforeEvaluate = [](facebook::jsi::Runtime& runtime) {
      margelo::nitro::install(runtime);
    };
  }
  hooks.onPost = [channel](std::vector<uint8_t> bytes) { channel->push(std::move(bytes)); };
  hooks.onError = [channel](std::string message) { channel->fail(std::move(message)); };
  return qntx::KernelRuntime::start(config, std::move(script), std::move(hooks));
}

std::string toString(const std::vector<uint8_t>& bytes) {
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

Clock::time_point deadlineAfter(std::chrono::milliseconds ms) {
  return Clock::now() + ms;
}

double percentile(std::vector<double> values, double p) {
  std::sort(values.begin(), values.end());
  if (values.empty()) {
    return 0;
  }
  const auto index = static_cast<size_t>(std::ceil(p / 100.0 * values.size())) - 1;
  return values[std::min(index, values.size() - 1)];
}

double residentBytes() {
#if defined(__APPLE__)
  task_basic_info_64 info;
  mach_msg_type_number_t count = TASK_BASIC_INFO_64_COUNT;
  if (task_info(
          mach_task_self(),
          TASK_BASIC_INFO_64,
          reinterpret_cast<task_info_t>(&info),
          &count) != KERN_SUCCESS) {
    return -1;
  }
  return static_cast<double>(info.resident_size);
#elif defined(__ANDROID__)
  if (FILE* statm = std::fopen("/proc/self/statm", "r")) {
    long pages = 0;
    long resident = 0;
    const int read = std::fscanf(statm, "%ld %ld", &pages, &resident);
    std::fclose(statm);
    if (read == 2) {
      return static_cast<double>(resident) * ::sysconf(_SC_PAGESIZE);
    }
  }
  return -1;
#else
  return -1;
#endif
}

std::string escapeJson(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (const char c : in) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

std::string statsJson(const std::vector<double>& samples) {
  char buf[128];
  std::snprintf(
      buf,
      sizeof(buf),
      "{\"n\":%zu,\"median\":%.3f,\"p95\":%.3f}",
      samples.size(),
      percentile(samples, 50),
      percentile(samples, 95));
  return buf;
}

// Embedded probe scripts (generated/probes.hpp).

qntx::harness::probes::Script scriptFor(const std::string& name) {
  using namespace qntx::harness::probes;
  if (name == "runtime") {
    return kRuntime;
  }
  if (name == "echo") {
    return kEcho;
  }
  if (name == "startup") {
    return kStartup;
  }
  if (name == "crash-sync") {
    return kCrashSync;
  }
  if (name == "crash-promise") {
    return kCrashPromise;
  }
  if (name == "kernel") {
    return kKernel;
  }
  if (name == "nitro") {
    return kNitro;
  }
  if (name == "nitro-ping") {
    return kNitroPing;
  }
  throw std::invalid_argument("unknown probe script: " + name);
}

// Runs a probe script and returns the first posted JSON.
std::string runPosted(
    const qntx::harness::probes::Script& script,
    bool bytecode,
    const ::hermes::vm::RuntimeConfig& config) {
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      config,
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel);
  try {
    auto bytes = channel->take(deadlineAfter(std::chrono::seconds(30)));
    rt->destroy();
    return toString(bytes);
  } catch (...) {
    rt->destroy();
    throw;
  }
}

// Runs a probe that posts two messages: a "-ready" marker right after evaluation (the
// create→script-ready timing) and the final result JSON.
std::string runTwoPosts(
    const qntx::harness::probes::Script& script,
    bool bytecode,
    bool installNitro) {
  auto channel = std::make_shared<Channel>();
  const auto t0 = Clock::now();
  auto rt = startKernel(
      defaultConfig(),
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel,
      installNitro);
  try {
    channel->take(deadlineAfter(std::chrono::minutes(2)));
    const auto t1 = Clock::now();
    auto bytes = channel->take(deadlineAfter(std::chrono::minutes(2)));
    rt->destroy();
    char buf[64];
    std::snprintf(
        buf,
        sizeof(buf),
        "%.3f",
        std::chrono::duration<double, std::milli>(t1 - t0).count());
    return std::string("{\"createToReadyMs\":") + buf + ",\"result\":" + toString(bytes) + "}";
  } catch (...) {
    rt->destroy();
    throw;
  }
}

std::string runStartup(bool bytecode) {
  std::vector<double> samples;
  samples.reserve(20);
  const auto script = scriptFor("startup");
  for (int i = 0; i < 20; i++) {
    auto channel = std::make_shared<Channel>();
    const auto t0 = Clock::now();
    auto rt = startKernel(
        defaultConfig(),
        script.source,
        script.sourceSize,
        script.bytecode,
        script.bytecodeSize,
        bytecode,
        channel);
    channel->take(deadlineAfter(std::chrono::seconds(30)));
    const auto t1 = Clock::now();
    rt->destroy();
    samples.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
  }
  return std::string("{\"createToReadyMs\":") + statsJson(samples) + "}";
}

std::string runRoundtrip(bool bytecode) {
  const auto script = scriptFor("echo");
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      defaultConfig(),
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel);
  try {
    channel->take(deadlineAfter(std::chrono::seconds(30)));
    auto measure = [&](size_t size, int count) {
      std::vector<double> samples;
      samples.reserve(count);
      std::vector<uint8_t> message(size);
      for (size_t i = 0; i < size; i++) {
        message[i] = static_cast<uint8_t>(i);
      }
      for (int i = 0; i < count; i++) {
        const auto t0 = Clock::now();
        rt->post(std::vector<uint8_t>(message));
        auto echoed = channel->take(deadlineAfter(std::chrono::seconds(30)));
        const auto t1 = Clock::now();
        if (echoed.size() != size) {
          throw std::runtime_error("echo returned wrong length");
        }
        samples.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
      }
      return statsJson(samples);
    };
    auto kib1 = measure(1024, 200);
    auto kib64 = measure(64 * 1024, 200);
    rt->destroy();
    return std::string("{\"rtt1KiB\":") + kib1 + ",\"rtt64KiB\":" + kib64 + "}";
  } catch (...) {
    rt->destroy();
    throw;
  }
}

std::string runLifecycle(bool bytecode) {
  const auto script = scriptFor("startup");
  const double before = residentBytes();
  int cycles = 0;
  for (int i = 0; i < 100; i++) {
    auto channel = std::make_shared<Channel>();
    auto rt = startKernel(
        defaultConfig(),
        script.source,
        script.sourceSize,
        script.bytecode,
        script.bytecodeSize,
        bytecode,
        channel);
    channel->take(deadlineAfter(std::chrono::seconds(30)));
    rt->destroy();
    cycles++;
  }
  const double after = residentBytes();
  char buf[256];
  std::snprintf(
      buf,
      sizeof(buf),
      "{\"cycles\":%d,\"rssBeforeBytes\":%.0f,\"rssAfterBytes\":%.0f,\"rssDeltaBytes\":%.0f}",
      cycles,
      before,
      after,
      after - before);
  return buf;
}

std::string runCrash(const std::string& probe, bool bytecode) {
  const auto script = scriptFor(probe);
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      defaultConfig(),
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel);
  try {
    auto error = channel->takeError(deadlineAfter(std::chrono::seconds(30)));
    rt->destroy();
    const bool destroyed = !rt->running();
    return std::string("{\"surfaced\":\"onError\",\"message\":\"") + escapeJson(error) +
        "\",\"runtimeDestroyed\":" + (destroyed ? "true" : "false") +
        ",\"appAlive\":true}";
  } catch (...) {
    rt->destroy();
    throw;
  }
}

std::string runHardened(bool bytecode) {
  auto config = facebook::hermes::hardenedHermesRuntimeConfig();
  const auto script = scriptFor("runtime");
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      config,
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel);
  try {
    auto bytes = channel->take(deadlineAfter(std::chrono::seconds(30)));
    rt->destroy();
    return std::string("{\"ran\":true,\"result\":") + toString(bytes) + "}";
  } catch (const std::exception& e) {
    rt->destroy();
    return std::string("{\"ran\":false,\"error\":\"") + escapeJson(e.what()) + "\"}";
  }
}

std::string runEchoCheck(bool bytecode) {
  const auto script = scriptFor("echo");
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      defaultConfig(),
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel);
  try {
    channel->take(deadlineAfter(std::chrono::seconds(30)));
    rt->post(std::vector<uint8_t>{'p', 'i', 'n', 'g'});
    auto echoed = channel->take(deadlineAfter(std::chrono::seconds(30)));
    rt->destroy();
    return std::string("{\"echoed\":") +
        (echoed == std::vector<uint8_t>{'p', 'i', 'n', 'g'} ? "true" : "false") +
        ",\"bytes\":" + std::to_string(echoed.size()) + "}";
  } catch (...) {
    rt->destroy();
    throw;
  }
}

std::string execute(const std::string& probe, const std::string& mode) {
  bool bytecode;
  if (mode == "source") {
    bytecode = false;
  } else if (mode == "bytecode") {
    bytecode = true;
  } else {
    throw std::invalid_argument("mode must be \"source\" or \"bytecode\", got: " + mode);
  }

  if (probe == "runtime") {
    return runPosted(scriptFor("runtime"), bytecode, defaultConfig());
  }
  if (probe == "echo") {
    return runEchoCheck(bytecode);
  }
  if (probe == "startup") {
    return runStartup(bytecode);
  }
  if (probe == "roundtrip") {
    return runRoundtrip(bytecode);
  }
  if (probe == "lifecycle") {
    return runLifecycle(bytecode);
  }
  if (probe == "crash-sync" || probe == "crash-promise") {
    return runCrash(probe, bytecode);
  }
  if (probe == "hardened") {
    return runHardened(bytecode);
  }
  if (probe == "kernel") {
    return runTwoPosts(scriptFor("kernel"), bytecode, false);
  }
  if (probe == "nitro" || probe == "nitro-ping") {
    return runTwoPosts(scriptFor(probe), bytecode, true);
  }
  throw std::invalid_argument("unknown probe: " + probe);
}

void printResultLine(const std::string& line) {
  std::string out = "V1_RESULT " + line;
#if defined(__ANDROID__)
  __android_log_print(ANDROID_LOG_INFO, "V1Probe", "%s", out.c_str());
#else
  std::fprintf(stderr, "%s\n", out.c_str());
  std::fflush(stderr);
#endif
}

void emitResult(const std::string& probe, const std::string& mode, bool ok, const std::string& payload) {
  // payload is either the probe JSON verbatim or an escaped error string.
  std::string line = std::string("{\"probe\":\"") + probe + "\",\"mode\":\"" + mode +
      "\",\"ok\":" + (ok ? "true" : "false") + "," +
      (ok ? "\"result\":" + payload : "\"error\":\"" + escapeJson(payload) + "\"") + "}";
  printResultLine(line);
}

} // namespace

std::shared_ptr<Promise<std::string>> HybridV1Probe::run(
    const std::string& probe,
    const std::string& mode) {
  auto promise = Promise<std::string>::create();
  std::thread([promise, probe, mode]() {
    try {
      auto result = execute(probe, mode);
      emitResult(probe, mode, true, result);
      promise->resolve(std::move(result));
    } catch (const std::exception& e) {
      emitResult(probe, mode, false, e.what());
      promise->reject(std::current_exception());
    } catch (...) {
      emitResult(probe, mode, false, "unknown error");
      promise->reject(
          std::make_exception_ptr(std::runtime_error("unknown probe error")));
    }
  }).detach();
  return promise;
}

void HybridV1Probe::emit(const std::string& line) {
  printResultLine(line);
}

} // namespace margelo::nitro::v1probe
