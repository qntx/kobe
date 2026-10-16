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
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#elif defined(__ANDROID__)
#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#endif

namespace margelo::nitro::v1probe {

using Clock = std::chrono::steady_clock;

// One open kernel driven by openKernel/send/closeKernel. The session owns the
// runtime; hooks capture the session (not the HybridObject) so the kernel thread
// never dereferences a destroyed probe. Kernel posts resolve pending sends FIFO;
// posts that arrive with no pending send queue in inbox for the next send.
struct KernelSession {
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<std::vector<uint8_t>> inbox;
  std::deque<std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>>> pending;
  std::optional<std::string> error;
  std::shared_ptr<qntx::KernelRuntime> rt;

  void onPost(std::vector<uint8_t> bytes) {
    std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> next;
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (!pending.empty()) {
        next = std::move(pending.front());
        pending.pop_front();
      } else {
        inbox.push_back(std::move(bytes));
      }
    }
    cv.notify_all();
    if (next) {
      next->resolve(ArrayBuffer::copy(bytes));
    }
  }

  void onError(std::string message) {
    std::deque<std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>>> failed;
    {
      std::lock_guard<std::mutex> lock(mutex);
      error = message;
      failed.swap(pending);
    }
    cv.notify_all();
    auto exception = std::make_exception_ptr(std::runtime_error(std::move(message)));
    for (const auto& promise : failed) {
      promise->reject(exception);
    }
  }
};

namespace {

// Mailbox between a KernelRuntime's hooks and the probe orchestrator thread.
struct Channel {
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<std::vector<uint8_t>> inbox;
  std::optional<std::string> error;
  Clock::time_point errorAt{};

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
      errorAt = Clock::now();
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
    qntx::KernelProfile profile,
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
  return qntx::KernelRuntime::start(std::move(script), std::move(hooks), profile);
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

// Physical footprint on Apple (TASK_VM_INFO phys_footprint — the number jetsam
// and Xcode report); resident set from /proc/self/statm on Android.
double footprintBytes() {
#if defined(__APPLE__)
  task_vm_info_data_t info;
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  if (task_info(
          mach_task_self(),
          TASK_VM_INFO,
          reinterpret_cast<task_info_t>(&info),
          &count) != KERN_SUCCESS) {
    return -1;
  }
  return static_cast<double>(info.phys_footprint);
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
  const auto sorted = [&] {
    auto v = samples;
    std::sort(v.begin(), v.end());
    return v;
  }();
  char buf[192];
  std::snprintf(
      buf,
      sizeof(buf),
      "{\"n\":%zu,\"median\":%.3f,\"p95\":%.3f,\"min\":%.3f,\"max\":%.3f}",
      samples.size(),
      percentile(samples, 50),
      percentile(samples, 95),
      sorted.empty() ? 0.0 : sorted.front(),
      sorted.empty() ? 0.0 : sorted.back());
  return buf;
}

#if defined(__APPLE__)
std::string sysctlString(const char* name) {
  size_t size = 0;
  if (sysctlbyname(name, nullptr, &size, nullptr, 0) != 0 || size == 0) {
    return "unknown";
  }
  std::string value(size, '\0');
  if (sysctlbyname(name, value.data(), &size, nullptr, 0) != 0) {
    return "unknown";
  }
  if (!value.empty() && value.back() == '\0') {
    value.pop_back();
  }
  return value;
}
#elif defined(__ANDROID__)
std::string systemProperty(const char* name) {
  char value[PROP_VALUE_MAX] = {0};
  if (__system_property_get(name, value) <= 0) {
    return "unknown";
  }
  return value;
}
#endif

// Provenance attached to every V1_RESULT line: build-time constants baked into
// generated/probes.hpp plus platform fields collected here.
std::string provenanceJson() {
#if defined(__ANDROID__)
  const char* platform = "android";
  const std::string osVersion =
      systemProperty("ro.build.version.release") + " (SDK " +
      systemProperty("ro.build.version.sdk") + ")";
  const std::string device = systemProperty("ro.product.model");
  const bool simulator =
      systemProperty("ro.kernel.qemu") == "1" || systemProperty("ro.boot.qemu") == "1";
#elif defined(__APPLE__) && TARGET_OS_SIMULATOR
  const char* platform = "ios";
  const std::string osVersion = sysctlString("kern.osproductversion");
  const char* model = std::getenv("SIMULATOR_MODEL_IDENTIFIER");
  const std::string device = model != nullptr ? model : sysctlString("hw.machine");
  const bool simulator = true;
#elif defined(__APPLE__)
  const char* platform = "ios";
  const std::string osVersion = sysctlString("kern.osproductversion");
  const std::string device = sysctlString("hw.machine");
  const bool simulator = false;
#else
  const char* platform = "unknown";
  const std::string osVersion = "unknown";
  const std::string device = "unknown";
  const bool simulator = false;
#endif
#ifdef NDEBUG
  const char* buildConfig = "release";
#else
  const char* buildConfig = "debug";
#endif
  using namespace qntx::harness::probes;
  return std::string("{\"commit\":\"") + kCommit + "\",\"dirty\":" + (kDirty ? "true" : "false") +
      ",\"buildConfig\":\"" + buildConfig + "\",\"platform\":\"" + platform +
      "\",\"osVersion\":\"" + escapeJson(osVersion) + "\",\"device\":\"" + escapeJson(device) +
      "\",\"simulator\":" + (simulator ? "true" : "false") + ",\"nitroVersion\":\"" +
      kNitroVersion + "\",\"nitroPatchSha256\":\"" + kNitroPatchSha256 + "\",\"hermesc\":\"" +
      escapeJson(kHermesc) + "\"}";
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
  if (name == "busy") {
    return kBusy;
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
    qntx::KernelProfile profile = qntx::KernelProfile::standard) {
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      profile,
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
    bool installNitro,
    qntx::KernelProfile profile = qntx::KernelProfile::standard) {
  auto channel = std::make_shared<Channel>();
  const auto t0 = Clock::now();
  auto rt = startKernel(
      profile,
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

// Q2: 20 create → kernel-ready startups of the REAL kernel bundle per mode.
std::string runStartup(bool bytecode) {
  std::vector<double> samples;
  samples.reserve(20);
  const auto script = scriptFor("kernel");
  for (int i = 0; i < 20; i++) {
    auto channel = std::make_shared<Channel>();
    const auto t0 = Clock::now();
    auto rt = startKernel(
        qntx::KernelProfile::standard,
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
  return std::string("{\"kernelReadyMs\":") + statsJson(samples) + "}";
}

std::string runRoundtrip(bool bytecode) {
  const auto script = scriptFor("echo");
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      qntx::KernelProfile::standard,
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

// Least-squares slope (bytes/cycle) over footprint samples taken at cycles
// `from`..100 step 10; `footprints` holds samples at 0,10,...,100.
double slopeBytesPerCycle(const std::vector<double>& footprints, int from) {
  std::vector<double> xs;
  std::vector<double> ys;
  for (size_t i = 0; i < footprints.size(); i++) {
    const int cycle = static_cast<int>(i) * 10;
    if (cycle >= from) {
      xs.push_back(cycle);
      ys.push_back(footprints[i]);
    }
  }
  if (xs.size() < 2) {
    return 0;
  }
  const double xMean = std::accumulate(xs.begin(), xs.end(), 0.0) / xs.size();
  const double yMean = std::accumulate(ys.begin(), ys.end(), 0.0) / ys.size();
  double num = 0;
  double den = 0;
  for (size_t i = 0; i < xs.size(); i++) {
    num += (xs[i] - xMean) * (ys[i] - yMean);
    den += (xs[i] - xMean) * (xs[i] - xMean);
  }
  return den == 0 ? 0 : num / den;
}

std::string lifecycleSeriesJson(int cycles, const std::vector<double>& footprints) {
  std::string out = "{\"cycles\":" + std::to_string(cycles) + ",\"footprints\":[";
  for (size_t i = 0; i < footprints.size(); i++) {
    if (i > 0) {
      out += ",";
    }
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%.0f", footprints[i]);
    out += buf;
  }
  char slope[32];
  std::snprintf(slope, sizeof(slope), "%.1f", slopeBytesPerCycle(footprints, 20));
  out += "],\"slopeBytesPerCycle\":" + std::string(slope) + "}";
  return out;
}

// One create → first post → destroy → waitUntilStopped cycle.
void lifecycleCycle(
    const qntx::harness::probes::Script& script,
    bool bytecode,
    bool installNitro) {
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      qntx::KernelProfile::standard,
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel,
      installNitro);
  channel->take(deadlineAfter(std::chrono::seconds(30)));
  rt->destroy();
  rt->waitUntilStopped(std::chrono::seconds(30));
}

// crash-sync tears itself down on the fatal error; waitUntilStopped proves it.
void lifecycleCrashCycle(const qntx::harness::probes::Script& script, bool bytecode) {
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      qntx::KernelProfile::standard,
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel);
  channel->takeError(deadlineAfter(std::chrono::seconds(30)));
  rt->waitUntilStopped(std::chrono::seconds(30));
  rt->destroy();
}

// Q6: 100 create/destroy cycles for the real kernel bundle, the Nitro-installed
// probe, and the crash path; footprint sampled every 10 cycles.
std::string runLifecycle(bool bytecode) {
  const auto kernelScript = scriptFor("kernel");
  const auto nitroScript = scriptFor("nitro-ping");
  const auto crashScript = scriptFor("crash-sync");

  auto runSeries = [&](const char* name, const auto& cycle) {
    std::vector<double> footprints;
    footprints.reserve(11);
    int cycles = 0;
    std::optional<std::string> error;
    try {
      for (int i = 0; i <= 100; i++) {
        if (i % 10 == 0) {
          footprints.push_back(footprintBytes());
        }
        if (i == 100) {
          break;
        }
        cycle();
        cycles++;
      }
    } catch (const std::exception& e) {
      error = e.what();
    }
    std::string out = std::string("\"") + name + "\":";
    if (error.has_value()) {
      out += "{\"error\":\"" + escapeJson(*error) + "\"}";
    } else {
      out += lifecycleSeriesJson(cycles, footprints);
    }
    return out;
  };

  const std::string kernel =
      runSeries("kernel", [&] { lifecycleCycle(kernelScript, bytecode, false); });
  const std::string nitro =
      runSeries("nitro", [&] { lifecycleCycle(nitroScript, bytecode, true); });
  const std::string crash =
      runSeries("crash", [&] { lifecycleCrashCycle(crashScript, bytecode); });
  return "{" + kernel + "," + nitro + "," + crash + "}";
}

std::string runCrash(const std::string& probe, bool bytecode) {
  const auto script = scriptFor(probe);
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      qntx::KernelProfile::standard,
      script.source,
      script.sourceSize,
      script.bytecode,
      script.bytecodeSize,
      bytecode,
      channel);
  try {
    auto error = channel->takeError(deadlineAfter(std::chrono::seconds(30)));
    // The kernel must tear itself down after a fatal error, without destroy().
    const bool stopped = rt->waitUntilStopped(std::chrono::seconds(1)) && !rt->running();
    const auto stoppedAt = Clock::now();
    const double stopMs =
        std::chrono::duration<double, std::milli>(stoppedAt - channel->errorAt).count();
    rt->destroy();
    char stopBuf[32];
    std::snprintf(stopBuf, sizeof(stopBuf), "%.3f", stopMs);
    return std::string("{\"surfaced\":\"onError\",\"message\":\"") + escapeJson(error) +
        "\",\"runtimeDestroyed\":" + (stopped ? "true" : "false") +
        ",\"stopMs\":" + stopBuf + ",\"appAlive\":true}";
  } catch (...) {
    rt->destroy();
    throw;
  }
}

std::string runHardened(bool bytecode) {
  const auto script = scriptFor("runtime");
  auto channel = std::make_shared<Channel>();
  auto rt = startKernel(
      qntx::KernelProfile::hardened,
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
      qntx::KernelProfile::standard,
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

bool parseBytecode(const std::string& mode) {
  if (mode == "source") {
    return false;
  }
  if (mode == "bytecode") {
    return true;
  }
  throw std::invalid_argument("mode must be \"source\" or \"bytecode\", got: " + mode);
}

std::string execute(const std::string& probe, const std::string& mode) {
  const bool bytecode = parseBytecode(mode);

  if (probe == "runtime") {
    return runPosted(scriptFor("runtime"), bytecode);
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
  if (probe == "kernel-hardened") {
    return runTwoPosts(scriptFor("kernel"), bytecode, false, qntx::KernelProfile::hardened);
  }
  if (probe == "nitro" || probe == "nitro-ping") {
    return runTwoPosts(scriptFor(probe), bytecode, true);
  }
  throw std::invalid_argument("unknown probe: " + probe);
}

void printResultLine(const std::string& line) {
  std::string out = "V1_RESULT " + line;
#if defined(__ANDROID__)
  // logd cuts messages at ~1 KiB; chunk long lines with V1_CONT continuations
  // and a V1_END terminator so capture can reassemble.
  static std::mutex printMutex;
  std::lock_guard<std::mutex> lock(printMutex);
  constexpr size_t kChunk = 900;
  size_t offset = 0;
  bool fragmented = false;
  while (offset < out.size()) {
    const auto piece = out.substr(offset, kChunk);
    __android_log_print(
        ANDROID_LOG_INFO,
        "V1Probe",
        "%s%s",
        fragmented ? "V1_CONT " : "",
        piece.c_str());
    fragmented = true;
    offset += piece.size();
  }
  if (fragmented && out.size() > kChunk) {
    __android_log_print(ANDROID_LOG_INFO, "V1Probe", "V1_END");
  }
#else
  std::fprintf(stderr, "%s\n", out.c_str());
  std::fflush(stderr);
#endif
}

void emitResult(const std::string& probe, const std::string& mode, bool ok, const std::string& payload) {
  // payload is either the probe JSON verbatim or an escaped error string.
  std::string line = std::string("{\"probe\":\"") + probe + "\",\"mode\":\"" + mode +
      "\",\"ok\":" + (ok ? "true" : "false") + "," +
      (ok ? "\"result\":" + payload : "\"error\":\"" + escapeJson(payload) + "\"") +
      ",\"provenance\":" + provenanceJson() + "}";
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

std::shared_ptr<Promise<void>> HybridV1Probe::openKernel(
    const std::string& probe,
    const std::string& mode) {
  auto promise = Promise<void>::create();
  std::shared_ptr<KernelSession> session;
  try {
    const auto script = scriptFor(probe);
    const bool bytecode = parseBytecode(mode);
    session = std::make_shared<KernelSession>();
    qntx::KernelScript kernelScript{
        bytecode ? qntx::KernelScript::Kind::bytecode : qntx::KernelScript::Kind::source,
        bytecode
            ? std::make_shared<const std::vector<uint8_t>>(
                  script.bytecode, script.bytecode + script.bytecodeSize)
            : std::make_shared<const std::vector<uint8_t>>(
                  script.source, script.source + script.sourceSize)};
    qntx::KernelRuntime::Hooks hooks;
    hooks.onPost = [session](std::vector<uint8_t> bytes) {
      session->onPost(std::move(bytes));
    };
    hooks.onError = [session](std::string message) {
      session->onError(std::move(message));
    };
    session->rt = qntx::KernelRuntime::start(std::move(kernelScript), std::move(hooks));
    {
      std::lock_guard<std::mutex> lock(sessionMutex_);
      if (session_) {
        session->rt->destroy();
        throw std::runtime_error("a kernel is already open");
      }
      session_ = session;
    }
  } catch (const std::exception& e) {
    promise->reject(std::make_exception_ptr(std::runtime_error(e.what())));
    return promise;
  }
  // Resolve once the kernel's first post (the ready marker) arrives.
  std::thread([session, promise]() {
    std::optional<std::string> failure;
    {
      std::unique_lock<std::mutex> lock(session->mutex);
      const bool ready = session->cv.wait_until(
          lock,
          Clock::now() + std::chrono::seconds(30),
          [&] { return !session->inbox.empty() || session->error.has_value(); });
      if (!ready) {
        failure = "openKernel timed out waiting for the first post";
      } else if (session->error.has_value()) {
        failure = *session->error;
      } else {
        session->inbox.pop_front();
      }
    }
    if (failure.has_value()) {
      promise->reject(std::make_exception_ptr(std::runtime_error(*failure)));
    } else {
      promise->resolve();
    }
  }).detach();
  return promise;
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridV1Probe::send(
    const std::shared_ptr<ArrayBuffer>& message) {
  auto promise = Promise<std::shared_ptr<ArrayBuffer>>::create();
  // Copy on the calling (JS) thread — the buffer's data is only valid here.
  std::vector<uint8_t> bytes(message->data(), message->data() + message->size());
  std::shared_ptr<KernelSession> session;
  {
    std::lock_guard<std::mutex> lock(sessionMutex_);
    session = session_;
  }
  if (!session) {
    promise->reject(
        std::make_exception_ptr(std::runtime_error("send: no kernel open")));
    return promise;
  }
  std::shared_ptr<ArrayBuffer> buffered;
  {
    std::lock_guard<std::mutex> lock(session->mutex);
    if (session->error.has_value()) {
      promise->reject(std::make_exception_ptr(std::runtime_error(*session->error)));
      return promise;
    }
    if (!session->inbox.empty()) {
      buffered = ArrayBuffer::copy(session->inbox.front());
      session->inbox.pop_front();
    } else {
      session->pending.push_back(promise);
    }
  }
  session->rt->post(std::move(bytes));
  if (buffered) {
    promise->resolve(std::move(buffered));
  }
  return promise;
}

void HybridV1Probe::closeKernel() {
  std::shared_ptr<KernelSession> session;
  {
    std::lock_guard<std::mutex> lock(sessionMutex_);
    session = std::move(session_);
    session_.reset();
  }
  if (session) {
    session->onError("kernel closed");
    session->rt->destroy();
  }
}

void HybridV1Probe::report(
    const std::string& probe,
    const std::string& mode,
    bool ok,
    const std::string& payload) {
  emitResult(probe, mode, ok, payload);
}

} // namespace margelo::nitro::v1probe
