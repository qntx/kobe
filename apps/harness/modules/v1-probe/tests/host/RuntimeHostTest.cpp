// Host test driver for the kernel runtime. One binary, one case per process:
// argv[1] selects the case, argv[2] optionally names a .hbc file for the
// bytecode variants. PBKDF2 reference values arrive via env vars
// V1_PBKDF2_SHA256_1 / V1_PBKDF2_SHA256_80000 / V1_PBKDF2_SHA512_UTF8.
#include "runtime/KernelRuntime.hpp"

#if __has_include("generated/probes.hpp")
#include "generated/probes.hpp"
#else
#error "generated/probes.hpp missing — run `bun run harness:bundles` first"
#endif

#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach.h>
#endif

namespace {

namespace jsi = facebook::jsi;
using qntx::KernelProfile;
using qntx::KernelRuntime;
using qntx::KernelScript;
using Clock = std::chrono::steady_clock;

int g_failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      ++g_failures;                                                            \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);       \
    }                                                                          \
  } while (0)

struct Mailbox {
  std::mutex m;
  std::condition_variable cv;
  std::vector<std::string> posts;
  std::vector<std::string> errors;

  void post(std::vector<uint8_t> bytes) {
    {
      std::lock_guard<std::mutex> lock(m);
      posts.emplace_back(bytes.begin(), bytes.end());
    }
    cv.notify_all();
  }
  void fail(std::string message) {
    {
      std::lock_guard<std::mutex> lock(m);
      errors.push_back(std::move(message));
    }
    cv.notify_all();
  }
  size_t waitPosts(size_t n, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(m);
    cv.wait_for(lock, timeout, [&] { return posts.size() >= n; });
    return posts.size();
  }
  bool waitErrors(size_t n, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(m);
    cv.wait_for(lock, timeout, [&] { return errors.size() >= n; });
    return errors.size() >= n;
  }
};

KernelRuntime::Hooks hooksFor(Mailbox& box) {
  KernelRuntime::Hooks hooks;
  hooks.onPost = [&box](std::vector<uint8_t> bytes) { box.post(std::move(bytes)); };
  hooks.onError = [&box](std::string message) { box.fail(std::move(message)); };
  return hooks;
}

KernelScript sourceScript(const std::string& source) {
  return {
      KernelScript::Kind::source,
      std::make_shared<const std::vector<uint8_t>>(source.begin(), source.end())};
}

KernelScript bytecodeScript(const std::vector<uint8_t>& bytes) {
  return {
      KernelScript::Kind::bytecode,
      std::make_shared<const std::vector<uint8_t>>(bytes)};
}

KernelScript probeScript(const qntx::harness::probes::Script& probe, bool bytecode) {
  return {
      bytecode ? KernelScript::Kind::bytecode : KernelScript::Kind::source,
      bytecode
          ? std::make_shared<const std::vector<uint8_t>>(
                probe.bytecode, probe.bytecode + probe.bytecodeSize)
          : std::make_shared<const std::vector<uint8_t>>(
                probe.source, probe.source + probe.sourceSize)};
}

std::vector<uint8_t> readFile(const char* path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// The kernel post channel carries ASCII JSON/text; this helper emits it from JS.
const char kSendHelper[] = R"JS(
function __send(s) {
  var b = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) {
    b[i] = s.charCodeAt(i) & 0xff;
  }
  __qntx.post(b.buffer);
}
)JS";

uint64_t physicalFootprint() {
#if defined(__APPLE__)
  task_vm_info_data_t info{};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  if (task_info(
          mach_task_self(), TASK_VM_INFO,
          reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS) {
    return 0;
  }
  return info.phys_footprint;
#else
  return 0;
#endif
}

// Mirrors KernelRuntime's internal config so the inventory test can diff
// against a bare runtime of the same profile.
::hermes::vm::RuntimeConfig bareConfig(KernelProfile profile) {
  auto builder = profile == KernelProfile::hardened
      ? facebook::hermes::hardenedHermesRuntimeConfig().rebuild()
      : ::hermes::vm::RuntimeConfig::Builder();
  return builder.withMicrotaskQueue(true)
      .withEnableEval(false)
      .withAsyncBreakCheckInEval(true)
      .build();
}

std::set<std::string> globalNames(jsi::Runtime& rt) {
  auto result = rt.evaluateJavaScript(
      std::make_shared<jsi::StringBuffer>(
          "JSON.stringify(Object.getOwnPropertyNames(globalThis))"),
      "<names>");
  const std::string json = result.asString(rt).utf8(rt);
  std::set<std::string> names;
  size_t i = 0;
  while (i < json.size()) {
    auto begin = json.find('"', i);
    if (begin == std::string::npos) {
      break;
    }
    auto end = json.find('"', begin + 1);
    if (end == std::string::npos) {
      break;
    }
    names.insert(json.substr(begin + 1, end - begin - 1));
    i = end + 1;
  }
  return names;
}

int destroyBusyloop(const char* hbcPath) {
  const bool bytecode = hbcPath != nullptr;
  const std::string js = std::string(kSendHelper) +
      "__send(\"ready\"); var t = Date.now(); while (Date.now() - t < 3000) {}";
  Mailbox box;
  auto rt = KernelRuntime::start(
      bytecode ? bytecodeScript(readFile(hbcPath)) : sourceScript(js),
      hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(15)) == 1, "busyloop: ready post missing");
  const auto t0 = Clock::now();
  rt->destroy();
  const auto destroyMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
  CHECK(destroyMs < 50, "busyloop: destroy() blocked >= 50ms");
  CHECK(
      rt->waitUntilStopped(std::chrono::seconds(1)),
      "busyloop: runtime did not stop within 1s");
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  CHECK(box.errors.empty(), "busyloop: destroy surfaced onError");
  return g_failures;
}

// destroy() can win the race against script evaluation itself: whichever side
// is faster, the runtime must stop without the script ever running its loop
// body to completion — and without surfacing an error.
int destroyBeforeEvaluate() {
  Mailbox box;
  auto rt = KernelRuntime::start(
      sourceScript(std::string(kSendHelper) +
          "var t = Date.now(); while (Date.now() - t < 3000) {} __send(\"done\");"),
      hooksFor(box));
  const auto t0 = Clock::now();
  rt->destroy();
  const auto destroyMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
  CHECK(destroyMs < 50, "destroy-before-evaluate: destroy() blocked >= 50ms");
  CHECK(
      rt->waitUntilStopped(std::chrono::seconds(1)),
      "destroy-before-evaluate: runtime did not stop within 1s");
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  {
    std::lock_guard<std::mutex> lock(box.m);
    CHECK(box.posts.empty(), "destroy-before-evaluate: script post arrived");
    CHECK(box.errors.empty(), "destroy-before-evaluate: unexpected onError");
  }
  return g_failures;
}

int destroyConcurrent() {
  Mailbox box;
  auto rt = KernelRuntime::start(
      sourceScript(std::string(kSendHelper) + "__send(\"ready\");"), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(15)) == 1, "concurrent: ready post missing");
  std::thread a([&] {
    for (int i = 0; i < 10; i++) {
      rt->destroy();
    }
  });
  std::thread b([&] {
    for (int i = 0; i < 10; i++) {
      rt->destroy();
    }
  });
  a.join();
  b.join();
  CHECK(rt->waitUntilStopped(std::chrono::seconds(5)), "concurrent: runtime still running");
  CHECK(box.errors.empty(), "concurrent: unexpected onError");
  return g_failures;
}

int destroyKdfInflight() {
  Mailbox box;
  auto rt = KernelRuntime::start(
      sourceScript(
          std::string(kSendHelper) +
          "__qntx.pbkdf2(\"sha256\", new Uint8Array(16), new Uint8Array(16), 10000000, 32,"
          " function () { __send(\"kdf-done\"); });"
          "__send(\"submitted\");"),
      hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(15)) == 1, "kdf-inflight: submit post missing");
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  rt->destroy();
  CHECK(rt->waitUntilStopped(std::chrono::seconds(5)), "kdf-inflight: runtime still running");
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  CHECK(box.posts.size() == 1, "kdf-inflight: completion callback fired after destroy");
  CHECK(box.errors.empty(), "kdf-inflight: unexpected onError");
  return g_failures;
}

int timersCancel() {
  const uint64_t before = physicalFootprint();
  Mailbox box;
  auto rt = KernelRuntime::start(
      sourceScript(
          std::string(kSendHelper) +
          "for (var i = 0; i < 200000; i++) {"
          "  var cancel = __qntx.setTimer(3600000, function () {});"
          "  cancel();"
          "}"
          "__send(\"done\");"),
      hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(120)) == 1, "timers-cancel: never finished");
  rt->destroy();
  const uint64_t after = physicalFootprint();
  std::fprintf(stderr, "timers-cancel footprint: %llu -> %llu\n",
      (unsigned long long)before, (unsigned long long)after);
  CHECK(after - before < 20ULL * 1024 * 1024, "timers-cancel: footprint grew >= 20MB");
  return g_failures;
}

int timersFired() {
  const uint64_t before = physicalFootprint();
  Mailbox box;
  auto rt = KernelRuntime::start(
      sourceScript(
          std::string(kSendHelper) +
          "var i = 0;"
          "function next() {"
          "  i += 1;"
          "  if (i >= 100000) { __send(\"done\"); } else { __qntx.setTimer(0, next); }"
          "}"
          "__qntx.setTimer(0, next);"),
      hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(120)) == 1, "timers-fired: never finished");
  rt->destroy();
  const uint64_t after = physicalFootprint();
  std::fprintf(stderr, "timers-fired footprint: %llu -> %llu\n",
      (unsigned long long)before, (unsigned long long)after);
  CHECK(after - before < 20ULL * 1024 * 1024, "timers-fired: footprint grew >= 20MB");
  return g_failures;
}

int forgedViews() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
function tryCall(f) {
  try {
    f();
    return "no-throw";
  } catch (e) {
    return "threw";
  }
}
var forged = { buffer: new ArrayBuffer(16), byteOffset: 1048576, byteLength: 64 };
__send("pbkdf2-forged:" + tryCall(function () {
  __qntx.pbkdf2("sha256", forged, new Uint8Array(16), 1, 32, function () {});
}));
__send("grv-forged:" + tryCall(function () {
  crypto.getRandomValues(forged);
}));
Object.defineProperty(Uint8Array.prototype, "byteOffset", {
  get: function () { return 1048576; },
  configurable: true,
});
// The intrinsic getters must keep reporting the real slots: a genuine view
// still works and is filled at its true offset even though JS now reads a lie.
__send("grv-redefined:" + tryCall(function () {
  var v = new Uint8Array(16);
  crypto.getRandomValues(v);
}));
__send("pbkdf2-redefined:" + tryCall(function () {
  __qntx.pbkdf2("sha256", new Uint8Array(4), new Uint8Array(4), 1, 32,
      function (r) { __send("pbkdf2-done:" + (r ? r.length : "none")); });
}));
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(5, std::chrono::seconds(30)) == 5, "forged: missing posts");
  std::lock_guard<std::mutex> lock(box.m);
  CHECK(box.posts.size() >= 4 && box.posts[0] == "pbkdf2-forged:threw",
      "forged: pbkdf2 accepted forged view");
  CHECK(box.posts.size() >= 4 && box.posts[1] == "grv-forged:threw",
      "forged: getRandomValues accepted forged view");
  CHECK(box.posts.size() >= 4 && box.posts[2] == "grv-redefined:no-throw",
      "forged: getRandomValues failed on a genuine view after getter redefinition");
  CHECK(box.posts.size() >= 4 && box.posts[3] == "pbkdf2-redefined:no-throw",
      "forged: pbkdf2 rejected a genuine view after getter redefinition");
  CHECK(box.posts.size() >= 5 && box.posts[4] == "pbkdf2-done:32",
      "forged: pbkdf2 completion never arrived");
  rt->destroy();
  return g_failures;
}

int numericValidation() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
var bad = [NaN, Infinity, -1, 1e300, 1.5];
var out = [];
function t(name, f) {
  try {
    var r = f();
    if (typeof r === "function") { r(); }
    out.push(name + ":ok");
  } catch (e) {
    out.push(name + ":threw");
  }
}
for (var i = 0; i < bad.length; i++) {
  var v = bad[i];
  (function (v) {
    t("random-" + v, function () { __qntx.random(v); });
    t("timer-" + v, function () { return __qntx.setTimer(v, function () {}); });
    t("kdf-it-" + v, function () {
      __qntx.pbkdf2("sha256", new Uint8Array(4), new Uint8Array(4), v, 32, function () {});
    });
    t("kdf-len-" + v, function () {
      __qntx.pbkdf2("sha256", new Uint8Array(4), new Uint8Array(4), 1, v, function () {});
    });
  })(v);
}
__send(out.join(","));
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "numeric: no report");
  std::string report;
  {
    std::lock_guard<std::mutex> lock(box.m);
    if (!box.posts.empty()) {
      report = box.posts[0];
    }
  }
  // These are the JS String() renderings the report uses — 1e300 prints "1e+300".
  const std::vector<std::string> bad = {"NaN", "Infinity", "-1", "1e+300", "1.5"};
  for (const auto& value : bad) {
    const bool fractionalDelay = value == "1.5";
    CHECK(report.find("random-" + value + ":threw") != std::string::npos,
        ("numeric: random accepted " + value).c_str());
    const std::string timer = "timer-" + value;
    if (fractionalDelay) {
      CHECK(report.find(timer + ":ok") != std::string::npos,
          "numeric: setTimer rejected fractional delay");
    } else {
      CHECK(report.find(timer + ":threw") != std::string::npos,
          ("numeric: setTimer accepted " + value).c_str());
    }
    CHECK(report.find("kdf-it-" + value + ":threw") != std::string::npos,
        ("numeric: pbkdf2 accepted iterations " + value).c_str());
    CHECK(report.find("kdf-len-" + value + ":threw") != std::string::npos,
        ("numeric: pbkdf2 accepted length " + value).c_str());
  }
  rt->destroy();
  return g_failures;
}

int randomBounds() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
var out = [];
function t(name, f) {
  try { out.push(name + ":" + f()); } catch (e) { out.push(name + ":threw"); }
}
t("r0", function () { return __qntx.random(0).length; });
t("r32", function () { return __qntx.random(32).length; });
t("r65536", function () { return __qntx.random(65536).length; });
t("r65537", function () { __qntx.random(65537); });
var a = __qntx.random(32);
var b = __qntx.random(32);
var same = a.length === b.length;
for (var i = 0; same && i < a.length; i++) { same = a[i] === b[i]; }
out.push("distinct:" + (same ? "no" : "yes"));
__send(out.join(","));
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "random: no report");
  std::lock_guard<std::mutex> lock(box.m);
  CHECK(!box.posts.empty() &&
            box.posts[0].find("r0:0") != std::string::npos &&
            box.posts[0].find("r32:32") != std::string::npos &&
            box.posts[0].find("r65536:65536") != std::string::npos &&
            box.posts[0].find("r65537:threw") != std::string::npos &&
            box.posts[0].find("distinct:yes") != std::string::npos,
      "random: unexpected bounds report");
  rt->destroy();
  return g_failures;
}

int getRandomValuesCase() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
var out = [];
function t(name, f) {
  try { out.push(name + ":" + f()); } catch (e) { out.push(name + ":threw"); }
}
var a = new Uint8Array(16);
a.fill(0xaa);
var sub = a.subarray(4, 8);
var ret = crypto.getRandomValues(sub);
var windowOnly = ret === sub;
for (var i = 0; windowOnly && i < 16; i++) {
  if ((i < 4 || i >= 8) && a[i] !== 0xaa) { windowOnly = false; }
}
out.push("subarray:" + (windowOnly ? "yes" : "no"));
t("float64", function () { crypto.getRandomValues(new Float64Array(4)); });
t("big65k", function () { crypto.getRandomValues(new Uint8Array(65537)); });
t("bigint64", function () { return crypto.getRandomValues(new BigInt64Array(4)).length; });
t("plain", function () { crypto.getRandomValues({ length: 4 }); });
__send(out.join(","));
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "grv: no report");
  std::lock_guard<std::mutex> lock(box.m);
  CHECK(!box.posts.empty() &&
            box.posts[0].find("subarray:yes") != std::string::npos &&
            box.posts[0].find("float64:threw") != std::string::npos &&
            box.posts[0].find("big65k:threw") != std::string::npos &&
            box.posts[0].find("bigint64:4") != std::string::npos &&
            box.posts[0].find("plain:threw") != std::string::npos,
      "grv: unexpected report");
  rt->destroy();
  return g_failures;
}

int crashCase(bool promise, bool bytecode) {
  Mailbox box;
  const auto& script =
      promise ? qntx::harness::probes::kCrashPromise : qntx::harness::probes::kCrashSync;
  auto rt = KernelRuntime::start(probeScript(script, bytecode), hooksFor(box));
  CHECK(box.waitErrors(1, std::chrono::seconds(30)), "crash: no onError");
  CHECK(
      rt->waitUntilStopped(std::chrono::seconds(1)),
      "crash: runtime not stopped within 1s without destroy");
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  CHECK(box.errors.size() == 1, "crash: expected exactly one onError");
  rt->destroy();
  return g_failures;
}

int evalDisabled(KernelProfile profile) {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
var out = [];
try { eval("1"); out.push("eval:ran"); } catch (e) { out.push("eval:threw"); }
try { Function("return 1")(); out.push("fn:ran"); } catch (e) { out.push("fn:threw"); }
__send(out.join(","));
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box), profile);
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "eval: no report");
  std::lock_guard<std::mutex> lock(box.m);
  CHECK(!box.posts.empty() &&
            box.posts[0].find("eval:threw") != std::string::npos &&
            box.posts[0].find("fn:threw") != std::string::npos,
      "eval: eval or Function ran");
  rt->destroy();
  return g_failures;
}

int globalDescriptors() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
function hidden(name) {
  var d = Object.getOwnPropertyDescriptor(globalThis, name);
  return d && d.writable === false && d.configurable === false && d.enumerable === false;
}
function stillThere(name, kind) {
  try { globalThis[name] = 1; } catch (e) {}
  try { delete globalThis[name]; } catch (e) {}
  return typeof globalThis[name] === kind;
}
function decoderTamper() {
  try { TextDecoder.prototype.decode = function () { return "forged"; }; } catch (e) {}
  var bytes = new Uint8Array([0x68, 0x69]);
  var stillWorks = new TextDecoder().decode(bytes) === "hi";
  var threw = false;
  try {
    Object.defineProperty(TextDecoder.prototype, "decode", { value: function () { return "x"; } });
  } catch (e) { threw = true; }
  return stillWorks && threw;
}
__send(JSON.stringify({
  qntx: hidden("__qntx") && Object.isFrozen(__qntx) && stillThere("__qntx", "object"),
  crypto: hidden("crypto") && Object.isFrozen(crypto) && stillThere("crypto", "object"),
  decoder: hidden("TextDecoder") && stillThere("TextDecoder", "function") && decoderTamper(),
  noPrivate: Object.getOwnPropertyNames(globalThis).indexOf("__qntxUnhandledRejection") < 0,
}));
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "descriptors: no report");
  std::lock_guard<std::mutex> lock(box.m);
  CHECK(!box.posts.empty() &&
            box.posts[0].find("\"qntx\":true") != std::string::npos &&
            box.posts[0].find("\"crypto\":true") != std::string::npos &&
            box.posts[0].find("\"decoder\":true") != std::string::npos &&
            box.posts[0].find("\"noPrivate\":true") != std::string::npos,
      "descriptors: globals writable/configurable/enumerable or deletable");
  rt->destroy();
  return g_failures;
}

int globalInventory(KernelProfile profile) {
  Mailbox box;
  auto rt = KernelRuntime::start(
      sourceScript(
          std::string(kSendHelper) +
          "__send(JSON.stringify(Object.getOwnPropertyNames(globalThis)));"),
      hooksFor(box),
      profile);
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "inventory: no report");
  std::set<std::string> kernelNames;
  {
    std::lock_guard<std::mutex> lock(box.m);
    if (!box.posts.empty()) {
      const std::string& json = box.posts[0];
      size_t i = 0;
      while (i < json.size()) {
        auto begin = json.find('"', i);
        if (begin == std::string::npos) {
          break;
        }
        auto end = json.find('"', begin + 1);
        if (end == std::string::npos) {
          break;
        }
        kernelNames.insert(json.substr(begin + 1, end - begin - 1));
        i = end + 1;
      }
    }
  }
  rt->destroy();
  // __send is declared by the test script itself, not installed by the runtime.
  kernelNames.erase("__send");
  auto bare = facebook::hermes::makeHermesRuntime(bareConfig(profile));
  std::set<std::string> bareNames = globalNames(*bare);
  std::vector<std::string> diff;
  for (const auto& name : kernelNames) {
    if (bareNames.find(name) == bareNames.end()) {
      diff.push_back(name);
    }
  }
  const std::set<std::string> expected =
      {"__qntx", "crypto", "TextDecoder", "setTimeout", "clearTimeout"};
  CHECK(
      std::set<std::string>(diff.begin(), diff.end()) == expected,
      "inventory: unexpected kernel global set");
  if (g_failures > 0) {
    std::fprintf(stderr, "inventory diff:");
    for (const auto& name : diff) {
      std::fprintf(stderr, " %s", name.c_str());
    }
    std::fprintf(stderr, "\n");
  }
  return g_failures;
}

int textDecoderCase() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
var out = [];
function t(name, f) {
  try { out.push(name + ":" + f()); } catch (e) { out.push(name + ":" + e.name); }
}
function dec(bytes, opts) {
  return new TextDecoder("utf-8", opts).decode(new Uint8Array(bytes), opts);
}
// Valid 1-4 byte sequences (code points — the post channel is ASCII only).
out.push("ascii:" + dec([0x61]));
out.push("two:" + dec([0xc3, 0xa9]).charCodeAt(0));
out.push("three:" + dec([0xe2, 0x82, 0xac]).charCodeAt(0));
out.push("four:" + dec([0xf0, 0x9f, 0x98, 0x80]).length);
// BOM strip by default, kept under ignoreBOM.
out.push("bom:" + dec([0xef, 0xbb, 0xbf, 0x78]));
out.push("bomKeep:" + dec([0xef, 0xbb, 0xbf, 0x78], { ignoreBOM: true }).length);
// fatal rejects.
var bad = [
  [0xc0, 0x80], [0xe0, 0x80, 0x80], [0xed, 0xa0, 0x80],
  [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82], [0x80],
];
for (var i = 0; i < bad.length; i++) {
  (function (bytes, idx) {
    t("fatal" + idx, function () {
      dec(bytes, { fatal: true });
      return "ran";
    });
  })(bad[i], i);
}
// WHATWG maximal-subpart replacement counts.
out.push("repTrunc4:" + dec([0xf0, 0x90, 0x80]).length);
out.push("repC0:" + dec([0xc0, 0x80]).length);
out.push("repED:" + dec([0xed, 0xa0, 0x80]).length);
t("stream", function () {
  dec([0x61], { stream: true });
  return "ran";
});
t("label", function () {
  new TextDecoder("utf-16");
  return "ran";
});
t("labels", function () {
  new TextDecoder(" UTF8 ");
  new TextDecoder("unicode-1-1-utf-8");
  return "ok";
});
out.push("empty:" + (new TextDecoder().decode() === ""));
__send(out.join(","));
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "decoder: no report");
  std::lock_guard<std::mutex> lock(box.m);
  if (!box.posts.empty()) {
    const std::string& r = box.posts[0];
    CHECK(r.find("ascii:a") != std::string::npos &&
              r.find("two:233") != std::string::npos &&
              r.find("three:8364") != std::string::npos &&
              r.find("four:2") != std::string::npos,
        "decoder: valid sequences failed");
    CHECK(r.find("bom:x") != std::string::npos &&
              r.find("bomKeep:2") != std::string::npos,
        "decoder: BOM handling wrong");
    for (int i = 0; i < 6; i++) {
      CHECK(r.find("fatal" + std::to_string(i) + ":TypeError") != std::string::npos,
          ("decoder: fatal accepted bad input " + std::to_string(i)).c_str());
    }
    CHECK(r.find("repTrunc4:1") != std::string::npos &&
              r.find("repC0:2") != std::string::npos &&
              r.find("repED:3") != std::string::npos,
        "decoder: replacement counts wrong");
    CHECK(r.find("stream:TypeError") != std::string::npos,
        "decoder: stream:true did not throw");
    CHECK(r.find("label:RangeError") != std::string::npos,
        "decoder: unknown label did not throw RangeError");
    CHECK(r.find("labels:ok") != std::string::npos &&
              r.find("empty:true") != std::string::npos,
        "decoder: valid labels or empty decode failed");
  }
  rt->destroy();
  return g_failures;
}

int pbkdf2Vectors() {
  const char* expect1 = std::getenv("V1_PBKDF2_SHA256_1");
  const char* expect2 = std::getenv("V1_PBKDF2_SHA256_80000");
  const char* expect3 = std::getenv("V1_PBKDF2_SHA512_UTF8");
  CHECK(expect1 && expect2 && expect3, "pbkdf2: expected vectors not in env");
  Mailbox box;
  // Password/salt byte lists are UTF-8 encodings baked in by the script.
  const std::string js = std::string(kSendHelper) + R"JS(
var pending = 3;
var out = [];
function hex(b) {
  var h = "";
  for (var i = 0; i < b.length; i++) {
    var x = b[i].toString(16);
    h += x.length < 2 ? "0" + x : x;
  }
  return h;
}
function ascii(s) {
  var a = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) { a[i] = s.charCodeAt(i); }
  return a;
}
function done(r, e) {
  out.push(e ? "err" : hex(r));
  if (--pending === 0) { __send(out.join(",")); }
}
__qntx.pbkdf2("sha256", ascii("passwd"), ascii("salt"), 1, 64, done);
__qntx.pbkdf2("sha256", ascii("Password"), ascii("NaCl"), 80000, 64, done);
__qntx.pbkdf2("sha512", new Uint8Array([
  0x70, 0xc3, 0xa4, 0x73, 0x73, 0x77, 0xc3, 0xb6, 0x72, 0x64, 0x20, 0xf0, 0x9f, 0x94, 0x91]),
  new Uint8Array([0x73, 0x61, 0x6c, 0x74, 0x2d, 0xe2, 0x9c, 0x93]), 777, 48, done);
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(60)) == 1, "pbkdf2: no report");
  {
    std::lock_guard<std::mutex> lock(box.m);
    if (!box.posts.empty() && expect1 && expect2 && expect3) {
      const std::string want =
          std::string(expect1) + "," + expect2 + "," + expect3;
      CHECK(box.posts[0] == want, "pbkdf2: vector mismatch");
      if (box.posts[0] != want) {
        std::fprintf(stderr, "pbkdf2 got:  %s\nwant: %s\n", box.posts[0].c_str(), want.c_str());
      }
    }
  }
  rt->destroy();
  return g_failures;
}

int kdfQueueFull() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
var errors = [];
var done = 0;
function cb(r, e) {
  done += 1;
  if (e) { errors.push(e); }
  if (errors.length > 0) {
    __send("error:" + errors[0]);
  }
}
// Occupy the single worker for seconds, then fill the queue of 8: the ninth
// queued job must come back with "kdf queue full".
__qntx.pbkdf2("sha256", new Uint8Array(4), new Uint8Array(4), 10000000, 32, cb);
for (var i = 0; i < 8; i++) {
  __qntx.pbkdf2("sha256", new Uint8Array(4), new Uint8Array(4), 1, 32, cb);
}
__qntx.pbkdf2("sha256", new Uint8Array(4), new Uint8Array(4), 1, 32, cb);
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  // Both the ninth and the tenth submit can be rejected when the worker has
  // not picked up the first job yet; every rejection must carry the error.
  CHECK(
      box.waitPosts(1, std::chrono::seconds(30)) >= 1,
      "kdf-queue: full-queue error never arrived");
  {
    std::lock_guard<std::mutex> lock(box.m);
    for (const auto& post : box.posts) {
      CHECK(post == "error:kdf queue full", "kdf-queue: wrong error string");
    }
    CHECK(box.errors.empty(), "kdf-queue: unexpected onError");
  }
  rt->destroy();
  return g_failures;
}

int elapsedMonotonic() {
  Mailbox box;
  const std::string js = std::string(kSendHelper) + R"JS(
var prev = __qntx.elapsed();
var monotonic = true;
var fractional = prev !== Math.floor(prev);
var subMs = false;
for (var i = 0; i < 1000; i++) {
  var t = __qntx.elapsed();
  if (t < prev) { monotonic = false; }
  if (t - prev > 0 && t - prev < 1) { subMs = true; }
  if (t !== Math.floor(t)) { fractional = true; }
  prev = t;
}
__send("monotonic:" + monotonic + ",fractional:" + fractional + ",subMs:" + subMs);
)JS";
  auto rt = KernelRuntime::start(sourceScript(js), hooksFor(box));
  CHECK(box.waitPosts(1, std::chrono::seconds(30)) == 1, "elapsed: no report");
  std::lock_guard<std::mutex> lock(box.m);
  CHECK(!box.posts.empty() &&
            box.posts[0].find("monotonic:true") != std::string::npos &&
            box.posts[0].find("fractional:true") != std::string::npos &&
            box.posts[0].find("subMs:true") != std::string::npos,
      "elapsed: not monotonic or no sub-ms resolution");
  rt->destroy();
  return g_failures;
}

int kernelProbe(bool bytecode, KernelProfile profile) {
  Mailbox box;
  auto rt = KernelRuntime::start(
      probeScript(qntx::harness::probes::kKernel, bytecode), hooksFor(box), profile);
  CHECK(
      box.waitPosts(2, std::chrono::seconds(180)) == 2,
      "kernel-probe: expected kernel-ready and done posts");
  {
    std::lock_guard<std::mutex> lock(box.m);
    if (box.posts.size() >= 2) {
      CHECK(box.posts[0].find("\"kernel-ready\"") != std::string::npos,
          "kernel-probe: first post was not kernel-ready");
      CHECK(box.posts[1].find("\"pass\":true") != std::string::npos,
          "kernel-probe: kernel probe failed");
      if (box.posts[1].find("\"pass\":true") == std::string::npos) {
        std::fprintf(stderr, "kernel-probe result: %s\n", box.posts[1].c_str());
      }
    }
  }
  CHECK(box.errors.empty(), "kernel-probe: unexpected onError");
  rt->destroy();
  return g_failures;
}

// Regression check for the measured timer-globals decision: Promise.then and
// async/await ride the engine microtask queue and need no globals; the
// bundled rejection tracker defers onUnhandled through the literal
// setTimeout/clearTimeout globals the prelude installs. This case re-arms the
// tracker with a posting callback and asserts the installed globals actually
// deliver it.
int measureTimers(KernelProfile profile) {
  Mailbox box;
  auto rt = KernelRuntime::start(
      sourceScript(std::string(kSendHelper) + R"JS(
Promise.resolve().then(function () { __send("then-ok"); });
(async function () { await Promise.resolve(); __send("async-ok"); })();
HermesInternal.enablePromiseRejectionTracker({
  allRejections: true,
  onUnhandled: function (id, e) { __send("unhandled"); },
  onHandled: function (id) { __send("handled"); }
});
Promise.reject(new TypeError("rejection probe"));
)JS"),
      hooksFor(box),
      profile);
  box.waitPosts(3, std::chrono::seconds(10));
  rt->destroy();
  std::lock_guard<std::mutex> lock(box.m);
  bool thenOk = false;
  bool asyncOk = false;
  bool unhandled = false;
  for (const auto& p : box.posts) {
    thenOk = thenOk || p == "then-ok";
    asyncOk = asyncOk || p == "async-ok";
    unhandled = unhandled || p == "unhandled";
  }
  CHECK(thenOk, "measure: Promise.then did not run");
  CHECK(asyncOk, "measure: async function did not run");
  CHECK(unhandled, "measure: rejection tracker never fired via setTimeout");
  CHECK(box.errors.empty(), "measure: unexpected onError");
  return g_failures;
}

} // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: RuntimeHostTest <case> [bytecode.hbc]\n");
    return 2;
  }
  const std::string testCase = argv[1];
  const char* hbcPath = argc > 2 ? argv[2] : nullptr;

  using Entry = std::function<int(const char* hbc)>;
  const Entry needHbc = [&testCase](const char*) -> int {
    std::fprintf(stderr, "%s needs a .hbc path\n", testCase.c_str());
    return 2;
  };
  const std::map<std::string, Entry> cases = {
      {"destroy-busyloop-source", [](const char*) { return destroyBusyloop(nullptr); }},
      {"destroy-busyloop-bytecode",
       [&needHbc](const char* hbc) {
         return hbc == nullptr ? needHbc(hbc) : destroyBusyloop(hbc);
       }},
      {"destroy-before-evaluate", [](const char*) { return destroyBeforeEvaluate(); }},
      {"destroy-concurrent", [](const char*) { return destroyConcurrent(); }},
      {"destroy-kdf-inflight", [](const char*) { return destroyKdfInflight(); }},
      {"timers-cancel", [](const char*) { return timersCancel(); }},
      {"timers-fired", [](const char*) { return timersFired(); }},
      {"forged-views", [](const char*) { return forgedViews(); }},
      {"numeric-validation", [](const char*) { return numericValidation(); }},
      {"random-bounds", [](const char*) { return randomBounds(); }},
      {"getrandomvalues", [](const char*) { return getRandomValuesCase(); }},
      {"crash-sync-source", [](const char*) { return crashCase(false, false); }},
      {"crash-sync-bytecode", [](const char*) { return crashCase(false, true); }},
      {"crash-promise-source", [](const char*) { return crashCase(true, false); }},
      {"crash-promise-bytecode", [](const char*) { return crashCase(true, true); }},
      {"eval-disabled-standard",
       [](const char*) { return evalDisabled(KernelProfile::standard); }},
      {"eval-disabled-hardened",
       [](const char*) { return evalDisabled(KernelProfile::hardened); }},
      {"global-descriptors", [](const char*) { return globalDescriptors(); }},
      {"global-inventory-standard",
       [](const char*) { return globalInventory(KernelProfile::standard); }},
      {"global-inventory-hardened",
       [](const char*) { return globalInventory(KernelProfile::hardened); }},
      {"textdecoder", [](const char*) { return textDecoderCase(); }},
      {"pbkdf2-vectors", [](const char*) { return pbkdf2Vectors(); }},
      {"kdf-queue-full", [](const char*) { return kdfQueueFull(); }},
      {"elapsed-monotonic", [](const char*) { return elapsedMonotonic(); }},
      {"kernel-probe-source-standard",
       [](const char*) { return kernelProbe(false, KernelProfile::standard); }},
      {"kernel-probe-bytecode-standard",
       [](const char*) { return kernelProbe(true, KernelProfile::standard); }},
      {"kernel-probe-source-hardened",
       [](const char*) { return kernelProbe(false, KernelProfile::hardened); }},
      {"kernel-probe-bytecode-hardened",
       [](const char*) { return kernelProbe(true, KernelProfile::hardened); }},
      {"measure-timers-standard",
       [](const char*) { return measureTimers(KernelProfile::standard); }},
      {"measure-timers-hardened",
       [](const char*) { return measureTimers(KernelProfile::hardened); }},
  };
  const auto found = cases.find(testCase);
  if (found == cases.end()) {
    std::fprintf(stderr, "unknown case: %s\n", testCase.c_str());
    return 2;
  }
  return found->second(hbcPath);
}
