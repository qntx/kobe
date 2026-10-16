/**
 * Q5 probe: a long-lived kernel that performs blocking work on demand so the JS side can
 * sample main-thread lag while the kernel is busy. On "kdf" it runs a 600,000-iteration
 * PBKDF2-SHA256 (32-byte output) on the KDF worker thread and posts when done; on "spin" it
 * busy-loops for 2000 ms on the kernel thread (measured on __qntx.elapsed) and posts.
 * Everything else is echoed back so the probe also works as a round-trip endpoint.
 */
import { postJson, utf8Encode } from "./share";

__qntx.setMessageHandler((message) => {
  const text = new TextDecoder().decode(message);
  if (text === "kdf") {
    __qntx.pbkdf2("sha256", utf8Encode("v1-busy"), utf8Encode("v1-busy-salt"), 600_000, 32, (result, error) => {
      postJson({ kind: "work-done", work: "kdf", ok: error === undefined && result !== undefined });
    });
  } else if (text === "spin") {
    const until = __qntx.elapsed() + 2000;
    while (__qntx.elapsed() < until) {
      // busy loop
    }
    postJson({ kind: "work-done", work: "spin" });
  } else {
    __qntx.post(message);
  }
});

postJson({ ready: true });
