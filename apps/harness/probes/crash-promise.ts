// TypeError is on Hermes' rejection-tracker whitelist, so onUnhandled is
// delivered after ~100 ms instead of the default 2 s — the host test asserts
// the runtime reports the crash and stops within one second.
Promise.reject(new TypeError("v1 crash-promise probe: unhandled rejection"));
