//! Seeded property tests for the v1 envelope: round-trips, single-byte
//! tampering, and context mismatch.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed test state must fail loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "test-only byte offsets are bounds-checked by construction"
)]

use kobe_vault::{open, seal};

/// `SplitMix64`: a deterministic seeded RNG for tests (not for production).
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(n);
        out
    }
}

impl rand_core::TryRng for SplitMix64 {
    type Error = rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.next().to_le_bytes()[..4]);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let bytes = self.bytes(dst.len());
        dst.copy_from_slice(&bytes);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SplitMix64 {}

/// `open`'s outcome as the shared error-code string (or `<no error>`).
fn open_code(key: &[u8], sealed: &[u8], context: &str) -> &'static str {
    match open(key, sealed, context) {
        Ok(_) => "<no error>",
        Err(e) => e.code().as_str(),
    }
}

#[test]
fn seal_open_round_trip() {
    let mut rng = SplitMix64::new(0x5eed);
    for i in 0..64usize {
        let key = rng.bytes(32);
        let plaintext_len = usize::try_from(rng.next() % 129).unwrap_or(0);
        let plaintext = rng.bytes(plaintext_len);
        let context = format!("ctx/{i}/{}", rng.next());
        let sealed = seal(&key, &plaintext, &context, &mut rng)
            .unwrap_or_else(|e| panic!("iteration {i}: seal failed: {e}"));
        let opened = open(&key, &sealed, &context)
            .unwrap_or_else(|e| panic!("iteration {i}: open failed: {e}"));
        assert_eq!(opened.as_slice(), plaintext.as_slice(), "iteration {i}");
    }
}

#[test]
fn flipping_any_byte_fails() {
    let mut rng = SplitMix64::new(0xf11f);
    let key = rng.bytes(32);
    let plaintext = rng.bytes(48);
    let context = "kobe/test/v1/test/data";
    let sealed =
        seal(&key, &plaintext, context, &mut rng).unwrap_or_else(|e| panic!("seal failed: {e}"));

    for i in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[i] ^= 0x01;
        let expected = if i == 0 { "version" } else { "decrypt" };
        assert_eq!(open_code(&key, &tampered, context), expected, "byte {i}");
    }
}

#[test]
fn context_mismatch_fails_with_decrypt() {
    let mut rng = SplitMix64::new(0xc0_ffee);
    let key = rng.bytes(32);
    let plaintext = rng.bytes(24);
    let sealed = seal(&key, &plaintext, "kobe/test/v1/a/data", &mut rng)
        .unwrap_or_else(|e| panic!("seal failed: {e}"));
    assert_eq!(open_code(&key, &sealed, "kobe/test/v1/b/data"), "decrypt");
}
