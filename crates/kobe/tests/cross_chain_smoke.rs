//! Cross-chain smoke: one abandon mnemonic, derive(0) on every enabled chain.
//!
//! Run: `cargo test -p kobe --all-features --test cross_chain_smoke`

#![cfg(feature = "all-chains")]
// Integration tests inherit the umbrella package's optional chain crates;
// usage goes through `kobe::*` re-exports, so the lint is noise here.
#![allow(
    unused_crate_dependencies,
    reason = "chains are used via kobe::* re-exports, not as direct crate roots"
)]

// Clippy's `tests_outside_test_module` is aimed at unit tests in `src/`;
// integration tests under `tests/` are already a dedicated test crate.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "smoke tests intentionally panic on setup / derive failures"
)]
mod smoke {
    use kobe::Wallet;
    use kobe::prelude::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC, None).unwrap()
    }

    #[test]
    fn btc_default_p2wpkh() {
        let w = wallet();
        let a = kobe::btc::Deriver::new(&w, kobe::btc::Network::Mainnet)
            .derive(0)
            .unwrap();
        assert_eq!(a.address(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn evm() {
        let w = wallet();
        let a = kobe::evm::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with("0x"));
        assert_eq!(a.address().len(), 42);
    }

    #[test]
    fn svm() {
        let w = wallet();
        let a = kobe::svm::Deriver::new(&w).derive(0).unwrap();
        assert!(!a.address().is_empty());
        assert!(!a.keypair_base58().is_empty());
    }

    #[test]
    fn cosmos() {
        let w = wallet();
        let a = kobe::cosmos::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with("cosmos1"));
    }

    #[test]
    fn tron() {
        let w = wallet();
        let a = kobe::tron::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with('T'));
    }

    #[test]
    fn spark() {
        let w = wallet();
        let a = kobe::spark::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with("spark"));
    }

    #[test]
    fn fil() {
        let w = wallet();
        let a = kobe::fil::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with("f1"));
    }

    #[test]
    fn ton() {
        let w = wallet();
        let a = kobe::ton::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with('U') || a.address().starts_with('E'));
    }

    #[test]
    fn sui() {
        let w = wallet();
        let a = kobe::sui::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with("0x"));
    }

    #[test]
    fn aptos() {
        let w = wallet();
        let a = kobe::aptos::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with("0x"));
    }

    #[test]
    fn nostr() {
        let w = wallet();
        let a = kobe::nostr::Deriver::new(&w).derive(0).unwrap();
        assert!(a.npub().starts_with("npub1"));
        assert!(a.nsec().starts_with("nsec1"));
    }

    #[test]
    fn xrpl() {
        let w = wallet();
        let a = kobe::xrpl::Deriver::new(&w).derive(0).unwrap();
        assert!(a.address().starts_with('r'));
    }

    #[test]
    fn derive_many_agrees() {
        let w = wallet();
        let d = kobe::evm::Deriver::new(&w);
        let batch = d.derive_many(0, 3).unwrap();
        for (i, acct) in batch.iter().enumerate() {
            assert_eq!(
                acct.address(),
                d.derive(u32::try_from(i).unwrap()).unwrap().address()
            );
        }
    }
}
