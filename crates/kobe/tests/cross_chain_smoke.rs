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
        // Cross-checked in kobe-evm KAT (iancoleman / MetaMask Standard path).
        assert_eq!(a.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn svm() {
        let w = wallet();
        let a = kobe::svm::Deriver::new(&w).derive(0).unwrap();
        // Phantom Standard path KAT in kobe-svm.
        assert_eq!(a.address(), "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
        assert!(!a.keypair_base58().is_empty());
    }

    #[test]
    fn cosmos() {
        let w = wallet();
        let a = kobe::cosmos::Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address(), "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
    }

    #[test]
    fn tron() {
        let w = wallet();
        let a = kobe::tron::Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address(), "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
    }

    #[test]
    fn spark() {
        let w = wallet();
        let a = kobe::spark::Deriver::new(&w).derive(0).unwrap();
        assert_eq!(
            a.address(),
            "spark1pgssy6vty7krpze82ecm8j39gd35v35aqjjmhftc4culawsavkyh564uc6zmqs"
        );
    }

    #[test]
    fn fil() {
        let w = wallet();
        let a = kobe::fil::Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address(), "f1qode47ievxlxzk6z2viuovedabmn3tq6t57uqhq");
    }

    #[test]
    fn ton() {
        let w = wallet();
        let a = kobe::ton::Deriver::new(&w).derive(0).unwrap();
        // Default: mainnet, non-bounceable, workchain 0.
        assert_eq!(
            a.address(),
            "UQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLtaT"
        );
    }

    #[test]
    fn sui() {
        let w = wallet();
        let a = kobe::sui::Deriver::new(&w).derive(0).unwrap();
        assert_eq!(
            a.address(),
            "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1"
        );
    }

    #[test]
    fn aptos() {
        let w = wallet();
        let a = kobe::aptos::Deriver::new(&w).derive(0).unwrap();
        assert_eq!(
            a.address(),
            "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf"
        );
    }

    #[test]
    fn nostr() {
        let w = wallet();
        // NIP-06 abandon vectors differ; smoke only checks encoding shape here
        // when using the shared abandon mnemonic (not NIP official TV mnemonics).
        let a = kobe::nostr::Deriver::new(&w).derive(0).unwrap();
        assert!(a.npub().starts_with("npub1"));
        assert!(a.nsec().starts_with("nsec1"));
    }

    #[test]
    fn xrpl() {
        let w = wallet();
        let a = kobe::xrpl::Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address(), "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3");
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
