//! Owned 32-byte secret key material shared by the curve signers.

use zeroize::Zeroizing;

use crate::{DerivedAccount, Error};

/// Owned 32-byte secret key (zeroized on drop).
///
/// Bytes are never exposed through `Debug`; the only views are
/// [`as_bytes`](Self::as_bytes) and the one-shot copies handed to signer
/// constructors.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    /// Wrap raw secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Input`] if `bytes` is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::Input(alloc::format!(
                "expected 32-byte secret key, got {} bytes",
                bytes.len()
            ))
        })?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// Copy the 32-byte private key of a derived HD account.
    #[must_use]
    pub fn from_account(account: &DerivedAccount) -> Self {
        Self(Zeroizing::new(**account.private_key_bytes()))
    }

    /// Sample a fresh secret from a caller-supplied cryptographic RNG.
    ///
    /// Mirrors [`Wallet::generate_with`](crate::Wallet::generate_with): in
    /// `no_std` environments the caller provides the CSPRNG. The 32-byte
    /// string is stored verbatim — curve validity is the signer's concern
    /// (secp256k1 rejects out-of-range scalars, Ed25519 accepts all).
    #[must_use]
    pub fn generate_with<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + ?Sized,
    {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    /// Sample a fresh secret from OS entropy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the OS RNG fails.
    ///
    /// # Note
    ///
    /// This function requires the `os-rng` feature to be enabled.
    #[cfg(feature = "os-rng")]
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut_slice())
            .map_err(|e| Error::Crypto(alloc::format!("os rng failed: {e}")))?;
        Ok(Self(bytes))
    }

    /// Borrow the inner 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;
    use crate::DerivedPublicKey;

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(matches!(
            SecretKey::from_bytes(&[0u8; 31]),
            Err(Error::Input(_))
        ));
        assert!(matches!(
            SecretKey::from_bytes(&[0u8; 33]),
            Err(Error::Input(_))
        ));
        assert!(SecretKey::from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn round_trip_as_bytes() {
        let bytes = [0xAB; 32];
        let key = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn from_account_copies_private_key() {
        let account = DerivedAccount::new(
            "m/0'".to_owned(),
            Zeroizing::new([0x42; 32]),
            DerivedPublicKey::Ed25519([0xAB; 32]),
            "addr".to_owned(),
        );
        let key = SecretKey::from_account(&account);
        assert_eq!(key.as_bytes(), &[0x42; 32]);
    }

    #[test]
    fn generate_with_fills_secret() {
        struct ZeroRng;
        impl rand_core::TryRng for ZeroRng {
            type Error = rand_core::Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }

            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                dst.fill(0x5A);
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for ZeroRng {}

        let mut rng = ZeroRng;
        let key = SecretKey::generate_with(&mut rng);
        assert_eq!(key.as_bytes(), &[0x5A; 32]);
    }

    #[test]
    fn debug_and_clone_do_not_leak_material() {
        let key = SecretKey::from_bytes(&[0x7E; 32]).unwrap();
        let debug = format!("{key:?}");
        assert_eq!(debug, "SecretKey([REDACTED])");
        let clone = key.clone();
        assert_eq!(clone.as_bytes(), key.as_bytes());
    }
}
