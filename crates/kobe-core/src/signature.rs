//! Signature container shared by the curve signers.

/// Compact recoverable ECDSA signature: `r || s` plus the raw recovery
/// parity.
///
/// `recovery` is always `0` or `1` — chain wire formats that add an offset
/// (EIP-191/712 `27`, BIP-137 header bytes) encode it in the chain module,
/// never here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// `r || s` (64 bytes).
    pub signature: [u8; 64],
    /// Recovery parity; always `0` or `1`.
    pub recovery: u8,
}

impl RecoverableSignature {
    /// `r || s || recovery` (65 bytes).
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "the 65-byte buffer is split at fixed offsets by construction"
    )]
    pub fn to_bytes(self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&self.signature);
        out[64] = self.recovery;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_bytes_is_r_s_v_65() {
        let out = RecoverableSignature {
            signature: [0xAB; 64],
            recovery: 1,
        };
        let bytes = out.to_bytes();
        assert_eq!(bytes.len(), 65);
        let (head, tail) = bytes.split_at(64);
        assert!(head.iter().all(|&b| b == 0xAB));
        assert_eq!(tail, [1]);
    }
}
