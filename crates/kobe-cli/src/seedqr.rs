//! `SeedQR` QR construction: `standard` numeric and `compact` byte
//! segments at the spec's fixed versions, ECC L.

use kobe::Wallet;
use qrcode::{EcLevel, QrCode, Version, bits::Bits};

use crate::CliResult;

/// `SeedQR` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeedQrKind {
    Standard,
    Compact,
}

impl SeedQrKind {
    /// CLI value for `--seedqr <kind>` (default when bare: `standard`).
    pub(crate) fn parse(s: &str) -> CliResult<Self> {
        match s {
            "standard" => Ok(Self::Standard),
            "compact" => Ok(Self::Compact),
            other => Err(format!(
                "invalid --seedqr format {other:?} (expected: standard, compact)"
            )
            .into()),
        }
    }
}

fn version(kind: SeedQrKind, words: usize) -> CliResult<Version> {
    let v = match (kind, words) {
        (SeedQrKind::Standard, 12) | (SeedQrKind::Compact, 24) => 2,
        (SeedQrKind::Standard, 24) => 3,
        (SeedQrKind::Compact, 12) => 1,
        (_, n) => {
            return Err(format!("SeedQR supports only 12 or 24 words, got {n}").into());
        }
    };
    Ok(Version::Normal(v))
}

/// Build the `SeedQR` for `wallet`'s mnemonic. Payloads come from
/// `kobe::seedqr` (zeroized); the segment is written explicitly so the
/// encoder cannot re-pack digits-looking bytes as a numeric segment.
pub(crate) fn encode(wallet: &Wallet, kind: SeedQrKind) -> CliResult<QrCode> {
    let words = wallet.mnemonic().split_whitespace().count();
    let version = version(kind, words)?;
    let mut bits = Bits::new(version);
    match kind {
        SeedQrKind::Standard => {
            let digits = kobe::seedqr::standard(wallet)?;
            bits.push_numeric_data(digits.as_bytes())
                .map_err(|e| format!("SeedQR encode: {e}"))?;
        }
        SeedQrKind::Compact => {
            let entropy = kobe::seedqr::compact(wallet)?;
            bits.push_byte_data(&entropy)
                .map_err(|e| format!("SeedQR encode: {e}"))?;
        }
    }
    bits.push_terminator(EcLevel::L)
        .map_err(|e| format!("SeedQR encode: {e}"))?;
    QrCode::with_bits(bits, EcLevel::L).map_err(|e| format!("SeedQR encode: {e}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../../vectors/seedqr.json");

    /// Prepare `code`'s matrix as a greyscale image with a 2-module
    /// quiet zone, detect the grid, and decode it to raw bytes.
    fn decode_to_bytes(code: &QrCode) -> Vec<u8> {
        const Q: usize = 2;
        let w = code.width();
        let colors = code.to_colors();
        let size = w + Q * 2;
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(size, size, |x, y| {
            let dark = x >= Q
                && y >= Q
                && x - Q < w
                && y - Q < w
                && colors.get((y - Q) * w + (x - Q)) == Some(&qrcode::Color::Dark);
            if dark { 0 } else { 255 }
        });
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1);
        let mut bytes = Vec::new();
        grids
            .first()
            .expect("grid")
            .decode_to(&mut bytes)
            .expect("decode");
        bytes
    }

    fn vector_cases(v: &serde_json::Value) -> [(SeedQrKind, i16, String); 2] {
        [
            (
                SeedQrKind::Standard,
                i16::try_from(v["standard_version"].as_u64().expect("v")).expect("v"),
                v["standard"].as_str().expect("digits").replace(' ', ""),
            ),
            (
                SeedQrKind::Compact,
                i16::try_from(v["compact_version"].as_u64().expect("v")).expect("v"),
                v["compact"].as_str().expect("entropy").to_owned(),
            ),
        ]
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .filter_map(|i| hex.get(i..i + 2))
            .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
            .collect()
    }

    fn check_case(wallet: &Wallet, phrase: &str, kind: SeedQrKind, version: i16, payload: &str) {
        let code = encode(wallet, kind).expect("encode");
        assert_eq!(code.error_correction_level(), EcLevel::L, "{phrase}");
        assert_eq!(code.version(), Version::Normal(version), "{phrase}");
        let bytes = decode_to_bytes(&code);
        if kind == SeedQrKind::Standard {
            assert_eq!(
                String::from_utf8_lossy(&bytes).as_ref(),
                payload,
                "digits for {phrase}"
            );
        } else {
            assert_eq!(bytes, hex_bytes(payload), "entropy for {phrase}");
        }
    }

    #[test]
    fn all_vectors_decode_to_payload() {
        let file: serde_json::Value = serde_json::from_str(VECTORS).expect("json");
        let list = file
            .get("vectors")
            .and_then(|v| v.as_array())
            .expect("vectors");
        assert_eq!(list.len(), 9);
        for v in list {
            let phrase = v.get("phrase").and_then(|p| p.as_str()).expect("phrase");
            let wallet = Wallet::from_mnemonic(phrase, "").expect("wallet");
            for (kind, version, payload) in vector_cases(v) {
                check_case(&wallet, phrase, kind, version, &payload);
            }
        }
    }
}
