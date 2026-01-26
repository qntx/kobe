//! Bitcoin address implementation.

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::network::Network;
use crate::public_key::BtcPublicKey;
use kobe::hash::double_sha256;
use kobe::{Error, Result};

/// Bitcoin address format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressFormat {
    /// Legacy Pay-to-Public-Key-Hash (P2PKH) - starts with 1 or m/n
    P2PKH,
    /// Pay-to-Script-Hash (P2SH) - starts with 3 or 2
    P2SH,
    /// Nested SegWit P2SH-P2WPKH - starts with 3 or 2
    P2SHP2WPKH,
    /// Native SegWit P2WPKH (Bech32) - starts with bc1q or tb1q
    P2WPKH,
    /// Native SegWit P2WSH (Bech32) - starts with bc1q or tb1q
    P2WSH,
    /// Taproot (Bech32m) - starts with bc1p or tb1p
    P2TR,
}

/// Bitcoin address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcAddress {
    /// The address data (hash160 for most formats, 32 bytes for taproot)
    data: [u8; 32],
    /// Length of valid data
    data_len: usize,
    /// Network
    network: Network,
    /// Address format
    format: AddressFormat,
}

impl BtcAddress {
    /// Create a P2PKH address from a public key.
    pub fn from_public_key(
        public_key: &BtcPublicKey,
        network: Network,
        format: AddressFormat,
    ) -> Result<Self> {
        match format {
            AddressFormat::P2PKH => {
                let hash = public_key.hash160();
                let mut data = [0u8; 32];
                data[..20].copy_from_slice(&hash);
                Ok(Self {
                    data,
                    data_len: 20,
                    network,
                    format,
                })
            }
            AddressFormat::P2WPKH => {
                if !public_key.is_compressed() {
                    return Err(Error::msg("P2WPKH requires compressed public key"));
                }
                let hash = public_key.hash160();
                let mut data = [0u8; 32];
                data[..20].copy_from_slice(&hash);
                Ok(Self {
                    data,
                    data_len: 20,
                    network,
                    format,
                })
            }
            AddressFormat::P2SHP2WPKH => {
                if !public_key.is_compressed() {
                    return Err(Error::msg("P2SH-P2WPKH requires compressed public key"));
                }
                // Build redeem script: OP_0 <20-byte-key-hash>
                let keyhash = public_key.hash160();
                let mut redeem_script = [0u8; 22];
                redeem_script[0] = 0x00; // OP_0 (witness version)
                redeem_script[1] = 0x14; // Push 20 bytes
                redeem_script[2..22].copy_from_slice(&keyhash);

                // Hash the redeem script
                let script_hash = kobe::hash::hash160(&redeem_script);
                let mut data = [0u8; 32];
                data[..20].copy_from_slice(&script_hash);
                Ok(Self {
                    data,
                    data_len: 20,
                    network,
                    format: AddressFormat::P2SH, // Display as P2SH
                })
            }
            AddressFormat::P2TR => {
                // BIP-341 Taproot: use x-only public key (32 bytes)
                // For key-path only spending, the output key is the internal key
                let x_only = public_key.to_x_only();
                let mut data = [0u8; 32];
                data.copy_from_slice(&x_only);
                Ok(Self {
                    data,
                    data_len: 32,
                    network,
                    format,
                })
            }
            _ => Err(Error::UnsupportedOperation),
        }
    }

    /// Create from hash160 (20 bytes).
    pub fn from_hash160(hash: [u8; 20], network: Network, format: AddressFormat) -> Self {
        let mut data = [0u8; 32];
        data[..20].copy_from_slice(&hash);
        Self {
            data,
            data_len: 20,
            network,
            format,
        }
    }

    /// Get the network.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Get the format.
    pub const fn format(&self) -> AddressFormat {
        self.format
    }

    /// Get the hash data.
    pub fn hash(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Encode as Base58Check string (for P2PKH and P2SH).
    #[cfg(feature = "alloc")]
    fn to_base58check(&self) -> String {
        let prefix = match self.format {
            AddressFormat::P2PKH => self.network.p2pkh_prefix(),
            AddressFormat::P2SH | AddressFormat::P2SHP2WPKH => self.network.p2sh_prefix(),
            _ => panic!("Base58Check only for P2PKH/P2SH"),
        };

        let mut data = Vec::with_capacity(25);
        data.push(prefix);
        data.extend_from_slice(&self.data[..20]);

        let checksum = double_sha256(&data);
        data.extend_from_slice(&checksum[..4]);

        bs58::encode(data).into_string()
    }

    /// Encode as Bech32/Bech32m string (for SegWit).
    #[cfg(feature = "alloc")]
    fn to_bech32(&self) -> Result<String> {
        use bech32::Hrp;

        let hrp = Hrp::parse(self.network.bech32_hrp()).map_err(|_| Error::InvalidEncoding)?;

        // Use segwit encoding which properly handles witness version and checksum variant
        let encoded = match self.format {
            AddressFormat::P2TR => {
                bech32::segwit::encode(hrp, bech32::segwit::VERSION_1, &self.data[..self.data_len])
            }
            AddressFormat::P2WPKH | AddressFormat::P2WSH => {
                bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &self.data[..self.data_len])
            }
            _ => return Err(Error::msg("invalid format for bech32")),
        }
        .map_err(|_| Error::InvalidEncoding)?;

        Ok(encoded)
    }
}

impl core::fmt::Display for BtcAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "alloc")]
        {
            let s = match self.format {
                AddressFormat::P2PKH | AddressFormat::P2SH | AddressFormat::P2SHP2WPKH => {
                    self.to_base58check()
                }
                AddressFormat::P2WPKH | AddressFormat::P2WSH | AddressFormat::P2TR => {
                    self.to_bech32().unwrap_or_else(|_| String::from("invalid"))
                }
            };
            write!(f, "{}", s)
        }
        #[cfg(not(feature = "alloc"))]
        {
            write!(f, "BtcAddress({:?})", self.format)
        }
    }
}

#[cfg(feature = "alloc")]
impl core::str::FromStr for BtcAddress {
    type Err = Error;

    /// Parse a Bitcoin address from string.
    fn from_str(s: &str) -> Result<Self> {
        // Try Bech32/Bech32m first (bc1... or tb1...)
        if s.starts_with("bc1")
            || s.starts_with("tb1")
            || s.starts_with("BC1")
            || s.starts_with("TB1")
        {
            return Self::from_bech32(s);
        }

        // Try Base58Check
        Self::from_base58check(s)
    }
}

#[cfg(feature = "alloc")]
impl BtcAddress {
    /// Parse from Base58Check encoded address.
    fn from_base58check(s: &str) -> Result<Self> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::InvalidEncoding)?;

        if decoded.len() != 25 {
            return Err(Error::InvalidLength {
                expected: 25,
                actual: decoded.len(),
            });
        }

        // Verify checksum
        let checksum = &decoded[21..];
        let computed = double_sha256(&decoded[..21]);
        if checksum != &computed[..4] {
            return Err(Error::InvalidChecksum);
        }

        // Parse version byte
        let (network, format) = match decoded[0] {
            0x00 => (Network::Mainnet, AddressFormat::P2PKH),
            0x05 => (Network::Mainnet, AddressFormat::P2SH),
            0x6f => (Network::Testnet, AddressFormat::P2PKH),
            0xc4 => (Network::Testnet, AddressFormat::P2SH),
            _ => return Err(Error::msg("unknown address version")),
        };

        let mut data = [0u8; 32];
        data[..20].copy_from_slice(&decoded[1..21]);

        Ok(Self {
            data,
            data_len: 20,
            network,
            format,
        })
    }

    /// Parse from Bech32/Bech32m encoded address.
    fn from_bech32(s: &str) -> Result<Self> {
        // Use segwit::decode which properly handles witness version and program
        let (hrp, witness_version, witness_program) =
            bech32::segwit::decode(s).map_err(|_| Error::InvalidEncoding)?;

        // Parse HRP to determine network
        let network = match hrp.as_str() {
            "bc" => Network::Mainnet,
            "tb" => Network::Testnet,
            _ => return Err(Error::msg("unknown bech32 HRP")),
        };

        // Get witness version as u8
        let version = witness_version.to_u8();

        // Determine format based on witness version and program length
        let (format, expected_len) = match (version, witness_program.len()) {
            (0, 20) => (AddressFormat::P2WPKH, 20),
            (0, 32) => (AddressFormat::P2WSH, 32),
            (1, 32) => (AddressFormat::P2TR, 32),
            _ => return Err(Error::msg("invalid witness program")),
        };

        let mut addr_data = [0u8; 32];
        addr_data[..expected_len].copy_from_slice(&witness_program);

        Ok(Self {
            data: addr_data,
            data_len: expected_len,
            network,
            format,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BtcPrivateKey;

    #[test]
    fn test_p2pkh_address() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let addr = key.address(Network::Mainnet, AddressFormat::P2PKH).unwrap();
        assert_eq!(addr.to_string(), "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK");
    }

    #[test]
    fn test_p2wpkh_address() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let addr = key
            .address(Network::Mainnet, AddressFormat::P2WPKH)
            .unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("bc1q"));
    }

    #[test]
    fn test_p2sh_p2wpkh_address() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let addr = key
            .address(Network::Mainnet, AddressFormat::P2SHP2WPKH)
            .unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with('3')); // Mainnet P2SH starts with 3
    }

    #[test]
    fn test_parse_p2pkh_address() {
        let addr: BtcAddress = "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK".parse().unwrap();
        assert_eq!(addr.network(), Network::Mainnet);
        assert_eq!(addr.format(), AddressFormat::P2PKH);
    }

    #[test]
    fn test_parse_p2sh_address() {
        let addr: BtcAddress = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".parse().unwrap();
        assert_eq!(addr.network(), Network::Mainnet);
        assert_eq!(addr.format(), AddressFormat::P2SH);
    }

    #[test]
    fn test_parse_bech32_address() {
        // Generate an address and test roundtrip parsing
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let addr = key
            .address(Network::Mainnet, AddressFormat::P2WPKH)
            .unwrap();
        let addr_str = addr.to_string();

        // Parse it back
        let parsed: BtcAddress = addr_str.parse().unwrap();
        assert_eq!(parsed.network(), Network::Mainnet);
        assert_eq!(parsed.format(), AddressFormat::P2WPKH);
        assert_eq!(parsed.to_string(), addr_str);
    }

    #[test]
    fn test_address_roundtrip_p2pkh() {
        let original = "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK";
        let addr: BtcAddress = original.parse().unwrap();
        assert_eq!(addr.to_string(), original);
    }

    #[test]
    fn test_testnet_address() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let addr = key.address(Network::Testnet, AddressFormat::P2PKH).unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with('m') || addr_str.starts_with('n'));
    }

    #[test]
    fn test_p2tr_taproot_address() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let addr = key.address(Network::Mainnet, AddressFormat::P2TR).unwrap();
        let addr_str = addr.to_string();
        // P2TR addresses start with bc1p on mainnet
        assert!(
            addr_str.starts_with("bc1p"),
            "Expected bc1p prefix, got: {}",
            addr_str
        );
        assert_eq!(addr.format(), AddressFormat::P2TR);
    }

    #[test]
    fn test_p2tr_roundtrip() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let addr = key.address(Network::Mainnet, AddressFormat::P2TR).unwrap();
        let addr_str = addr.to_string();

        // Parse it back
        let parsed: BtcAddress = addr_str.parse().unwrap();
        assert_eq!(parsed.network(), Network::Mainnet);
        assert_eq!(parsed.format(), AddressFormat::P2TR);
        assert_eq!(parsed.to_string(), addr_str);
    }
}
