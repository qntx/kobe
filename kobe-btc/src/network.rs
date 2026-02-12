//! Bitcoin network types.

use core::fmt;
use core::str::FromStr;

use bitcoin::Network as BtcNetwork;

/// Supported Bitcoin networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Network {
    /// Bitcoin mainnet.
    #[default]
    Mainnet,
    /// Bitcoin testnet.
    Testnet,
}

impl Network {
    /// Convert to bitcoin crate's Network type.
    #[inline]
    #[must_use]
    pub const fn to_bitcoin_network(self) -> BtcNetwork {
        match self {
            Self::Mainnet => BtcNetwork::Bitcoin,
            Self::Testnet => BtcNetwork::Testnet,
        }
    }

    /// Get the BIP44 coin type for this network.
    #[inline]
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
        }
    }

    /// Get network name as string.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Error returned when parsing an invalid network string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseNetworkError;

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid network, expected: mainnet or testnet")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {}

impl FromStr for Network {
    type Err = ParseNetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" | "bitcoin" => Ok(Self::Mainnet),
            "testnet" | "test" | "testnet3" | "testnet4" => Ok(Self::Testnet),
            _ => Err(ParseNetworkError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_from_str() {
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("main".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("test".parse::<Network>().unwrap(), Network::Testnet);
    }

    #[test]
    fn test_network_from_str_case_insensitive() {
        assert_eq!("MAINNET".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("TESTNET".parse::<Network>().unwrap(), Network::Testnet);
    }

    #[test]
    fn test_network_from_str_invalid() {
        assert!("invalid".parse::<Network>().is_err());
        assert!("".parse::<Network>().is_err());
    }

    #[test]
    fn test_network_coin_type() {
        assert_eq!(Network::Mainnet.coin_type(), 0);
        assert_eq!(Network::Testnet.coin_type(), 1);
    }

    #[test]
    fn test_network_default() {
        assert_eq!(Network::default(), Network::Mainnet);
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Testnet.to_string(), "testnet");
    }
}
