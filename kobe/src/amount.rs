//! Cryptocurrency amount types and denominations.
//!
//! Provides concrete implementations of the `Amount` trait for Bitcoin and Ethereum.

use crate::traits::Amount;
use core::fmt;
use core::ops::{Add, Div, Mul, Sub};

/// Bitcoin denomination units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BitcoinDenomination {
    /// Satoshi (base unit)
    Satoshi,
    /// Micro Bitcoin (μBTC) = 100 satoshis
    MicroBit,
    /// Milli Bitcoin (mBTC) = 100,000 satoshis
    MilliBit,
    /// Centi Bitcoin (cBTC) = 1,000,000 satoshis
    CentiBit,
    /// Deci Bitcoin (dBTC) = 10,000,000 satoshis
    DeciBit,
    /// Bitcoin (BTC) = 100,000,000 satoshis
    Bitcoin,
}

impl BitcoinDenomination {
    /// Get the precision (decimal places relative to satoshi).
    pub const fn precision(&self) -> u32 {
        match self {
            Self::Satoshi => 0,
            Self::MicroBit => 2,
            Self::MilliBit => 5,
            Self::CentiBit => 6,
            Self::DeciBit => 7,
            Self::Bitcoin => 8,
        }
    }

    /// Get the multiplier relative to satoshi.
    pub const fn multiplier(&self) -> u64 {
        match self {
            Self::Satoshi => 1,
            Self::MicroBit => 100,
            Self::MilliBit => 100_000,
            Self::CentiBit => 1_000_000,
            Self::DeciBit => 10_000_000,
            Self::Bitcoin => 100_000_000,
        }
    }

    /// Get the symbol for this denomination.
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Satoshi => "sat",
            Self::MicroBit => "μBTC",
            Self::MilliBit => "mBTC",
            Self::CentiBit => "cBTC",
            Self::DeciBit => "dBTC",
            Self::Bitcoin => "BTC",
        }
    }
}

impl fmt::Display for BitcoinDenomination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

/// Bitcoin amount in satoshis.
///
/// 1 BTC = 100,000,000 satoshis
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Satoshi(u64);

impl Satoshi {
    /// Zero satoshis.
    pub const ZERO: Self = Self(0);

    /// One satoshi.
    pub const ONE: Self = Self(1);

    /// One Bitcoin in satoshis.
    pub const ONE_BTC: Self = Self(100_000_000);

    /// Maximum supply of Bitcoin in satoshis (21 million BTC).
    pub const MAX_SUPPLY: Self = Self(21_000_000 * 100_000_000);

    /// Create from satoshis.
    pub const fn new(satoshis: u64) -> Self {
        Self(satoshis)
    }

    /// Create from BTC.
    pub fn from_btc(btc: f64) -> Self {
        Self::from_main_units(btc)
    }

    /// Convert to BTC.
    pub fn to_btc(&self) -> f64 {
        self.to_main_units()
    }

    /// Get the raw satoshi value.
    pub const fn as_sat(&self) -> u64 {
        self.0
    }

    /// Create from a value in the specified denomination.
    pub fn from_denomination(value: u64, denom: BitcoinDenomination) -> Self {
        Self(value.saturating_mul(denom.multiplier()))
    }

    /// Convert to a value in the specified denomination.
    pub fn to_denomination(&self, denom: BitcoinDenomination) -> f64 {
        self.0 as f64 / denom.multiplier() as f64
    }

    /// Create from mBTC (milli-bitcoin).
    pub fn from_mbtc(mbtc: f64) -> Self {
        Self((mbtc * BitcoinDenomination::MilliBit.multiplier() as f64) as u64)
    }

    /// Convert to mBTC (milli-bitcoin).
    pub fn to_mbtc(&self) -> f64 {
        self.to_denomination(BitcoinDenomination::MilliBit)
    }

    /// Create from μBTC (micro-bitcoin).
    pub fn from_ubtc(ubtc: f64) -> Self {
        Self((ubtc * BitcoinDenomination::MicroBit.multiplier() as f64) as u64)
    }

    /// Convert to μBTC (micro-bitcoin).
    pub fn to_ubtc(&self) -> f64 {
        self.to_denomination(BitcoinDenomination::MicroBit)
    }

    /// Check if amount exceeds Bitcoin max supply.
    pub fn exceeds_max_supply(&self) -> bool {
        self.0 > Self::MAX_SUPPLY.0
    }
}

impl Amount for Satoshi {
    const DECIMALS: u8 = 8;
    const SYMBOL: &'static str = "BTC";

    fn from_base_units(value: u64) -> Self {
        Self(value)
    }

    fn to_base_units(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Satoshi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 100_000_000 {
            write!(f, "{:.8} BTC", self.to_btc())
        } else if self.0 >= 1000 {
            write!(f, "{} sats", self.0)
        } else {
            write!(f, "{} sat", self.0)
        }
    }
}

impl Add for Satoshi {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl Sub for Satoshi {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl Mul<u64> for Satoshi {
    type Output = Self;
    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_mul(rhs))
    }
}

impl Div<u64> for Satoshi {
    type Output = Self;
    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl From<u64> for Satoshi {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Satoshi> for u64 {
    fn from(value: Satoshi) -> Self {
        value.0
    }
}

/// Ethereum denomination units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EthereumDenomination {
    /// Wei (base unit)
    Wei,
    /// Kwei = 10^3 wei
    Kwei,
    /// Mwei = 10^6 wei
    Mwei,
    /// Gwei = 10^9 wei (commonly used for gas prices)
    Gwei,
    /// Szabo = 10^12 wei
    Szabo,
    /// Finney = 10^15 wei
    Finney,
    /// Ether = 10^18 wei
    Ether,
}

impl EthereumDenomination {
    /// Get the precision (decimal places relative to wei).
    pub const fn precision(&self) -> u32 {
        match self {
            Self::Wei => 0,
            Self::Kwei => 3,
            Self::Mwei => 6,
            Self::Gwei => 9,
            Self::Szabo => 12,
            Self::Finney => 15,
            Self::Ether => 18,
        }
    }

    /// Get the multiplier relative to wei.
    pub const fn multiplier(&self) -> u128 {
        match self {
            Self::Wei => 1,
            Self::Kwei => 1_000,
            Self::Mwei => 1_000_000,
            Self::Gwei => 1_000_000_000,
            Self::Szabo => 1_000_000_000_000,
            Self::Finney => 1_000_000_000_000_000,
            Self::Ether => 1_000_000_000_000_000_000,
        }
    }

    /// Get the symbol for this denomination.
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Wei => "wei",
            Self::Kwei => "kwei",
            Self::Mwei => "mwei",
            Self::Gwei => "gwei",
            Self::Szabo => "szabo",
            Self::Finney => "finney",
            Self::Ether => "ETH",
        }
    }
}

impl fmt::Display for EthereumDenomination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

/// Ethereum amount in wei.
///
/// 1 ETH = 10^18 wei
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Wei(u128);

impl Wei {
    /// Zero wei.
    pub const ZERO: Self = Self(0);

    /// One wei.
    pub const ONE: Self = Self(1);

    /// One Gwei in wei (10^9).
    pub const ONE_GWEI: Self = Self(1_000_000_000);

    /// One Ether in wei (10^18).
    pub const ONE_ETH: Self = Self(1_000_000_000_000_000_000);

    /// Create from wei.
    pub const fn new(wei: u128) -> Self {
        Self(wei)
    }

    /// Create from Gwei.
    pub fn from_gwei(gwei: f64) -> Self {
        Self((gwei * 1_000_000_000.0) as u128)
    }

    /// Create from ETH.
    pub fn from_eth(eth: f64) -> Self {
        Self((eth * 1_000_000_000_000_000_000.0) as u128)
    }

    /// Convert to Gwei.
    pub fn to_gwei(&self) -> f64 {
        self.0 as f64 / 1_000_000_000.0
    }

    /// Convert to ETH.
    pub fn to_eth(&self) -> f64 {
        self.0 as f64 / 1_000_000_000_000_000_000.0
    }

    /// Get the raw wei value.
    pub const fn as_wei(&self) -> u128 {
        self.0
    }

    /// Create from a value in the specified denomination.
    pub fn from_denomination(value: u128, denom: EthereumDenomination) -> Self {
        Self(value.saturating_mul(denom.multiplier()))
    }

    /// Convert to a value in the specified denomination.
    pub fn to_denomination(&self, denom: EthereumDenomination) -> f64 {
        self.0 as f64 / denom.multiplier() as f64
    }

    /// Create from Kwei.
    pub fn from_kwei(kwei: u128) -> Self {
        Self::from_denomination(kwei, EthereumDenomination::Kwei)
    }

    /// Convert to Kwei.
    pub fn to_kwei(&self) -> f64 {
        self.to_denomination(EthereumDenomination::Kwei)
    }

    /// Create from Mwei.
    pub fn from_mwei(mwei: u128) -> Self {
        Self::from_denomination(mwei, EthereumDenomination::Mwei)
    }

    /// Convert to Mwei.
    pub fn to_mwei(&self) -> f64 {
        self.to_denomination(EthereumDenomination::Mwei)
    }

    /// Create from Szabo.
    pub fn from_szabo(szabo: u128) -> Self {
        Self::from_denomination(szabo, EthereumDenomination::Szabo)
    }

    /// Convert to Szabo.
    pub fn to_szabo(&self) -> f64 {
        self.to_denomination(EthereumDenomination::Szabo)
    }

    /// Create from Finney.
    pub fn from_finney(finney: u128) -> Self {
        Self::from_denomination(finney, EthereumDenomination::Finney)
    }

    /// Convert to Finney.
    pub fn to_finney(&self) -> f64 {
        self.to_denomination(EthereumDenomination::Finney)
    }

    /// Create from Gwei (integer).
    pub fn from_gwei_u128(gwei: u128) -> Self {
        Self::from_denomination(gwei, EthereumDenomination::Gwei)
    }
}

impl Amount for Wei {
    const DECIMALS: u8 = 18;
    const SYMBOL: &'static str = "ETH";

    fn from_base_units(value: u64) -> Self {
        Self(value as u128)
    }

    fn to_base_units(&self) -> u64 {
        self.0 as u64
    }

    fn from_main_units(value: f64) -> Self {
        Self::from_eth(value)
    }

    fn to_main_units(&self) -> f64 {
        self.to_eth()
    }
}

impl fmt::Display for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1_000_000_000_000_000_000 {
            write!(f, "{:.18} ETH", self.to_eth())
        } else if self.0 >= 1_000_000_000 {
            write!(f, "{:.9} Gwei", self.to_gwei())
        } else {
            write!(f, "{} wei", self.0)
        }
    }
}

impl Add for Wei {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl Sub for Wei {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl Mul<u128> for Wei {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self::Output {
        Self(self.0.saturating_mul(rhs))
    }
}

impl Div<u128> for Wei {
    type Output = Self;
    fn div(self, rhs: u128) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl From<u128> for Wei {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<Wei> for u128 {
    fn from(value: Wei) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod satoshi_tests {
        use super::*;

        #[test]
        fn test_satoshi_new() {
            let sat = Satoshi::new(100);
            assert_eq!(sat.as_sat(), 100);
        }

        #[test]
        fn test_satoshi_from_btc() {
            let sat = Satoshi::from_btc(1.0);
            assert_eq!(sat.as_sat(), 100_000_000);

            let sat = Satoshi::from_btc(0.5);
            assert_eq!(sat.as_sat(), 50_000_000);
        }

        #[test]
        fn test_satoshi_to_btc() {
            let sat = Satoshi::new(100_000_000);
            assert!((sat.to_btc() - 1.0).abs() < 0.0001);

            let sat = Satoshi::new(50_000_000);
            assert!((sat.to_btc() - 0.5).abs() < 0.0001);
        }

        #[test]
        fn test_satoshi_add() {
            let a = Satoshi::new(100);
            let b = Satoshi::new(200);
            assert_eq!((a + b).as_sat(), 300);
        }

        #[test]
        fn test_satoshi_sub() {
            let a = Satoshi::new(200);
            let b = Satoshi::new(100);
            assert_eq!((a - b).as_sat(), 100);
        }

        #[test]
        fn test_satoshi_display() {
            let sat = Satoshi::new(100);
            assert!(sat.to_string().contains("sat"));

            let sat = Satoshi::ONE_BTC;
            assert!(sat.to_string().contains("BTC"));
        }

        #[test]
        fn test_satoshi_constants() {
            assert_eq!(Satoshi::ZERO.as_sat(), 0);
            assert_eq!(Satoshi::ONE.as_sat(), 1);
            assert_eq!(Satoshi::ONE_BTC.as_sat(), 100_000_000);
        }
    }

    mod wei_tests {
        use super::*;

        #[test]
        fn test_wei_new() {
            let wei = Wei::new(100);
            assert_eq!(wei.as_wei(), 100);
        }

        #[test]
        fn test_wei_from_eth() {
            let wei = Wei::from_eth(1.0);
            assert_eq!(wei.as_wei(), 1_000_000_000_000_000_000);
        }

        #[test]
        fn test_wei_from_gwei() {
            let wei = Wei::from_gwei(1.0);
            assert_eq!(wei.as_wei(), 1_000_000_000);
        }

        #[test]
        fn test_wei_to_eth() {
            let wei = Wei::ONE_ETH;
            assert!((wei.to_eth() - 1.0).abs() < 0.0001);
        }

        #[test]
        fn test_wei_to_gwei() {
            let wei = Wei::ONE_GWEI;
            assert!((wei.to_gwei() - 1.0).abs() < 0.0001);
        }

        #[test]
        fn test_wei_add() {
            let a = Wei::new(100);
            let b = Wei::new(200);
            assert_eq!((a + b).as_wei(), 300);
        }

        #[test]
        fn test_wei_sub() {
            let a = Wei::new(200);
            let b = Wei::new(100);
            assert_eq!((a - b).as_wei(), 100);
        }

        #[test]
        fn test_wei_display() {
            let wei = Wei::new(100);
            assert!(wei.to_string().contains("wei"));

            let wei = Wei::ONE_GWEI;
            assert!(wei.to_string().contains("Gwei"));

            let wei = Wei::ONE_ETH;
            assert!(wei.to_string().contains("ETH"));
        }

        #[test]
        fn test_wei_constants() {
            assert_eq!(Wei::ZERO.as_wei(), 0);
            assert_eq!(Wei::ONE.as_wei(), 1);
            assert_eq!(Wei::ONE_GWEI.as_wei(), 1_000_000_000);
            assert_eq!(Wei::ONE_ETH.as_wei(), 1_000_000_000_000_000_000);
        }
    }

    mod denomination_tests {
        use super::*;

        #[test]
        fn test_bitcoin_denomination_multiplier() {
            assert_eq!(BitcoinDenomination::Satoshi.multiplier(), 1);
            assert_eq!(BitcoinDenomination::MicroBit.multiplier(), 100);
            assert_eq!(BitcoinDenomination::MilliBit.multiplier(), 100_000);
            assert_eq!(BitcoinDenomination::Bitcoin.multiplier(), 100_000_000);
        }

        #[test]
        fn test_satoshi_from_denomination() {
            let sat = Satoshi::from_denomination(1, BitcoinDenomination::Bitcoin);
            assert_eq!(sat.as_sat(), 100_000_000);

            let sat = Satoshi::from_denomination(1000, BitcoinDenomination::MilliBit);
            assert_eq!(sat.as_sat(), 100_000_000);
        }

        #[test]
        fn test_satoshi_to_denomination() {
            let sat = Satoshi::ONE_BTC;
            assert!((sat.to_denomination(BitcoinDenomination::Bitcoin) - 1.0).abs() < 0.0001);
            assert!((sat.to_denomination(BitcoinDenomination::MilliBit) - 1000.0).abs() < 0.0001);
        }

        #[test]
        fn test_satoshi_mbtc_conversion() {
            let sat = Satoshi::from_mbtc(1.0);
            assert_eq!(sat.as_sat(), 100_000);

            assert!((Satoshi::new(100_000).to_mbtc() - 1.0).abs() < 0.0001);
        }

        #[test]
        fn test_ethereum_denomination_multiplier() {
            assert_eq!(EthereumDenomination::Wei.multiplier(), 1);
            assert_eq!(EthereumDenomination::Gwei.multiplier(), 1_000_000_000);
            assert_eq!(
                EthereumDenomination::Ether.multiplier(),
                1_000_000_000_000_000_000
            );
        }

        #[test]
        fn test_wei_from_denomination() {
            let wei = Wei::from_denomination(1, EthereumDenomination::Ether);
            assert_eq!(wei.as_wei(), 1_000_000_000_000_000_000);

            let wei = Wei::from_denomination(1, EthereumDenomination::Gwei);
            assert_eq!(wei.as_wei(), 1_000_000_000);
        }

        #[test]
        fn test_wei_to_denomination() {
            let wei = Wei::ONE_ETH;
            assert!((wei.to_denomination(EthereumDenomination::Ether) - 1.0).abs() < 0.0001);
            assert!(
                (wei.to_denomination(EthereumDenomination::Gwei) - 1_000_000_000.0).abs() < 1.0
            );
        }

        #[test]
        fn test_wei_szabo_finney() {
            let wei = Wei::from_szabo(1);
            assert_eq!(wei.as_wei(), 1_000_000_000_000);

            let wei = Wei::from_finney(1);
            assert_eq!(wei.as_wei(), 1_000_000_000_000_000);
        }

        #[test]
        fn test_denomination_display() {
            assert_eq!(BitcoinDenomination::Bitcoin.to_string(), "BTC");
            assert_eq!(BitcoinDenomination::MilliBit.to_string(), "mBTC");
            assert_eq!(EthereumDenomination::Gwei.to_string(), "gwei");
            assert_eq!(EthereumDenomination::Ether.to_string(), "ETH");
        }
    }
}
