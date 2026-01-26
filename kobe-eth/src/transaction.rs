//! Ethereum transaction implementation.
//!
//! Supports legacy (EIP-155) and EIP-1559 transactions.

use crate::address::Address;
use crate::network::Network;
use crate::privkey::PrivateKey;
use alloc::vec::Vec;
use kobe::hash::keccak256;
use kobe::transaction::{Eip1559TxParams, EthTxParams};
use kobe::{Error, Result};

/// Ethereum transaction ID (32-byte hash).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl kobe::TransactionId for TxId {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Display for TxId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Legacy Ethereum transaction (EIP-155).
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Transaction nonce.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address (None for contract creation).
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Transaction data.
    pub data: Vec<u8>,
    /// Chain ID (EIP-155).
    pub chain_id: u64,
    /// Signature v component.
    pub v: Option<u64>,
    /// Signature r component.
    pub r: Option<[u8; 32]>,
    /// Signature s component.
    pub s: Option<[u8; 32]>,
}

impl Transaction {
    /// Create a new unsigned transaction.
    pub fn new(params: EthTxParams) -> Self {
        Self {
            nonce: params.nonce,
            gas_price: params.gas_price,
            gas_limit: params.gas_limit,
            to: params.to,
            value: params.value,
            data: params.data,
            chain_id: params.chain_id,
            v: None,
            r: None,
            s: None,
        }
    }

    /// Create a simple ETH transfer transaction with Network type.
    ///
    /// # Example
    /// ```rust,ignore
    /// use kobe_eth::{Transaction, Network, Address};
    ///
    /// let tx = Transaction::transfer_on(
    ///     Network::Mainnet,
    ///     recipient,
    ///     1_000_000_000_000_000_000, // 1 ETH
    ///     0,                          // nonce
    ///     20_000_000_000,             // 20 Gwei gas price
    /// );
    /// ```
    pub fn transfer_on(
        network: Network,
        to: Address,
        value: u128,
        nonce: u64,
        gas_price: u128,
    ) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit: 21000,
            to: Some(*to.as_bytes()),
            value,
            data: Vec::new(),
            chain_id: network.chain_id(),
            v: None,
            r: None,
            s: None,
        }
    }

    /// Create a simple ETH transfer transaction (legacy API with raw chain_id).
    #[deprecated(since = "0.2.0", note = "Use transfer_on() with Network type instead")]
    pub fn transfer(to: Address, value: u128, nonce: u64, gas_price: u128, chain_id: u64) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit: 21000,
            to: Some(*to.as_bytes()),
            value,
            data: Vec::new(),
            chain_id,
            v: None,
            r: None,
            s: None,
        }
    }

    /// Get the network for this transaction.
    pub fn network(&self) -> Option<Network> {
        Network::from_chain_id(self.chain_id)
    }

    /// Check if the transaction is signed.
    pub fn is_signed(&self) -> bool {
        self.v.is_some() && self.r.is_some() && self.s.is_some()
    }

    /// Sign the transaction with a private key.
    pub fn sign(&self, private_key: &PrivateKey) -> Result<Self> {
        if self.is_signed() {
            return Ok(self.clone());
        }

        let hash = self.signing_hash();
        let sig = kobe::PrivateKey::sign_prehash(private_key, &hash)?;

        // EIP-155: v = chain_id * 2 + 35 + recovery_id
        let v = self.chain_id * 2 + 35 + sig.v as u64;

        Ok(Self {
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            data: self.data.clone(),
            chain_id: self.chain_id,
            v: Some(v),
            r: Some(sig.r),
            s: Some(sig.s),
        })
    }

    /// Get the hash used for signing (EIP-155).
    pub fn signing_hash(&self) -> [u8; 32] {
        let encoded = self.rlp_encode_for_signing();
        keccak256(&encoded)
    }

    /// Get the transaction hash.
    pub fn tx_hash(&self) -> TxId {
        TxId(keccak256(&self.to_bytes()))
    }

    /// RLP encode for signing (unsigned transaction with chain_id).
    fn rlp_encode_for_signing(&self) -> Vec<u8> {
        let items = vec![
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.gas_price),
            rlp_encode_u64(self.gas_limit),
            match &self.to {
                Some(addr) => rlp_encode_bytes(addr),
                None => rlp_encode_bytes(&[]),
            },
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
            rlp_encode_u64(self.chain_id),
            rlp_encode_u64(0), // empty r
            rlp_encode_u64(0), // empty s
        ];

        rlp_encode_list(&items)
    }

    /// Serialize to bytes (RLP encoded).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut items = vec![
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.gas_price),
            rlp_encode_u64(self.gas_limit),
            match &self.to {
                Some(addr) => rlp_encode_bytes(addr),
                None => rlp_encode_bytes(&[]),
            },
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
        ];

        if let (Some(v), Some(r), Some(s)) = (self.v, &self.r, &self.s) {
            items.push(rlp_encode_u64(v));
            items.push(rlp_encode_bytes(trim_leading_zeros(r)));
            items.push(rlp_encode_bytes(trim_leading_zeros(s)));
        }

        rlp_encode_list(&items)
    }

    /// Serialize to hex string.
    pub fn to_hex(&self) -> alloc::string::String {
        let bytes = self.to_bytes();
        let mut result = alloc::string::String::with_capacity(2 + bytes.len() * 2);
        result.push_str("0x");
        for byte in bytes {
            result.push_str(&alloc::format!("{:02x}", byte));
        }
        result
    }

    /// Get the sender address (requires signature).
    pub fn sender(&self) -> Result<Address> {
        if !self.is_signed() {
            return Err(Error::msg("Transaction not signed"));
        }

        let hash = self.signing_hash();
        let v = self.v.unwrap();
        let recovery_id = if v >= 35 {
            ((v - 35) % 2) as u8
        } else {
            (v - 27) as u8
        };

        let sig = kobe::Signature::new(self.r.unwrap(), self.s.unwrap(), recovery_id);
        let pubkey = crate::pubkey::PublicKey::recover_from_prehash(&hash, &sig)?;

        Ok(Address::from_public_key(&pubkey))
    }
}

/// EIP-1559 transaction.
#[derive(Clone, Debug)]
pub struct Eip1559Transaction {
    /// Chain ID.
    pub chain_id: u64,
    /// Transaction nonce.
    pub nonce: u64,
    /// Max priority fee per gas (tip).
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas.
    pub max_fee_per_gas: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address (None for contract creation).
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Transaction data.
    pub data: Vec<u8>,
    /// Access list.
    pub access_list: Vec<(Vec<u8>, Vec<[u8; 32]>)>,
    /// Signature y parity.
    pub y_parity: Option<u8>,
    /// Signature r component.
    pub r: Option<[u8; 32]>,
    /// Signature s component.
    pub s: Option<[u8; 32]>,
}

impl Eip1559Transaction {
    /// Create a new unsigned transaction.
    pub fn new(params: Eip1559TxParams) -> Self {
        Self {
            chain_id: params.chain_id,
            nonce: params.nonce,
            max_priority_fee_per_gas: params.max_priority_fee_per_gas,
            max_fee_per_gas: params.max_fee_per_gas,
            gas_limit: params.gas_limit,
            to: params.to,
            value: params.value,
            data: params.data,
            access_list: params.access_list,
            y_parity: None,
            r: None,
            s: None,
        }
    }

    /// Create a simple ETH transfer transaction with Network type.
    ///
    /// # Example
    /// ```rust,ignore
    /// use kobe_eth::{Eip1559Transaction, Network, Address};
    ///
    /// let tx = Eip1559Transaction::transfer_on(
    ///     Network::Mainnet,
    ///     recipient,
    ///     1_000_000_000_000_000_000, // 1 ETH
    ///     0,                          // nonce
    ///     2_000_000_000,              // 2 Gwei priority fee
    ///     100_000_000_000,            // 100 Gwei max fee
    /// );
    /// ```
    pub fn transfer_on(
        network: Network,
        to: Address,
        value: u128,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
    ) -> Self {
        Self {
            chain_id: network.chain_id(),
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: 21000,
            to: Some(*to.as_bytes()),
            value,
            data: Vec::new(),
            access_list: Vec::new(),
            y_parity: None,
            r: None,
            s: None,
        }
    }

    /// Get the network for this transaction.
    pub fn network(&self) -> Option<Network> {
        Network::from_chain_id(self.chain_id)
    }

    /// Check if the transaction is signed.
    pub fn is_signed(&self) -> bool {
        self.y_parity.is_some() && self.r.is_some() && self.s.is_some()
    }

    /// Sign the transaction with a private key.
    pub fn sign(&self, private_key: &PrivateKey) -> Result<Self> {
        if self.is_signed() {
            return Ok(self.clone());
        }

        let hash = self.signing_hash();
        let sig = kobe::PrivateKey::sign_prehash(private_key, &hash)?;

        Ok(Self {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            data: self.data.clone(),
            access_list: self.access_list.clone(),
            y_parity: Some(sig.v),
            r: Some(sig.r),
            s: Some(sig.s),
        })
    }

    /// Get the hash used for signing.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut payload = Vec::new();
        payload.push(0x02); // EIP-1559 type
        payload.extend_from_slice(&self.rlp_encode_for_signing());
        keccak256(&payload)
    }

    /// Get the transaction hash.
    pub fn tx_hash(&self) -> TxId {
        TxId(keccak256(&self.to_bytes()))
    }

    /// RLP encode for signing.
    fn rlp_encode_for_signing(&self) -> Vec<u8> {
        let items = vec![
            rlp_encode_u64(self.chain_id),
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.max_priority_fee_per_gas),
            rlp_encode_u128(self.max_fee_per_gas),
            rlp_encode_u64(self.gas_limit),
            match &self.to {
                Some(addr) => rlp_encode_bytes(addr),
                None => rlp_encode_bytes(&[]),
            },
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
            rlp_encode_access_list(&self.access_list),
        ];

        rlp_encode_list(&items)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut items = vec![
            rlp_encode_u64(self.chain_id),
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.max_priority_fee_per_gas),
            rlp_encode_u128(self.max_fee_per_gas),
            rlp_encode_u64(self.gas_limit),
            match &self.to {
                Some(addr) => rlp_encode_bytes(addr),
                None => rlp_encode_bytes(&[]),
            },
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
            rlp_encode_access_list(&self.access_list),
        ];

        if let (Some(y_parity), Some(r), Some(s)) = (self.y_parity, &self.r, &self.s) {
            items.push(rlp_encode_u64(y_parity as u64));
            items.push(rlp_encode_bytes(trim_leading_zeros(r)));
            items.push(rlp_encode_bytes(trim_leading_zeros(s)));
        }

        let mut result = vec![0x02]; // EIP-1559 type
        result.extend_from_slice(&rlp_encode_list(&items));
        result
    }

    /// Serialize to hex string.
    pub fn to_hex(&self) -> alloc::string::String {
        let bytes = self.to_bytes();
        let mut result = alloc::string::String::with_capacity(2 + bytes.len() * 2);
        result.push_str("0x");
        for byte in bytes {
            result.push_str(&alloc::format!("{:02x}", byte));
        }
        result
    }
}

/// RLP encode a u64.
fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }

    let bytes = value.to_be_bytes();
    let trimmed = trim_leading_zeros(&bytes);
    rlp_encode_bytes(trimmed)
}

/// RLP encode a u128.
fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }

    let bytes = value.to_be_bytes();
    let trimmed = trim_leading_zeros(&bytes);
    rlp_encode_bytes(trimmed)
}

/// RLP encode bytes.
fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0x80];
    }

    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }

    if bytes.len() <= 55 {
        let mut result = Vec::with_capacity(1 + bytes.len());
        result.push(0x80 + bytes.len() as u8);
        result.extend_from_slice(bytes);
        return result;
    }

    let len_bytes = encode_length(bytes.len());
    let mut result = Vec::with_capacity(1 + len_bytes.len() + bytes.len());
    result.push(0xb7 + len_bytes.len() as u8);
    result.extend_from_slice(&len_bytes);
    result.extend_from_slice(bytes);
    result
}

/// RLP encode a list.
fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = items.iter().map(|i| i.len()).sum();

    if total_len <= 55 {
        let mut result = Vec::with_capacity(1 + total_len);
        result.push(0xc0 + total_len as u8);
        for item in items {
            result.extend_from_slice(item);
        }
        return result;
    }

    let len_bytes = encode_length(total_len);
    let mut result = Vec::with_capacity(1 + len_bytes.len() + total_len);
    result.push(0xf7 + len_bytes.len() as u8);
    result.extend_from_slice(&len_bytes);
    for item in items {
        result.extend_from_slice(item);
    }
    result
}

/// Encode access list for EIP-1559.
fn rlp_encode_access_list(access_list: &[(Vec<u8>, Vec<[u8; 32]>)]) -> Vec<u8> {
    let mut items = Vec::new();

    for (address, storage_keys) in access_list {
        let mut entry = Vec::new();
        entry.push(rlp_encode_bytes(address));

        let keys: Vec<Vec<u8>> = storage_keys.iter().map(|k| rlp_encode_bytes(k)).collect();
        entry.push(rlp_encode_list(&keys));

        items.push(rlp_encode_list(&entry));
    }

    rlp_encode_list(&items)
}

/// Encode length as big-endian bytes.
fn encode_length(len: usize) -> Vec<u8> {
    if len <= 0xff {
        vec![len as u8]
    } else if len <= 0xffff {
        (len as u16).to_be_bytes().to_vec()
    } else if len <= 0xffffff {
        let bytes = (len as u32).to_be_bytes();
        bytes[1..].to_vec()
    } else {
        (len as u32).to_be_bytes().to_vec()
    }
}

/// Trim leading zeros from bytes.
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use kobe::PrivateKey as PrivateKeyTrait;

    #[test]
    fn test_create_legacy_tx() {
        let tx = Transaction::new(EthTxParams::transfer(
            [1u8; 20],
            1_000_000_000_000_000_000,
            0,
            20_000_000_000,
            1,
        ));
        assert!(!tx.is_signed());
        assert_eq!(tx.gas_limit, 21000);
    }

    #[test]
    fn test_create_eip1559_tx() {
        let tx = Eip1559Transaction::new(Eip1559TxParams::transfer(
            [1u8; 20],
            1_000_000_000_000_000_000,
            0,
            2_000_000_000,
            100_000_000_000,
            1,
        ));
        assert!(!tx.is_signed());
        assert_eq!(tx.gas_limit, 21000);
    }

    #[test]
    fn test_rlp_encode_u64() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
        assert_eq!(rlp_encode_u64(1), vec![0x01]);
        assert_eq!(rlp_encode_u64(127), vec![0x7f]);
        assert_eq!(rlp_encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_u64(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_rlp_encode_bytes() {
        assert_eq!(rlp_encode_bytes(&[]), vec![0x80]);
        assert_eq!(rlp_encode_bytes(&[0x00]), vec![0x00]);
        assert_eq!(rlp_encode_bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(rlp_encode_bytes(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn test_rlp_encode_list() {
        let items: Vec<Vec<u8>> = vec![];
        assert_eq!(rlp_encode_list(&items), vec![0xc0]);

        let items = vec![vec![0x01], vec![0x02]];
        assert_eq!(rlp_encode_list(&items), vec![0xc2, 0x01, 0x02]);
    }

    #[test]
    fn test_tx_hash_display() {
        let hash = TxId([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let display = hash.to_string();
        assert!(display.starts_with("0x0102"));
    }

    #[test]
    fn test_sign_legacy_tx() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = <PrivateKey as PrivateKeyTrait>::from_bytes(&bytes).unwrap();

        let tx = Transaction::new(EthTxParams::transfer(
            [1u8; 20],
            1_000_000_000_000_000_000,
            0,
            20_000_000_000,
            1,
        ));

        let signed = tx.sign(&key).unwrap();
        assert!(signed.is_signed());
        assert!(signed.v.unwrap() >= 37); // EIP-155: 1 * 2 + 35 = 37
    }

    #[test]
    fn test_sign_eip1559_tx() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = <PrivateKey as PrivateKeyTrait>::from_bytes(&bytes).unwrap();

        let tx = Eip1559Transaction::new(Eip1559TxParams::transfer(
            [1u8; 20],
            1_000_000_000_000_000_000,
            0,
            2_000_000_000,
            100_000_000_000,
            1,
        ));

        let signed = tx.sign(&key).unwrap();
        assert!(signed.is_signed());
    }

    #[test]
    fn test_serialize_to_hex() {
        let tx = Transaction::new(EthTxParams::transfer([1u8; 20], 0, 0, 20_000_000_000, 1));

        let hex = tx.to_hex();
        assert!(hex.starts_with("0x"));
    }

    #[test]
    fn test_transfer_on_network() {
        use crate::network::Network;

        let recipient = Address::from_bytes([1u8; 20]);

        // Create mainnet transaction
        let tx = Transaction::transfer_on(
            Network::Mainnet,
            recipient.clone(),
            1_000_000_000_000_000_000,
            0,
            20_000_000_000,
        );
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.network(), Some(Network::Mainnet));

        // Create BSC transaction
        let bsc_tx = Transaction::transfer_on(
            Network::BinanceSmartChain,
            recipient.clone(),
            1_000_000_000_000_000_000,
            0,
            5_000_000_000,
        );
        assert_eq!(bsc_tx.chain_id, 56);
        assert_eq!(bsc_tx.network(), Some(Network::BinanceSmartChain));

        // Create Polygon transaction
        let polygon_tx = Transaction::transfer_on(
            Network::Polygon,
            recipient,
            1_000_000_000_000_000_000,
            0,
            30_000_000_000,
        );
        assert_eq!(polygon_tx.chain_id, 137);
    }

    #[test]
    fn test_eip1559_transfer_on_network() {
        use crate::network::Network;

        let recipient = Address::from_bytes([1u8; 20]);

        let tx = Eip1559Transaction::transfer_on(
            Network::Mainnet,
            recipient,
            1_000_000_000_000_000_000,
            0,
            2_000_000_000,
            100_000_000_000,
        );

        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.network(), Some(Network::Mainnet));
        assert_eq!(tx.gas_limit, 21000);
    }
}
