//! Transaction-related types for cryptocurrency transactions.
//!
//! Contains concrete types for Bitcoin and Ethereum transaction parameters.
//! The `Transaction` and `TransactionId` traits are defined in `traits.rs`.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Bitcoin-specific transaction input.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    /// Previous transaction hash (txid).
    pub prev_txid: [u8; 32],
    /// Previous output index.
    pub prev_vout: u32,
    /// Script signature (empty for unsigned).
    pub script_sig: Vec<u8>,
    /// Sequence number.
    pub sequence: u32,
    /// Witness data (for SegWit).
    pub witness: Vec<Vec<u8>>,
    /// Amount of the previous output (needed for SegWit signing).
    pub amount: Option<u64>,
}

#[cfg(feature = "alloc")]
impl TxInput {
    /// Create a new transaction input.
    pub fn new(prev_txid: [u8; 32], prev_vout: u32, amount: Option<u64>) -> Self {
        Self {
            prev_txid,
            prev_vout,
            script_sig: Vec::new(),
            sequence: 0xffffffff,
            witness: Vec::new(),
            amount,
        }
    }

    /// Create with RBF (Replace-By-Fee) enabled.
    pub fn with_rbf(mut self) -> Self {
        self.sequence = 0xfffffffd;
        self
    }
}

/// Bitcoin-specific transaction output.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    /// Output amount in satoshis.
    pub amount: u64,
    /// Script public key.
    pub script_pubkey: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl TxOutput {
    /// Create a new transaction output.
    pub fn new(amount: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            amount,
            script_pubkey,
        }
    }
}

/// Ethereum transaction parameters (EIP-155 legacy transaction).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthTxParams {
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
}

#[cfg(feature = "alloc")]
impl EthTxParams {
    /// Create parameters for a simple ETH transfer.
    pub fn transfer(to: [u8; 20], value: u128, nonce: u64, gas_price: u128, chain_id: u64) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit: 21000,
            to: Some(to),
            value,
            data: Vec::new(),
            chain_id,
        }
    }

    /// Create parameters for a contract call.
    pub fn contract_call(
        to: [u8; 20],
        data: Vec<u8>,
        value: u128,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        chain_id: u64,
    ) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit,
            to: Some(to),
            value,
            data,
            chain_id,
        }
    }
}

/// EIP-1559 transaction parameters.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559TxParams {
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
    /// Access list (EIP-2930).
    pub access_list: Vec<(Vec<u8>, Vec<[u8; 32]>)>,
}

#[cfg(feature = "alloc")]
impl Eip1559TxParams {
    /// Create parameters for a simple ETH transfer.
    pub fn transfer(
        to: [u8; 20],
        value: u128,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        chain_id: u64,
    ) -> Self {
        Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: 21000,
            to: Some(to),
            value,
            data: Vec::new(),
            access_list: Vec::new(),
        }
    }
}

/// Bitcoin signature hash types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SigHashType {
    /// Sign all inputs and outputs.
    All = 0x01,
    /// Sign all inputs, no outputs.
    None = 0x02,
    /// Sign all inputs, one output per input.
    Single = 0x03,
    /// Sign only this input, all outputs (ANYONECANPAY).
    AllAnyoneCanPay = 0x81,
    /// Sign only this input, no outputs.
    NoneAnyoneCanPay = 0x82,
    /// Sign only this input, corresponding output.
    SingleAnyoneCanPay = 0x83,
}

impl SigHashType {
    /// Check if ANYONECANPAY flag is set.
    pub const fn is_anyone_can_pay(&self) -> bool {
        (*self as u8) & 0x80 != 0
    }

    /// Get the base type (without ANYONECANPAY).
    pub const fn base_type(&self) -> u8 {
        (*self as u8) & 0x1f
    }
}

impl Default for SigHashType {
    fn default() -> Self {
        Self::All
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sighash_type() {
        assert_eq!(SigHashType::All as u8, 0x01);
        assert_eq!(SigHashType::AllAnyoneCanPay as u8, 0x81);
        assert!(SigHashType::AllAnyoneCanPay.is_anyone_can_pay());
        assert!(!SigHashType::All.is_anyone_can_pay());
    }

    #[test]
    fn test_tx_input_new() {
        let input = TxInput::new([0u8; 32], 0, Some(1000));
        assert_eq!(input.sequence, 0xffffffff);
        assert!(input.script_sig.is_empty());
    }

    #[test]
    fn test_tx_input_rbf() {
        let input = TxInput::new([0u8; 32], 0, None).with_rbf();
        assert_eq!(input.sequence, 0xfffffffd);
    }

    #[test]
    fn test_eth_tx_params_transfer() {
        let params = EthTxParams::transfer([1u8; 20], 1_000_000_000, 0, 20_000_000_000, 1);
        assert_eq!(params.gas_limit, 21000);
        assert_eq!(params.chain_id, 1);
        assert!(params.data.is_empty());
    }

    #[test]
    fn test_eip1559_params() {
        let params = Eip1559TxParams::transfer(
            [1u8; 20],
            1_000_000_000,
            0,
            2_000_000_000,
            100_000_000_000,
            1,
        );
        assert_eq!(params.gas_limit, 21000);
        assert!(params.access_list.is_empty());
    }
}
