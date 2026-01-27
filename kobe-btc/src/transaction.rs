//! Bitcoin transaction implementation.
//!
//! Supports legacy (P2PKH) and SegWit (P2WPKH) transactions.

use crate::network::Network;
use crate::privkey::PrivateKey;
use alloc::vec::Vec;
use kobe::hash::double_sha256;
use kobe::transaction::{SigHashType, TxInput, TxOutput};
use kobe::{Error, Result};

/// Bitcoin transaction ID (32-byte hash).
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
        // Bitcoin displays txid in reverse byte order
        for byte in self.0.iter().rev() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Bitcoin transaction.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Transaction version.
    pub version: i32,
    /// Transaction inputs.
    pub inputs: Vec<TxInput>,
    /// Transaction outputs.
    pub outputs: Vec<TxOutput>,
    /// Lock time.
    pub lock_time: u32,
    /// Network.
    pub network: Network,
    /// Whether this is a SegWit transaction.
    pub segwit: bool,
}

impl Transaction {
    /// Create a new unsigned transaction.
    pub fn new(network: Network) -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            network,
            segwit: false,
        }
    }

    /// Add an input.
    pub fn add_input(&mut self, input: TxInput) -> &mut Self {
        self.inputs.push(input);
        self
    }

    /// Add an output.
    pub fn add_output(&mut self, output: TxOutput) -> &mut Self {
        self.outputs.push(output);
        self
    }

    /// Enable SegWit.
    pub fn set_segwit(&mut self, segwit: bool) -> &mut Self {
        self.segwit = segwit;
        self
    }

    /// Calculate the signature hash for signing an input.
    pub fn signature_hash(
        &self,
        input_index: usize,
        script_code: &[u8],
        sighash_type: SigHashType,
    ) -> Result<[u8; 32]> {
        if self.segwit {
            self.signature_hash_segwit(input_index, script_code, sighash_type)
        } else {
            self.signature_hash_legacy(input_index, script_code, sighash_type)
        }
    }

    /// Legacy signature hash (BIP-143 not used).
    fn signature_hash_legacy(
        &self,
        input_index: usize,
        script_code: &[u8],
        sighash_type: SigHashType,
    ) -> Result<[u8; 32]> {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // Inputs
        write_varint(&mut data, self.inputs.len() as u64);
        for (i, input) in self.inputs.iter().enumerate() {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_vout.to_le_bytes());

            if i == input_index {
                write_varint(&mut data, script_code.len() as u64);
                data.extend_from_slice(script_code);
            } else {
                write_varint(&mut data, 0);
            }

            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        write_varint(&mut data, self.outputs.len() as u64);
        for output in &self.outputs {
            data.extend_from_slice(&output.amount.to_le_bytes());
            write_varint(&mut data, output.script_pubkey.len() as u64);
            data.extend_from_slice(&output.script_pubkey);
        }

        // Lock time
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        // Sighash type
        data.extend_from_slice(&(sighash_type as u32).to_le_bytes());

        Ok(double_sha256(&data))
    }

    /// SegWit signature hash (BIP-143).
    fn signature_hash_segwit(
        &self,
        input_index: usize,
        script_code: &[u8],
        sighash_type: SigHashType,
    ) -> Result<[u8; 32]> {
        let input = &self.inputs[input_index];
        let amount = input
            .amount
            .ok_or(Error::msg("SegWit input requires amount"))?;

        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // hashPrevouts
        let mut prevouts = Vec::new();
        for inp in &self.inputs {
            prevouts.extend_from_slice(&inp.prev_txid);
            prevouts.extend_from_slice(&inp.prev_vout.to_le_bytes());
        }
        data.extend_from_slice(&double_sha256(&prevouts));

        // hashSequence
        let mut sequences = Vec::new();
        for inp in &self.inputs {
            sequences.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        data.extend_from_slice(&double_sha256(&sequences));

        // outpoint
        data.extend_from_slice(&input.prev_txid);
        data.extend_from_slice(&input.prev_vout.to_le_bytes());

        // scriptCode
        write_varint(&mut data, script_code.len() as u64);
        data.extend_from_slice(script_code);

        // value
        data.extend_from_slice(&amount.to_le_bytes());

        // sequence
        data.extend_from_slice(&input.sequence.to_le_bytes());

        // hashOutputs
        let mut outputs = Vec::new();
        for out in &self.outputs {
            outputs.extend_from_slice(&out.amount.to_le_bytes());
            write_varint(&mut outputs, out.script_pubkey.len() as u64);
            outputs.extend_from_slice(&out.script_pubkey);
        }
        data.extend_from_slice(&double_sha256(&outputs));

        // nLockTime
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        // sighash type
        data.extend_from_slice(&(sighash_type as u32).to_le_bytes());

        Ok(double_sha256(&data))
    }

    /// Sign an input with a private key.
    pub fn sign_input(
        &mut self,
        input_index: usize,
        private_key: &PrivateKey,
        script_code: &[u8],
        sighash_type: SigHashType,
    ) -> Result<()> {
        let sighash = self.signature_hash(input_index, script_code, sighash_type)?;
        let sig = kobe::PrivateKey::sign_prehash(private_key, &sighash)?;

        // Create DER signature with sighash type appended
        let der_sig = sig.to_der();
        let mut sig_with_type = der_sig.to_vec();
        sig_with_type.push(sighash_type as u8);

        let pubkey = kobe::PrivateKey::public_key(private_key);
        let pubkey_bytes = kobe::PublicKey::to_bytes(&pubkey);

        if self.segwit {
            // SegWit: add to witness
            self.inputs[input_index].witness = vec![sig_with_type, pubkey_bytes.to_vec()];
        } else {
            // Legacy: create script_sig
            let mut script_sig = Vec::new();
            script_sig.push(sig_with_type.len() as u8);
            script_sig.extend_from_slice(&sig_with_type);
            script_sig.push(pubkey_bytes.len() as u8);
            script_sig.extend_from_slice(&pubkey_bytes);
            self.inputs[input_index].script_sig = script_sig;
        }

        Ok(())
    }

    /// Serialize the transaction to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // SegWit marker and flag
        if self.segwit && self.has_witness() {
            data.push(0x00); // marker
            data.push(0x01); // flag
        }

        // Inputs
        write_varint(&mut data, self.inputs.len() as u64);
        for input in &self.inputs {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_vout.to_le_bytes());
            write_varint(&mut data, input.script_sig.len() as u64);
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        write_varint(&mut data, self.outputs.len() as u64);
        for output in &self.outputs {
            data.extend_from_slice(&output.amount.to_le_bytes());
            write_varint(&mut data, output.script_pubkey.len() as u64);
            data.extend_from_slice(&output.script_pubkey);
        }

        // Witness data
        if self.segwit && self.has_witness() {
            for input in &self.inputs {
                write_varint(&mut data, input.witness.len() as u64);
                for item in &input.witness {
                    write_varint(&mut data, item.len() as u64);
                    data.extend_from_slice(item);
                }
            }
        }

        // Lock time
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        data
    }

    /// Get the transaction ID.
    pub fn txid(&self) -> TxId {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // Inputs (without witness)
        write_varint(&mut data, self.inputs.len() as u64);
        for input in &self.inputs {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_vout.to_le_bytes());
            write_varint(&mut data, input.script_sig.len() as u64);
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        write_varint(&mut data, self.outputs.len() as u64);
        for output in &self.outputs {
            data.extend_from_slice(&output.amount.to_le_bytes());
            write_varint(&mut data, output.script_pubkey.len() as u64);
            data.extend_from_slice(&output.script_pubkey);
        }

        // Lock time
        data.extend_from_slice(&self.lock_time.to_le_bytes());

        TxId(double_sha256(&data))
    }

    /// Get the witness transaction ID (wtxid).
    pub fn wtxid(&self) -> TxId {
        TxId(double_sha256(&self.to_bytes()))
    }

    /// Check if any input has witness data.
    fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Get the virtual size (vsize) in virtual bytes.
    pub fn vsize(&self) -> usize {
        let base_size = self.base_size();
        let total_size = self.to_bytes().len();

        if self.segwit && self.has_witness() {
            // vsize = (weight + 3) / 4
            // weight = base_size * 3 + total_size
            (base_size * 3 + total_size).div_ceil(4)
        } else {
            total_size
        }
    }

    /// Get the base size (without witness).
    fn base_size(&self) -> usize {
        let mut size = 4; // version
        size += varint_size(self.inputs.len() as u64);

        for input in &self.inputs {
            size += 32 + 4; // prevout
            size += varint_size(input.script_sig.len() as u64);
            size += input.script_sig.len();
            size += 4; // sequence
        }

        size += varint_size(self.outputs.len() as u64);
        for output in &self.outputs {
            size += 8; // amount
            size += varint_size(output.script_pubkey.len() as u64);
            size += output.script_pubkey.len();
        }

        size += 4; // lock_time
        size
    }

    /// Serialize to hex string.
    pub fn to_hex(&self) -> alloc::string::String {
        hex::encode(self.to_bytes())
    }
}

/// Write a variable-length integer.
fn write_varint(data: &mut Vec<u8>, value: u64) {
    match value {
        0..=252 => data.push(value as u8),
        253..=0xffff => {
            data.push(0xfd);
            data.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x10000..=0xffffffff => {
            data.push(0xfe);
            data.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            data.push(0xff);
            data.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Get the size of a varint.
fn varint_size(value: u64) -> usize {
    match value {
        0..=252 => 1,
        253..=0xffff => 3,
        0x10000..=0xffffffff => 5,
        _ => 9,
    }
}

/// Create P2PKH script pubkey from public key hash.
pub fn p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Create P2WPKH script pubkey from public key hash.
pub fn p2wpkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00); // OP_0
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    mod transaction_tests {
        use super::*;

        #[test]
        fn new_transaction() {
            let tx = Transaction::new(Network::Mainnet);
            assert_eq!(tx.version, 2);
            assert!(tx.inputs.is_empty());
            assert!(tx.outputs.is_empty());
        }

        #[test]
        fn add_input_output() {
            let mut tx = Transaction::new(Network::Mainnet);
            tx.add_input(TxInput::new([0u8; 32], 0, Some(100_000)));
            tx.add_output(TxOutput::new(90_000, p2pkh_script(&[0u8; 20])));
            assert_eq!(tx.inputs.len(), 1);
            assert_eq!(tx.outputs.len(), 1);
        }

        #[test]
        fn serialize_empty() {
            let tx = Transaction::new(Network::Mainnet);
            let bytes = tx.to_bytes();
            // version (4) + input count (1) + output count (1) + locktime (4) = 10
            assert_eq!(bytes.len(), 10);
        }

        #[test]
        fn vsize_legacy() {
            let mut tx = Transaction::new(Network::Mainnet);
            tx.add_input(TxInput::new([0u8; 32], 0, None));
            tx.add_output(TxOutput::new(1000, p2pkh_script(&[0u8; 20])));
            // For legacy tx, vsize == size
            assert_eq!(tx.vsize(), tx.to_bytes().len());
        }
    }

    mod script_tests {
        use super::*;

        #[test]
        fn p2pkh_script_format() {
            let script = p2pkh_script(&[0u8; 20]);
            assert_eq!(script.len(), 25);
            assert_eq!(script[0], 0x76); // OP_DUP
            assert_eq!(script[24], 0xac); // OP_CHECKSIG
        }

        #[test]
        fn p2wpkh_script_format() {
            let script = p2wpkh_script(&[0u8; 20]);
            assert_eq!(script.len(), 22);
            assert_eq!(script[0], 0x00); // OP_0
            assert_eq!(script[1], 0x14); // Push 20 bytes
        }
    }

    mod encoding_tests {
        use super::*;

        #[test]
        fn txid_display_reversed() {
            let txid = TxId([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ]);
            assert!(txid.to_string().starts_with("201f1e1d"));
        }

        #[test]
        fn varint_encoding() {
            let mut data = Vec::new();

            write_varint(&mut data, 0);
            assert_eq!(data, vec![0]);

            data.clear();
            write_varint(&mut data, 252);
            assert_eq!(data, vec![252]);

            data.clear();
            write_varint(&mut data, 253);
            assert_eq!(data, vec![0xfd, 253, 0]);

            data.clear();
            write_varint(&mut data, 0x10000);
            assert_eq!(data, vec![0xfe, 0, 0, 1, 0]);
        }
    }
}
