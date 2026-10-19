//! Cardano (ADA): CIP-3 master keys + ed25519-bip32 (V2) derivation.
//!
//! Paths follow CIP-1852: `m/1852'/1815'/{a}'/0/{n}` for payment keys, with
//! the stake key at `m/1852'/1815'/{a}'/2/0`. Output is a Shelley base
//! address (`addr`/`addr_test` bech32, header `0x01`/`0x00`), and
//! `extra.stake_address` holds the `stake`/`stake_test` reward address
//! (header `0xe1`/`0xe0`). `private_key` is the CIP-5 `addr_xsk` bech32
//! over `kL ‖ kR ‖ chain code` (96 bytes). Cardano bech32 strings exceed
//! the 90-char limit, so encoding goes through the primitives API.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use bech32::{Bech32, ByteIterExt, Fe32IterExt};
use ed25519_bip32::{DerivationScheme, XPrv};
use zeroize::Zeroizing;

use crate::encoding::hash::blake2b_224;
use crate::hd::cardano;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

crate::option_enum! {
    /// Cardano network (Shelley bech32 hrp and address header byte).
    pub enum Network {
        /// Mainnet: `addr`, `stake`.
        #[default]
        Mainnet = "mainnet",
        /// Testnets (preprod/preview/legacy): `addr_test`, `stake_test`.
        Testnet = "testnet",
    }
}

impl Network {
    const fn addr_hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "addr",
            Self::Testnet => "addr_test",
        }
    }

    const fn stake_hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "stake",
            Self::Testnet => "stake_test",
        }
    }

    /// Shelley base-address header nibble byte: `0x01` mainnet, `0x00` testnet.
    const fn base_header(self) -> u8 {
        match self {
            Self::Mainnet => 0x01,
            Self::Testnet => 0x00,
        }
    }

    /// Reward-account header byte: `0xe1` mainnet, `0xe0` testnet.
    const fn stake_header(self) -> u8 {
        match self {
            Self::Mainnet => 0xe1,
            Self::Testnet => 0xe0,
        }
    }
}

crate::option_enum! {
    /// CIP-3 master-key algorithm (the device/wallet family that generated it).
    pub enum Master {
        /// Icarus (Yoroi, Eternl, Lace, Typhon, Daedalus): PBKDF2 over the
        /// BIP-39 entropy.
        #[default]
        Icarus = "icarus",
        /// Ledger/BitBox02: HMAC-SHA512 loop over the BIP-39 seed.
        Ledger = "ledger",
        /// Icarus with the Trezor 24-word checksum-byte quirk.
        IcarusTrezor = "icarus-trezor",
    }
}

/// The Cardano chain (CIP-1852 Shelley wallets).
#[derive(Debug, Clone, Copy, Default)]
pub struct Cardano {
    /// Target network (`addr`/`addr_test` HRPs and address header bytes).
    pub network: Network,
    /// CIP-3 master-key algorithm (the device/wallet family).
    pub master: Master,
}

impl Cardano {
    /// Cardano on `network` with master-key algorithm `master`.
    #[must_use]
    pub const fn new(network: Network, master: Master) -> Self {
        Self { network, master }
    }
}

/// CIP-1852 purpose and coin type, hardened.
const PURPOSE: u32 = 1852;
const COIN_TYPE: u32 = 1815;

/// Append the bech32 (no length limit) encoding of `data` to `out`.
fn push_bech32(out: &mut String, hrp: &'static str, data: &[u8]) {
    let hrp = bech32::Hrp::parse_unchecked(hrp);
    let chars = data
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32>(&hrp)
        .chars();
    out.extend(chars);
}

/// Exact bech32 length: `hrp ‖ '1' ‖ base32(data) ‖ checksum6`.
const fn bech32_len(hrp: &'static str, data: &[u8]) -> usize {
    hrp.len() + 1 + (data.len() * 8).div_ceil(5) + 6
}

/// Bech32 (no length limit) over `data` — public material.
fn bech32_public(hrp: &'static str, data: &[u8]) -> String {
    let mut out = String::with_capacity(bech32_len(hrp, data));
    push_bech32(&mut out, hrp, data);
    out
}

/// Bech32 (no length limit) over `data` into a zeroized string — secrets.
fn bech32_secret(hrp: &'static str, data: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bech32_len(hrp, data)));
    push_bech32(&mut out, hrp, data);
    out
}

/// Validate `path` as `m/1852'/1815'/{a}'/0/{n}` and return the account `a`.
fn payment_account(path: &DerivationPath) -> Result<u32, Error> {
    let shape_error = || {
        Error::UnsupportedPath(format!(
            "{path}: expected m/1852'/1815'/{{a}}'/0/{{n}} (hardened, hardened, \
             hardened, normal 0, normal n)"
        ))
    };
    let segments = path.as_slice();
    let [purpose, coin, account, role, index] = *segments else {
        return Err(shape_error());
    };
    let hardened = [PURPOSE, COIN_TYPE]
        .into_iter()
        .zip([purpose, coin])
        .all(|(expected, got)| got.is_hardened() && got.index() == expected);
    if !hardened
        || !account.is_hardened()
        || role.is_hardened()
        || role.index() != 0
        || index.is_hardened()
    {
        return Err(shape_error());
    }
    Ok(account.index())
}

/// Derive `indices` (BIP-32 wire values) below `xprv` under V2.
fn derive(xprv: &XPrv, indices: &[u32]) -> XPrv {
    indices
        .iter()
        .fold(xprv.clone(), |x, &i| x.derive(DerivationScheme::V2, i))
}

/// `path` as raw wire indices.
fn wire_indices(path: &DerivationPath) -> Vec<u32> {
    path.as_slice().iter().map(|i| i.wire()).collect()
}

/// The `m/1852'/1815'/{a}'/2/0` stake-key wire indices for `account`.
const fn stake_indices(account: u32) -> [u32; 5] {
    const HARDENED: u32 = 0x8000_0000;
    [
        PURPOSE | HARDENED,
        COIN_TYPE | HARDENED,
        account | HARDENED,
        2,
        0,
    ]
}

impl Chain for Cardano {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "standard",
            "m/1852'/1815'/{i}'/0/0",
            "Yoroi, Eternl, Lace, Typhon, Daedalus, Trust Wallet (icarus); Trezor Suite (icarus-trezor); Ledger Live (ledger)",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let account = payment_account(path)?;
        let master = cardano::master_key(self.master, wallet)?;
        let root = XPrv::from_bytes_verified(*master)
            .map_err(|e| Error::InvalidKey(format!("xprv: {e}")))?;

        let payment = derive(&root, &wire_indices(path));
        let stake = derive(&root, &stake_indices(account));

        let payment_pk = payment.public().public_key();
        let stake_pk = stake.public().public_key();

        let mut base = Vec::with_capacity(57);
        base.push(self.network.base_header());
        base.extend_from_slice(&blake2b_224(&payment_pk));
        base.extend_from_slice(&blake2b_224(&stake_pk));
        let address = bech32_public(self.network.addr_hrp(), &base);

        let mut reward = Vec::with_capacity(29);
        reward.push(self.network.stake_header());
        reward.extend_from_slice(&blake2b_224(&stake_pk));
        let stake_address = bech32_public(self.network.stake_hrp(), &reward);

        let mut xsk = Zeroizing::new(Vec::with_capacity(96));
        xsk.extend_from_slice(payment.extended_secret_key_slice());
        xsk.extend_from_slice(payment.chain_code_slice());
        let private_key = bech32_secret("addr_xsk", &xsk);

        let mut secret = Zeroizing::new([0u8; 64]);
        secret.copy_from_slice(payment.extended_secret_key_bytes());

        let mut account_out = Account::new(
            path.clone(),
            address,
            hex::encode(payment_pk),
            private_key,
            SecretKey::Ed25519Extended(secret),
        );
        account_out.extra.push(("stake_address", stake_address));
        Ok(account_out)
    }
}
