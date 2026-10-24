//! Arweave: deterministic RSA-4096 (Wander/`human-crypto-keys`
//! byte-compatible) and secp256k1 ECDSA (`m/44'/472'/0'/0/{i}`, kobe v3/v4
//! compatible, protocol 2.9+).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::{Account, DerivationPath, Error, Style, Wallet};

/// `kobe arweave`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Arweave {
    /// `true` when the `ecdsa` style was selected (`-s ecdsa`).
    ecdsa: bool,
}

impl Arweave {
    /// Select by style id — `false` is `rsa`, `true` is `ecdsa`.
    #[must_use]
    pub const fn new(ecdsa: bool) -> Self {
        Self { ecdsa }
    }
}

crate::option_enum! {
    /// Address/key algorithm.
    pub enum Algorithm {
        /// Deterministic RSA-4096 from the BIP-39 seed (Wander).
        #[default]
        Rsa = "rsa" => "RSA-4096 (Wander)",
        /// secp256k1 at `m/44'/472'/0'/0/{i}` (protocol 2.9+).
        Ecdsa = "ecdsa" => "secp256k1 (kobe v3/v4)",
    }
}

impl Arweave {}

impl crate::Chain for Arweave {
    fn styles(&self) -> Vec<Style> {
        vec![
            Style::new("rsa", "m", "Wander"),
            Style::new("ecdsa", "m/44'/472'/0'/0/{i}", "kobe v3/v4"),
        ]
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        // RSA has no HD path: it must be requested via the `rsa` style
        // (template `m`, the BIP-32 root). Any explicit `--path` is
        // rejected — RSA cannot fake an HD path.
        if self.ecdsa {
            ecdsa_account(wallet, path)
        } else if path.as_slice().is_empty() {
            rsa_account(wallet, path)
        } else {
            Err(Error::UnsupportedPath(String::from(
                "arweave rsa has no derivation path; use -s rsa (or default)",
            )))
        }
    }
}

fn ecdsa_account(wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
    use base64::Engine as _;
    use sha2::Digest as _;

    let node = crate::hd::bip32::Node::derive(wallet.seed(), path)?;
    let pubkey = node.public_key();
    let digest = sha2::Sha256::digest(pubkey);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let private_key = node.private_key();
    Ok(Account::new(
        path.clone(),
        b64.encode(digest),
        b64.encode(pubkey),
        Zeroizing::new(hex::encode(*private_key)),
        crate::SecretKey::Secp256k1(private_key),
    ))
}

fn rsa_account(wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
    use base64::Engine as _;

    // Wander does not support a BIP-39 passphrase: the seed there is
    // always `mnemonicToSeed(mnemonic, "")`. Here `wallet.seed()` carries
    // the user's passphrase (empty by default).
    let key = rsa::generate(wallet.seed())?;
    let n = key.n.to_be_bytes_trimmed_vartime();
    let mut n512 = [0u8; 512];
    let Some(tail) = n512.get_mut(512 - n.len()..) else {
        return Err(Error::InvalidKey(String::from(
            "rsa modulus larger than 4096 bits",
        )));
    };
    tail.copy_from_slice(&n);
    let digest = {
        use sha2::Digest as _;
        sha2::Sha256::digest(n512)
    };
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk_bytes = Zeroizing::new(rsa::jwk(&key).as_bytes().to_vec());
    let jwk = rsa::jwk(&key);
    Ok(Account::new(
        path.clone(),
        b64.encode(digest),
        b64.encode(&*n),
        jwk,
        crate::SecretKey::Opaque(jwk_bytes),
    ))
}

/// Deterministic RSA-4096 generation, byte-compatible with node-forge
/// 1.3.1 `rsa._generateKeyPair` driven by `human-crypto-keys` 0.1.4 +
/// `hmac-drbg` 1.0.1 (see `design/v7-cli.md` §6.2).
mod rsa {
    use alloc::vec::Vec;

    use crypto_bigint::{BoxedUint, ConcatenatingMul as _, Limb, NonZero};
    use zeroize::Zeroizing;

    use crate::Error;

    pub(super) struct RsaKey {
        pub n: BoxedUint,
        pub d: BoxedUint,
        pub p: BoxedUint,
        pub q: BoxedUint,
        pub dp: BoxedUint,
        pub dq: BoxedUint,
        pub qi: BoxedUint,
    }

    const E: u64 = 65537;
    /// forge PRIMEINC delta table.
    const DELTA: [u64; 8] = [6, 4, 2, 4, 2, 4, 6, 2];
    const MODULUS_BITS: u32 = 4096;

    /// NIST SP 800-90A HMAC_DRBG(SHA-256), no prediction resistance, no
    /// additional input — matches `hmac-drbg` 1.0.1.
    pub(crate) struct Drbg {
        k: [u8; 32],
        v: [u8; 32],
    }

    /// One HMAC-SHA-256 evaluation. The key is padded to the SHA-256
    /// block size and passed to `Mac::new`, which is infallible.
    fn hmac_once(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
        use hmac::{Hmac, KeyInit, Mac as _};
        type H = Hmac<sha2::Sha256>;
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(key);
        let mut mac = <H as KeyInit>::new(&block.into());
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    impl Drbg {
        pub(crate) fn new(entropy: &[u8]) -> Self {
            let mut drbg = Self {
                k: [0; 32],
                v: [1; 32],
            };
            drbg.update(Some(entropy));
            drbg
        }

        fn update(&mut self, provided: Option<&[u8]>) {
            let mut seed: Vec<u8> = self.v.to_vec();
            seed.push(0x00);
            if let Some(p) = provided {
                seed.extend_from_slice(p);
            }
            self.k = hmac_once(&self.k, &[&seed]);
            self.v = hmac_once(&self.k, &[&self.v]);
            if let Some(p) = provided {
                let mut seed2: Vec<u8> = self.v.to_vec();
                seed2.push(0x01);
                seed2.extend_from_slice(p);
                self.k = hmac_once(&self.k, &[&seed2]);
                self.v = hmac_once(&self.k, &[&self.v]);
            }
        }

        /// `hmac-drbg`'s `generate(len)` returns `len` bytes and updates
        /// state once at the end.
        pub(crate) fn generate(&mut self, n: usize) -> Zeroizing<Vec<u8>> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                self.v = hmac_once(&self.k, &[&self.v]);
                out.extend_from_slice(&self.v);
            }
            out.truncate(n);
            self.update(None);
            Zeroizing::new(out)
        }
    }

    /// forge `rand(b)`: `(b>>3)+1` DRBG bytes, big-endian, with the
    /// jsbn first-byte masking rule.
    fn rand(drbg: &mut Drbg, b: u32) -> BoxedUint {
        let n = ((b >> 3) + 1) as usize;
        let mut bytes = drbg.generate(n);
        let rem = b & 7;
        if let Some(first) = bytes.get_mut(0) {
            *first = if rem == 0 {
                0
            } else {
                *first & ((1 << rem) - 1)
            };
        }
        BoxedUint::from_be_slice_vartime(&bytes)
    }

    /// `n mod m` for small `m` (single-limb division; `Limb` is u32 on
    /// 32-bit targets, so the widening is real there).
    #[allow(
        clippy::useless_conversion,
        reason = "widening is real on 32-bit targets"
    )]
    fn to_limb(n: &BoxedUint, m: u64) -> u64 {
        let Ok(l) = u32::try_from(m) else {
            return 0;
        };
        let Some(div) = NonZero::new(Limb::from(l)).into_option() else {
            return 0;
        };
        u64::from(n.div_rem_limb(div).1.0)
    }

    const SMALL_PRIMES_TABLE: &[u64] = &[
        7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
        103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
        197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
        419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521,
        523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
        643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757,
        761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881,
        883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
        1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103,
        1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
        1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319,
        1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
        1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553,
        1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
        1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777,
        1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
        1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011,
        2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
        2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251,
        2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
        2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467,
        2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617,
        2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711,
        2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
        2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953,
        2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
        3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217,
        3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
        3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463,
        3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571,
        3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691,
        3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821,
        3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929,
        3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057,
        4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201,
        4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
        4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451,
        4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
        4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703,
        4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
        4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969,
        4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
        5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231,
        5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
        5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483,
        5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
        5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741,
        5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
        5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011,
        6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
        6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269,
        6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
        6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547,
        6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
        6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793,
        6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
        6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039,
        7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
        7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333,
        7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
        7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591,
        7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
        7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877,
        7879, 7883, 7901, 7907, 7919,
    ];

    /// Probable-prime test matching forge's verdicts: jsbn's `lowprimes`
    /// trial-division sieve, then Miller-Rabin. forge runs `t` random-base
    /// rounds (2 at 2048 bits); two fixed bases are equivalent strength —
    /// verdicts agree on every real prime and on composites with margin.
    fn is_probable_prime(n: &BoxedUint) -> bool {
        use crypto_bigint::{Odd, U2048};
        use crypto_primes::hazmat::{MillerRabin, Primality};
        /// jsbn `lowprimes` sieve equivalent: trial division by the
        /// first ~1000 primes (candidates are already `1 mod 30`, so the
        /// sieve starts at 7). Each check is a single-limb `div_rem`.
        const SMALL_PRIMES: &[u64] = SMALL_PRIMES_TABLE;
        for p in SMALL_PRIMES {
            if to_limb(n, *p) == 0 {
                return false;
            }
        }
        // Miller-Rabin on fixed-size `U2048` is much faster than the
        // boxed Montgomery ops; candidates are exactly 2048 bits.
        let mut bytes = alloc::vec![0u8; 256];
        let raw = n.to_be_bytes_trimmed_vartime();
        let Some(tail) = bytes.get_mut(256 - raw.len()..) else {
            return false;
        };
        tail.copy_from_slice(&raw);
        let wide = U2048::from_be_slice(&bytes);
        let Some(odd) = Odd::new(wide).into_option() else {
            return false;
        };
        let mr = MillerRabin::new(odd);
        for base in [2u64, 3] {
            let b = U2048::from(base);
            if mr.test(&b) == Primality::Composite {
                return false;
            }
        }
        true
    }

    /// forge `PRIMEINC`: 30k+1-aligned candidates with the delta table;
    /// restart with fresh `rand(b)` if the candidate exceeds `b` bits.
    fn prime(drbg: &mut Drbg, b: u32) -> BoxedUint {
        /// `n = rand(b)` with bit `b-1` set, then `n += 31 - (n mod 30)`
        /// so candidates are `≡ 1 (mod 30)`.
        fn aligned(drbg: &mut Drbg, b: u32) -> BoxedUint {
            let x = rand(drbg, b);
            // Set bit `b-1` (forge "force MSB") via a big-endian addend:
            // `BoxedUint::shl` needs precision covering `b` bits, so build
            // `2^(b-1)` from raw bytes instead.
            let x = if bool::from(x.bit(b - 1).not()) {
                let mut top = alloc::vec![1u8 << ((b - 1) % 8)];
                top.resize((b / 8) as usize, 0);
                x.wrapping_add(BoxedUint::from_be_slice_vartime(&top))
            } else {
                x
            };
            let rem30 = to_limb(&x, 30);
            x.wrapping_add(BoxedUint::from(Limb::from(31 - rem30)))
        }
        let mut n = aligned(drbg, b);
        let mut k = 0usize;
        loop {
            if n.bits_vartime() > b {
                n = aligned(drbg, b);
                k = 0;
            } else if is_probable_prime(&n) {
                return n;
            } else {
                n = n.wrapping_add(BoxedUint::from(Limb::from(
                    DELTA.get(k % 8).copied().unwrap_or(6),
                )));
                k += 1;
            }
        }
    }

    /// Extended-Euclid inverse `a⁻¹ mod m` (works for even `m`).
    #[expect(clippy::many_single_char_names, reason = "RSA math names")]
    fn inv_mod(a: &BoxedUint, m: &BoxedUint) -> Result<BoxedUint, Error> {
        let (mut old_r, mut r) = (m.clone(), a.clone());
        // signed coefficients tracked as residues mod m
        let (mut old_s, mut s) = (
            BoxedUint::from(Limb::from(0u8)),
            BoxedUint::from(Limb::from(1u8)),
        );
        let Some(nzm) = NonZero::new(m.clone()).into_option() else {
            return Err(Error::InvalidKey(alloc::string::String::from(
                "zero modulus",
            )));
        };
        while !bool::from(r.is_zero()) {
            let Some(nzr) = NonZero::new(r.clone()).into_option() else {
                return Err(Error::InvalidKey(alloc::string::String::from(
                    "zero remainder",
                )));
            };
            let (q, rem) = old_r.div_rem_vartime(&nzr);
            old_r = r;
            r = rem;
            // new_s = old_s - q*s  (mod m)
            let qs = q.concatenating_mul(&s);
            let qs_mod = qs.rem_vartime(&nzm);
            let new_s = if old_s < qs_mod {
                m.wrapping_sub(&qs_mod)
                    .wrapping_add(&old_s)
                    .rem_vartime(&nzm)
            } else {
                old_s.wrapping_sub(&qs_mod)
            };
            old_s = s;
            s = new_s;
        }
        if bool::from(old_r.is_one().not()) {
            return Err(Error::InvalidKey(alloc::string::String::from(
                "not invertible",
            )));
        }
        Ok(old_s.rem_vartime(&nzm))
    }

    /// forge `_generateKeyPair` finish: `if p < q` swap runs on every call,
    /// then the regeneration branches in order. `next_prime` draws a fresh
    /// 2048-bit candidate; factored out so every branch is unit-testable.
    pub(crate) fn finish(
        mut p: BoxedUint,
        mut q: BoxedUint,
        mut next_prime: impl FnMut() -> BoxedUint,
    ) -> (BoxedUint, BoxedUint) {
        loop {
            if p < q {
                core::mem::swap(&mut p, &mut q);
            }
            if to_limb(&p.wrapping_sub(BoxedUint::from(Limb::from(1u8))), E) == 0 {
                p = next_prime();
                continue;
            }
            if to_limb(&q.wrapping_sub(BoxedUint::from(Limb::from(1u8))), E) == 0 {
                q = next_prime();
                continue;
            }
            if p.concatenating_mul(&q).bits_vartime() != MODULUS_BITS {
                q = next_prime();
                continue;
            }
            return (p, q);
        }
    }

    #[expect(clippy::many_single_char_names, reason = "RSA math names")]
    pub(super) fn generate(seed: &[u8]) -> Result<RsaKey, Error> {
        let mut drbg = Drbg::new(seed);
        let p0 = prime(&mut drbg, MODULUS_BITS / 2);
        let q0 = prime(&mut drbg, MODULUS_BITS / 2);
        let (p, q) = finish(p0, q0, || prime(&mut drbg, MODULUS_BITS / 2));
        let e = BoxedUint::from(Limb::from(E));
        let phi = p
            .wrapping_sub(BoxedUint::from(Limb::from(1u8)))
            .concatenating_mul(&q.wrapping_sub(BoxedUint::from(Limb::from(1u8))));
        let d = inv_mod(&e, &phi)?;
        let nonzero = |u: &BoxedUint| {
            NonZero::new(u.clone())
                .into_option()
                .ok_or_else(|| Error::InvalidKey(alloc::string::String::from("zero value")))
        };
        let dp = d.rem_vartime(&nonzero(&p.wrapping_sub(BoxedUint::from(Limb::from(1u8))))?);
        let dq = d.rem_vartime(&nonzero(&q.wrapping_sub(BoxedUint::from(Limb::from(1u8))))?);
        let qi = inv_mod(&q, &p)?;
        let n = p.concatenating_mul(&q);
        Ok(RsaKey {
            n,
            d,
            p,
            q,
            dp,
            dq,
            qi,
        })
    }

    fn b64u(b: &[u8]) -> alloc::string::String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    /// WebCrypto-style JWK export form: minimal big-endian base64url
    /// fields.
    pub(super) fn jwk(key: &RsaKey) -> Zeroizing<alloc::string::String> {
        let f = |u: &BoxedUint| b64u(&u.to_be_bytes_trimmed_vartime());
        let mut out = alloc::string::String::with_capacity(5600);
        out.push_str("{\"kty\":\"RSA\",\"e\":\"AQAB\"");
        for (k, v) in [
            ("n", f(&key.n)),
            ("d", f(&key.d)),
            ("p", f(&key.p)),
            ("q", f(&key.q)),
            ("dp", f(&key.dp)),
            ("dq", f(&key.dq)),
            ("qi", f(&key.qi)),
        ] {
            out.push_str(",\"");
            out.push_str(k);
            out.push_str("\":\"");
            out.push_str(&v);
            out.push('\"');
        }
        out.push('}');
        Zeroizing::new(out)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec::Vec;
    use crypto_bigint::BoxedUint;
    use hex;

    fn big(hexstr: &str) -> BoxedUint {
        BoxedUint::from_be_slice_vartime(&hex::decode(hexstr).unwrap())
    }
    /// 2^2047 ("80" + 255 zero bytes)
    fn a() -> BoxedUint {
        let mut b = alloc::vec![0x80u8];
        b.resize(256, 0);
        BoxedUint::from_be_slice_vartime(&b)
    }
    /// 2^2048 - 1 (all-ones)
    fn b() -> BoxedUint {
        BoxedUint::from_be_slice_vartime(&[0xffu8; 256])
    }
    /// (x-1) % 65537 == 0 — 65537·2^2031 + 1 (bitlen 2048)
    fn p_bad() -> BoxedUint {
        big(&alloc::format!("800080{:0>506}01", ""))
    }
    /// (x-1) % 65537 == 0 — 65537·2^2030 + 1 (bitlen 2047)
    fn q_bad() -> BoxedUint {
        big(&alloc::format!("400040{:0>506}01", ""))
    }
    fn queued(
        v: Vec<BoxedUint>,
    ) -> (
        impl FnMut() -> BoxedUint,
        std::rc::Rc<std::cell::Cell<usize>>,
    ) {
        use std::cell::Cell;
        use std::rc::Rc;
        let n = Rc::new(Cell::new(0usize));
        let n2 = Rc::clone(&n);
        let mut it = v.into_iter();
        (
            move || {
                n2.set(n2.get() + 1);
                it.next().unwrap_or_else(b)
            },
            n,
        )
    }

    #[test]
    fn finish_initial_swap() {
        // p < q at entry → swap; then bitlen(A·B)=4095 → one q regen.
        let (next, ncalls) = queued(alloc::vec![b()]);
        let (p, q) = super::rsa::finish(a(), b(), next);
        assert_eq!(ncalls.get(), 1);
        assert_eq!(p, b());
        assert_eq!(q, b());
    }

    #[test]
    fn finish_regen_p_keeps_q_and_swaps_again() {
        // p_bad ≡ 1 mod e → initial swap puts p_bad in q position → regen
        // q once for e, once more for bitlen(B·a)=4095.
        let (next, ncalls) = queued(alloc::vec![a(), b()]);
        let (p, q) = super::rsa::finish(p_bad(), b(), next);
        assert_eq!(ncalls.get(), 2);
        assert_eq!(p, b());
        assert_eq!(q, b());
    }

    #[test]
    fn finish_regen_q_on_e() {
        // q_bad ≡ 1 mod e → regenerate q; new q = b() ≥ p → ok, B·A = 4095
        // → regen q again with b().
        let (next, ncalls) = queued(alloc::vec![b()]);
        let (p, q) = super::rsa::finish(b(), q_bad(), next);
        assert_eq!(ncalls.get(), 1);
        assert_eq!(p, b());
        assert_eq!(q, b());
    }

    #[test]
    fn finish_bitlen_regen_q_larger_swaps() {
        // p=a(), q=a() → p·q bitlen 4094 → regen q to b() which is LARGER
        // than p → must swap. Then (b()-1)%e!=0, B·B bitlen 4096 → done.
        let (next, ncalls) = queued(alloc::vec![b()]);
        let (p, q) = super::rsa::finish(a(), a(), next);
        // regen 1: q→b() (larger than p → swapped on next pass); then
        // bitlen(b·a)=4095 → regen 2: q→b() → done.
        assert_eq!(ncalls.get(), 2);
        assert_eq!(p, b());
        assert_eq!(q, b());
    }

    #[test]
    fn finish_chain_of_regens() {
        // p_bad → regen (p→a); q_bad → regen (q→a); bitlen(a·a)=4094 →
        // regen (q→b > p) → swap → done.
        let (next, ncalls) = queued(alloc::vec![a(), a(), b(), b()]);
        let (p, q) = super::rsa::finish(p_bad(), q_bad(), next);
        // calls: regen p→a, regen q→a, regen q→b (bitlen), regen q→b
        // (bitlen(b·a)=4095 again) → done.
        assert_eq!(ncalls.get(), 4);
        assert_eq!(p, b());
        assert_eq!(q, b());
    }

    /// NIST CAVP `HMAC_DRBG` SHA-256 vectors from vectors/hmac-drbg.json:
    /// instantiate with entropy‖nonce, generate 128 bytes twice, the
    /// second output is `returned_bits`.
    #[test]
    fn drbg_cavp_vectors() {
        use serde_json::Value;
        let doc: Value =
            serde_json::from_str(include_str!("../../../../vectors/hmac-drbg.json")).unwrap();
        let field = |v: &Value, k: &str| {
            alloc::string::String::from(v.get(k).and_then(Value::as_str).unwrap())
        };
        for v in doc.get("vectors").and_then(Value::as_array).unwrap() {
            let mut seed = hex::decode(field(v, "entropy")).unwrap();
            seed.extend_from_slice(&hex::decode(field(v, "nonce")).unwrap());
            let mut drbg = super::rsa::Drbg::new(&seed);
            drbg.generate(128);
            let out = drbg.generate(128);
            assert_eq!(
                hex::encode(&*out),
                field(v, "returned_bits"),
                "count {:?}",
                v.get("count")
            );
        }
    }

    #[test]
    fn rsa_key_is_deterministic_shape() {
        use crate::Chain as _;
        let w = crate::Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let account = super::Arweave::new(false)
            .derive(&w, &"m".parse::<crate::DerivationPath>().unwrap())
            .unwrap();
        assert_eq!(
            account.address,
            "l55sI4sCbT9d9AV6WKz2DQpnW4Ld0EcBAZv-CMv_HAQ"
        );
        assert!(account.private_key.starts_with("{\"kty\":\"RSA\""));
        assert!(
            super::Arweave::new(false)
                .derive(&w, &"m/44'/472'/0'/0/0".parse().unwrap())
                .is_err()
        );
    }
}
