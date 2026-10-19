//! End-to-end tests driving the `kobe` binary: generate/import, JSON output,
//! reveal gating, stdin import, 4-letter prefix expansion, and error paths.
#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "integration tests link deps indirectly and CLI tests intentionally panic on unexpected output"
)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const M12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// The same mnemonic written as 4-letter prefixes ("about" is unique at "abou").
const M12_PREFIX: &str = "aban aban aban aban aban aban aban aban aban aban aban abou";
const EVM_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const EVM_PRIVATE: &str = "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
const BTC_P2WPKH: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const BTC_P2TR: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
const SOL_ADDRESS: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";

fn kobe(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kobe"))
        .args(args)
        .output()
        .unwrap()
}

fn kobe_stdin(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kobe"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn parsed(out: &Output) -> Value {
    serde_json::from_str(&stdout(out)).unwrap()
}

fn ok_json(args: &[&str]) -> Value {
    let out = kobe(&[args, &["--json"]].concat());
    assert!(out.status.success(), "{args:?} failed: {out:?}");
    parsed(&out)
}

#[test]
fn mnemonic_generates_word_counts() {
    for (flag, words) in [("12", 12), ("24", 24)] {
        let out = kobe(&["mnemonic", "-w", flag]);
        assert!(out.status.success(), "mnemonic -w {flag}");
        assert_eq!(stdout(&out).split_whitespace().count(), words, "word count");
    }
    let out = kobe(&["mnemonic", "-w", "7"]);
    assert!(!out.status.success(), "invalid word count must fail");
}

#[test]
fn evm_import_and_styles() {
    let out = kobe(&["evm", "-m", M12]);
    let text = stdout(&out);
    assert!(out.status.success(), "evm import failed");
    assert!(text.contains(EVM_ADDRESS), "expected EIP-55 address");
    assert!(text.contains("m/44'/60'/0'/0/0"), "expected path");
    // Secrets stay hidden without --reveal.
    assert!(text.contains("<hidden>"), "secrets must be hidden");
    assert!(!text.contains(M12), "mnemonic must not leak");
    assert!(!text.contains(EVM_PRIVATE), "private key must not leak");
}

#[test]
fn evm_reveal_shows_secrets() {
    let out = kobe(&["evm", "-m", M12, "--reveal"]);
    let text = stdout(&out);
    assert!(out.status.success(), "reveal failed");
    assert!(text.contains(M12), "mnemonic must be shown");
    assert!(text.contains(EVM_PRIVATE), "private key must be shown");
}

#[test]
fn evm_json_output() {
    let out = kobe(&[
        "evm",
        "-m",
        M12,
        "-s",
        "ledger-live",
        "-i",
        "1",
        "--json",
        "-r",
    ]);
    assert!(out.status.success(), "json output failed");
    let v = parsed(&out);
    assert_eq!(v["chain"], "evm", "chain field");
    assert_eq!(v["style"], "ledger-live", "style field");
    assert_eq!(v["template"], "m/44'/60'/{i}'/0/0", "template field");
    assert_eq!(v["options"], json!({}), "no chain options");
    assert_eq!(v["mnemonic"], M12, "revealed mnemonic");
    assert_eq!(v["passphrase"], false, "passphrase flag");
    let account = &v["accounts"][0];
    assert_eq!(account["index"], 1, "index field");
    assert_eq!(account["path"], "m/44'/60'/1'/0/0", "path field");
    assert!(
        account["address"].as_str().unwrap().starts_with("0x"),
        "evm address format"
    );
    assert!(
        account["private_key"].as_str().unwrap().starts_with("0x"),
        "revealed private key"
    );
}

#[test]
fn evm_style_aliases() {
    for style in ["ledger-live", "LEDGER-LIVE"] {
        assert_eq!(
            ok_json(&["evm", "-m", M12, "-s", style])["style"],
            "ledger-live",
            "style alias {style}"
        );
    }
    assert_eq!(
        ok_json(&["evm", "-m", M12, "-s", "mew"])["style"],
        "ledger-legacy",
        "mew alias"
    );
}

#[test]
fn bitcoin_kinds_and_networks() {
    for (kind, prefix) in [
        ("p2pkh", "1"),
        ("p2sh-p2wpkh", "3"),
        ("p2wpkh", "bc1q"),
        ("p2tr", "bc1p"),
    ] {
        let v = ok_json(&["bitcoin", "-m", M12, "--type", kind]);
        assert_eq!(v["options"]["type"], kind, "options.type field");
        assert!(
            v["accounts"][0].as_object().unwrap()["address"]
                .as_str()
                .unwrap()
                .starts_with(prefix),
            "{kind} address prefix"
        );
    }
    assert_eq!(
        ok_json(&["bitcoin", "-m", M12, "--type", "p2wpkh"])["accounts"][0]["address"],
        BTC_P2WPKH,
        "bip84 address"
    );
    assert_eq!(
        ok_json(&["bitcoin", "-m", M12, "--type", "p2tr"])["accounts"][0]["address"],
        BTC_P2TR,
        "bip86 address"
    );
    assert_eq!(
        ok_json(&["bitcoin", "-m", M12, "--network", "testnet"])["accounts"][0]["path"],
        "m/84'/1'/0'/0/0",
        "testnet coin type"
    );
    assert!(
        ok_json(&["bitcoin", "-m", M12, "--network", "regtest"])["accounts"][0]["address"]
            .as_str()
            .unwrap()
            .starts_with("bcrt1q"),
        "regtest hrp"
    );
}

#[test]
fn bitcoin_account_style_alias() {
    let v = ok_json(&["bitcoin", "-m", M12, "-s", "ledger-live", "--type", "p2tr"]);
    assert_eq!(v["style"], "account", "alias resolves to canonical id");
    assert_eq!(v["accounts"][0]["path"], "m/86'/0'/0'/0/0", "account path");
}

#[test]
fn solana_derives_address() {
    assert_eq!(
        ok_json(&["solana", "-m", M12])["accounts"][0]["address"],
        SOL_ADDRESS,
        "solana address"
    );
    assert_eq!(
        ok_json(&["sol", "-m", M12])["chain"],
        "solana",
        "ticker alias"
    );
    // Ledger Live's non-iterating solanaMain mode.
    let root = ok_json(&["solana", "-m", M12, "-s", "root"]);
    assert_eq!(root["style"], "root", "root style id");
    assert_eq!(root["accounts"][0]["path"], "m/44'/501'", "root path");
    assert_eq!(root["accounts"][0]["index"], Value::Null, "non-iterating");
    assert_eq!(
        root["accounts"][0]["address"], "D2PPQSYFe83nDzk96FqGumVU8JA7J8vj2Rhjc2oXzEi5",
        "root address"
    );
}

#[test]
fn stdin_and_prefix_expansion() {
    let out = kobe_stdin(&["bitcoin", "-m", "-", "--json"], &format!("{M12}\n"));
    assert!(out.status.success(), "stdin import failed");
    assert_eq!(
        parsed(&out)["accounts"][0]["address"],
        BTC_P2WPKH,
        "stdin mnemonic"
    );
    // 4-letter prefixes expand to the identical derivation.
    assert_eq!(
        ok_json(&["bitcoin", "-m", M12_PREFIX])["accounts"][0]["address"],
        BTC_P2WPKH,
        "prefix expansion"
    );
}

#[test]
fn custom_path_template() {
    let v = ok_json(&["evm", "-m", M12, "--path", "m/44'/60'/0'/0/{i}", "-c", "2"]);
    assert_eq!(v["style"], "custom", "custom style id");
    assert_eq!(v["accounts"].as_array().unwrap().len(), 2, "account count");
    assert_eq!(v["accounts"][1]["path"], "m/44'/60'/0'/0/1", "second path");
    // A template without {i} yields exactly one account.
    let fixed = ok_json(&["evm", "-m", M12, "--path", "m/44'/60'/0'/0/0", "-c", "5"]);
    assert_eq!(
        fixed["accounts"].as_array().unwrap().len(),
        1,
        "fixed path count"
    );
    assert_eq!(
        fixed["accounts"][0]["index"],
        Value::Null,
        "index is null for a fixed path"
    );
}

#[test]
fn errors_exit_nonzero() {
    let bad_words = kobe(&["evm", "-m", "abandon bogus words"]);
    assert!(!bad_words.status.success(), "invalid mnemonic must fail");
    // JSON mode reports {"error": ...} on stdout with exit 1.
    let bad_prefix = kobe(&["evm", "-m", "abandon bogus", "--json"]);
    assert_eq!(bad_prefix.status.code(), Some(1), "json error exit code");
    let error = parsed(&bad_prefix)["error"].as_str().unwrap().to_owned();
    assert_eq!(
        error, "word 2 is not a BIP-39 English word or prefix",
        "error reports the word position"
    );
    assert!(!error.contains("bogus"), "error must not echo the word");
    // A short non-word keeps the plain "not a word" message.
    let short = parsed(&kobe(&["evm", "-m", "abandon zz", "--json"]))["error"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(short, "word 2 is not a BIP-39 English word");
    // Unknown style lists the available ones.
    let bad_style = kobe(&["evm", "-m", M12, "-s", "bogus", "--json"]);
    assert!(
        parsed(&bad_style)["error"]
            .as_str()
            .unwrap()
            .contains("ledger-live"),
        "style error lists options"
    );
    // -w conflicts with -m.
    assert!(
        !kobe(&["bitcoin", "-m", M12, "-w", "24"]).status.success(),
        "-w must conflict with -m"
    );
    // --path conflicts with -s.
    assert!(
        !kobe(&[
            "bitcoin",
            "-m",
            M12,
            "-s",
            "standard",
            "--path",
            "m/84'/0'/0'/0/{i}"
        ])
        .status
        .success(),
        "--path must conflict with -s"
    );
    // Index overflow past 2^31-1 is rejected.
    let overflow = kobe(&["solana", "-m", M12, "-i", "2147483647", "-c", "2", "--json"]);
    assert!(
        parsed(&overflow)["error"]
            .as_str()
            .unwrap()
            .contains("2147483647"),
        "index overflow rejected"
    );
    // Hardened-only chain rejects a non-hardened custom path.
    let non_hardened = kobe(&["solana", "-m", M12, "--path", "m/44'/501'/0", "--json"]);
    assert!(
        parsed(&non_hardened)["error"]
            .as_str()
            .unwrap()
            .contains("hardened"),
        "non-hardened path rejected"
    );
}

/// Every layer-2 chain end-to-end through the CLI, checking the first
/// account address byte-for-byte against the generated reference vectors.
#[test]
fn new_chains_smoke() {
    let cases: &[(&[&str], &str)] = &[
        (
            &["litecoin", "-m", M12],
            "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh",
        ),
        (
            &["dogecoin", "-m", M12],
            "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC",
        ),
        (
            &["bitcoin-cash", "-m", M12],
            "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6",
        ),
        (&["tron", "-m", M12], "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),
        (
            &["cosmos", "-m", M12],
            "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
        ),
        (
            &["cosmos", "-m", M12, "--chain", "injective"],
            "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz",
        ),
        (&["xrpl", "-m", M12], "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3"),
        (
            &["filecoin", "-m", M12],
            "f1qode47ievxlxzk6z2viuovedabmn3tq6t57uqhq",
        ),
        (
            &["filecoin", "-m", M12, "--network", "testnet"],
            "t1qode47ievxlxzk6z2viuovedabmn3tq6t57uqhq",
        ),
        (
            &["kaspa", "-m", M12],
            "kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh",
        ),
        (
            &["kaspa", "-m", M12, "--encoding", "onekey"],
            "kaspa:qqhn4wqjhza6anql6k2v9cwez23jatxvygv9dc0qs799evcjkgmsqjd7yc593",
        ),
        (
            &["nostr", "-m", M12],
            "npub1az708q3kd9zy6z6f44zav5ygvdwelkzspf6mtusttx47lft2z38sghk0w7",
        ),
        (
            &["spark", "-m", M12],
            "spark1pgss9qfk8ygtphqqzkj2yhn43k3s7r3g8z822ffvpcm38ym094800574x5numh",
        ),
        (
            &["spark", "-m", M12, "--network", "regtest"],
            "sparkrt1pgssy6vty7krpze82ecm8j39gd35v35aqjjmhftc4culawsavkyh564u2uv8v0",
        ),
        (
            &["casper", "-m", M12],
            "020357f9e27d8125932c5e6fd52babb1a114bc89363f2f56c7860bb594f74523342b",
        ),
        (
            &["sui", "-m", M12],
            "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1",
        ),
        (
            &["aptos", "-m", M12],
            "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf",
        ),
        (
            &["ton", "-m", M12],
            "UQAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-RKY",
        ),
        (
            &["ton", "-m", M12, "--contract", "v5r1", "--testnet"],
            "0QCf9EYCGEnzNflKo0BRm4IM0g2i094C_uqgJBSBmHZMUG87",
        ),
        (
            &["stellar", "-m", M12],
            "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX",
        ),
        (
            &["near", "-m", M12],
            "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412",
        ),
        (
            &["cardano", "-m", M12],
            "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv",
        ),
        (
            &[
                "cardano",
                "-m",
                M12,
                "--master",
                "ledger",
                "--network",
                "testnet",
            ],
            "addr_test1qq2vzmtlgvjrhkq50rngh8d482zj3l20kyrc6kx4ffl3zfqayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq2glhm4",
        ),
    ];
    for (args, address) in cases {
        let v = ok_json(args);
        assert_eq!(
            v["accounts"][0]["address"].as_str().unwrap(),
            *address,
            "{args:?} address"
        );
    }
}

#[test]
fn help_lists_styles_and_enum_choices() {
    let sol_help = kobe(&["solana", "--help"]);
    let sol_text = stdout(&sol_help);
    assert!(sol_help.status.success(), "solana --help");
    assert!(sol_text.contains("bip44-change"), "style id in help");
    assert!(sol_text.contains("phantom"), "style alias in help");
    assert!(sol_text.contains("m/44'/501'/{i}'/0'"), "template in help");
    let btc_help = kobe(&["bitcoin", "--help"]);
    let btc_text = stdout(&btc_help);
    assert!(btc_text.contains("m/86'/0'/{i}'/0/0"), "btc styles in help");
    assert!(btc_text.contains("p2tr"), "--type possible values in help");
    assert!(
        btc_text.contains("regtest"),
        "--network possible values in help"
    );
}
