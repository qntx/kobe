//! Derivation-path styles: named templates shared by wallet software.

use alloc::borrow::Cow;
use alloc::format;

use crate::{ChildIndex, DerivationPath, Error};

/// Placeholder for the iterated account index inside a [`Style`] template.
pub(crate) const INDEX_PLACEHOLDER: &str = "{i}";

/// A named derivation-path style for a chain.
///
/// The [`template`](Self::template) is a derivation path containing exactly
/// one `{i}` placeholder for the iterated index, or none for single-account
/// schemes. [`Style::path`] performs the expansion and validation in one
/// place, so user-supplied templates (CLI `--path`) go through the same code
/// as built-in styles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Style {
    /// Canonical identifier (the CLI `-s/--style` value).
    pub id: &'static str,
    /// Alternative identifiers accepted alongside `id` (case-insensitive).
    pub aliases: &'static [&'static str],
    /// Path template, e.g. `m/44'/60'/0'/0/{i}`.
    pub template: Cow<'static, str>,
    /// Index the CLI starts from when `-i/--index` is not given.
    pub start: u32,
    /// Human-readable list of compatible wallets, shown in help and docs.
    pub wallets: &'static str,
}

impl Style {
    /// A style with no aliases and `start = 0`.
    #[must_use]
    pub fn new(
        id: &'static str,
        template: impl Into<Cow<'static, str>>,
        wallets: &'static str,
    ) -> Self {
        Self {
            id,
            aliases: &[],
            template: template.into(),
            start: 0,
            wallets,
        }
    }

    /// Set the accepted alternative ids (matched case-insensitively).
    #[must_use]
    pub const fn aliases(mut self, aliases: &'static [&'static str]) -> Self {
        self.aliases = aliases;
        self
    }

    /// Set the default first iterated index (e.g. Spark mainnet starts at 1).
    #[must_use]
    pub const fn start(mut self, start: u32) -> Self {
        self.start = start;
        self
    }

    /// Whether the template iterates over `{i}`.
    ///
    /// When `false`, the style produces exactly one account regardless of
    /// the requested index.
    #[must_use]
    pub fn has_index(&self) -> bool {
        self.template.contains(INDEX_PLACEHOLDER)
    }

    /// Expand `{i}` with `index` and parse the result as a
    /// [`DerivationPath`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Path`] if the template contains more than one `{i}`
    /// placeholder or the expanded path fails to parse, and
    /// [`Error::IndexOutOfRange`] if `index > 2^31 - 1`.
    pub fn path(&self, index: u32) -> Result<DerivationPath, Error> {
        let template = self.template.as_ref();
        let Some((prefix, suffix)) = template.split_once(INDEX_PLACEHOLDER) else {
            return template.parse();
        };
        if suffix.contains(INDEX_PLACEHOLDER) {
            return Err(Error::Path(format!(
                "template {template:?} contains more than one {{i}} placeholder"
            )));
        }
        if index > ChildIndex::MAX {
            return Err(Error::IndexOutOfRange(u64::from(index)));
        }
        format!("{prefix}{index}{suffix}").parse()
    }
}
