//! Crate-internal macros.

/// Define a chain option enum: a `Copy` enum with the standard derives and
/// `#[non_exhaustive]`, a `pub const ALL` in declaration order, `Display`
/// rendering the canonical CLI id, and a case-insensitive `FromStr` whose
/// error lists the accepted ids.
///
/// ```ignore
/// option_enum! {
///     /// Doc comment for the enum.
///     pub enum Network {
///         /// Doc comment for the variant.
///         #[default]
///         Mainnet = "mainnet",
///         Testnet = "testnet",
///     }
/// }
/// ```
macro_rules! option_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident = $id:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        #[non_exhaustive]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                $variant,
            )+
        }

        impl $name {
            /// Every variant, in declaration (CLI) order.
            pub const ALL: [Self; { [$(stringify!($variant)),+].len() }] =
                [$(Self::$variant),+];
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(match self { $($name::$variant => $id,)+ })
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $(if s.eq_ignore_ascii_case($id) {
                    return Ok(Self::$variant);
                })+
                Err($crate::Error::InvalidValue(::alloc::format!(
                    "invalid value {s:?} (expected: {})",
                    [$($id),+].join(", ")
                )))
            }
        }
    };
}

pub(crate) use option_enum;
