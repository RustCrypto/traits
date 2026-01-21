//! Documentation macros.
//!
//! These are used for writing redundant documentation that shows how to use the trait-based
//! interface with a concrete crate/type.

/// Write the "Usage" section of the toplevel documentation, using the given `$aead` type in
/// code examples.
#[doc(hidden)]
#[macro_export]
#[rustfmt::skip]
macro_rules! doc_usage {
    ($aead:ident) => {
        concat!(
            "# Usage\n",
            "\n",
            "Simple usage (allocating, no associated data):\n",
            "\n",
            "```\n",
            "use ", env!("CARGO_CRATE_NAME"), "::{\n",
            "    aead::{Aead, AeadCore, KeyInit, rand_core::OsRng},\n",
            "    ", stringify!($aead), ", Nonce, Key\n",
            "};\n",
            "\n",
            "// The encryption key can be generated randomly:\n",
            "let key = ", stringify!($aead), "::generate_key().expect(\"generate key\");\n",
            "```\n"
        )
    };
}
