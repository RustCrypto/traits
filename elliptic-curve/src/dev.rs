//! Development-related functionality.
//!
//! Helpers and types for writing tests against concrete implementations of
//! the traits in this crate.

pub mod mock_curve;

#[deprecated(
    since = "0.14.0",
    note = "import these types from the `dev::mock_curves` module"
)]
pub use mock_curve::*;
