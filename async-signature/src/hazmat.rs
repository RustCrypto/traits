//! Hazardous Materials: low-level APIs which can be insecure if misused.
//!
//! The traits in this module are not generally recommended, and should only be
//! used in special cases where they are specifically needed.
//!
//! Using them incorrectly can introduce security vulnerabilities. Please
//! carefully read the documentation before attempting to use them.

#[deprecated(
    since = "0.6.0",
    note = "use `signature::hazmat::AsyncPrehashSigner` instead"
)]
pub use signature::hazmat::AsyncPrehashSigner;

#[cfg(feature = "rand_core")]
#[deprecated(
    since = "0.6.0",
    note = "use `signature::hazmat::AsyncRandomizedPrehashSigner` instead"
)]
pub use signature::hazmat::AsyncRandomizedPrehashSigner;
