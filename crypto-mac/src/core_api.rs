//! Low-level core API traits.
use crypto_common::KeyInit;
pub use crypto_common::{AlgorithmName, CoreWrapper, FixedOutputCore, UpdateCore};

/// Marker trait for MAC algorithms.
pub trait MacCore: UpdateCore + FixedOutputCore {}

impl<T: UpdateCore + FixedOutputCore + KeyInit> super::Mac for CoreWrapper<T> {}
