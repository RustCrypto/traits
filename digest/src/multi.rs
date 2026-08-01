//! Multi-buffer (multi-message) hashing.
//!
//! [`MultiDigest`] hashes many **independent messages of one compile-time length `N`** at
//! once — one per SIMD lane — running the compression across all lanes simultaneously.
//! This is a different axis of parallelism from block-level `ParBlocks` (which processes
//! multiple blocks of a *single* stream): here each lane is a distinct message.
//!
//! The message length `N` and batch size `B` are const generics, so equal length and the
//! one-output-per-message count are enforced by the type system rather than checked at
//! run time — `&[&[u8; N]; B] -> [Output; B]` cannot mismatch. Messages are passed *by
//! reference* (`&[u8; N]`), so they need not be contiguous in memory. The lane count is
//! deliberately *not* exposed: it is the hardware detail (AVX2 vs AVX-512 width) that an
//! implementation abstracts over via its own runtime dispatch.

use crate::array::{Array, ArraySize};
use crate::{Digest, Output, OutputSizeUser};

/// A stateless multi-buffer kernel: hash exactly `Lanes` messages of length `N` at once.
///
/// A single algorithm may provide several backend types, one per SIMD width it supports
/// (e.g. an AVX2 and an AVX-512 backend); [`MultiDigest::multi_digest`] selects among
/// them at runtime.
pub trait MultiDigestBackend: OutputSizeUser {
    /// Number of messages processed per batch. Must be at least 1 (a zero-lane backend
    /// is meaningless; drivers divide the batch by this count).
    type Lanes: ArraySize;

    /// Hash `Lanes` messages of length `N`, writing digest `i` into `out[i]`. Equal
    /// length is guaranteed by the type: every message is a `&[u8; N]`.
    fn multi_digest_lanes<const N: usize>(
        &self,
        msgs: &Array<&[u8; N], Self::Lanes>,
        out: &mut Array<Output<Self>, Self::Lanes>,
    );
}

/// Hash many independent, equal-length messages at once.
pub trait MultiDigest: Digest {
    /// Hash `B` messages of length `N`, returning digest `i` for message `i`.
    ///
    /// Equal length (`&[u8; N]`) and the one-output-per-message count (`[_; B]`) are both
    /// carried by the types and need no run-time check; the result is written directly
    /// into the returned array (`sret`), so no digest is copied. Messages are borrowed
    /// individually, so they need not be contiguous.
    ///
    /// The implementation selects a [`MultiDigestBackend`] for the current CPU, splits the
    /// batch into `Lanes`-sized groups for it, and hashes any `< Lanes` remainder with the
    /// scalar [`Digest`].
    fn multi_digest<const N: usize, const B: usize>(msgs: &[&[u8; N]; B]) -> [Output<Self>; B]
    where
        Self: Sized;
}
