//! Hashing many independent messages at once.
//!
//! An ordinary hash reads one message and produces one digest. The compression function
//! inside it is serial — block *n* depends on block *n−1* — so a single message cannot be
//! spread across SIMD lanes. But *different* messages are completely independent of one
//! another, so several of them can be hashed side by side, one per lane, with the same
//! instructions driving all lanes at once. That is what this module exposes.
//!
//! This is a different kind of parallelism from
//! [`ParBlocks`](crate::common::ParBlocks), which processes several blocks of a *single*
//! stream. Here each lane is a separate message.
//!
//! # Two layers, each hiding one detail
//!
//! Two unrelated things must be kept apart, and each layer hides one of them from the layer
//! above:
//!
//! 1. **[`MultiUpdateBackend`] hides the implementation.** One backend is one concrete way
//!    of doing the work — an AVX2 routine, an AVX-512 routine, a plain portable one, or
//!    some future instruction set. Each has a lane count fixed by the hardware it targets.
//!    An algorithm provides as many backends as it has implementations.
//!
//! 2. **[`MultiUpdateCore`] / [`MultiFixedOutputCore`] hide the lane count.** Callers ask
//!    to hash some number of messages; that number is a property of their workload and has
//!    nothing to do with how wide the machine is. The core picks a backend suitable for the
//!    current CPU, splits the messages across it, and handles any leftover that does not
//!    fill a full set of lanes. Above this layer, lane counts never appear.
//!
//! These mirror the layering this crate already uses for ordinary hashing:
//!
//! | layer | hides | here | single-stream analogue |
//! |-------|-------|------|------------------------|
//! | 1 | the implementation | [`MultiUpdateBackend`] | [`BlockCipherEncBackend`] |
//! | 2 | the lane count | [`MultiUpdateCore`], [`MultiFixedOutputCore`] | [`UpdateCore`], [`FixedOutputCore`] |
//!
//! [`BlockCipherEncBackend`]: https://docs.rs/cipher
//! [`UpdateCore`]: crate::block_api::UpdateCore
//! [`FixedOutputCore`]: crate::block_api::FixedOutputCore
//!
//! # Blocks in, a final tail at the end
//!
//! [`MultiUpdateCore::update_blocks`] accepts whole blocks and nothing else. A whole block
//! can be read straight from wherever the caller already keeps it, so no message data is
//! copied into a staging buffer, and each lane is borrowed separately, so the messages do
//! not need to sit next to each other in memory. Only [`finalize_fixed_core`] takes a
//! sub-block tail — that is the last call, so it can pad without breaking the zero-copy
//! rule for the bulk of the message.
//!
//! This matters most when a message is built from pieces — say a domain-separation tag
//! followed by a large payload. With a byte-oriented API the tag and payload must be
//! concatenated somewhere before hashing, which copies the payload. Here the tag is
//! absorbed with [`update_blocks_shared`](MultiUpdateCore::update_blocks_shared) (one copy
//! for all lanes, not one per lane) and the payload is absorbed where it already lives.
//!
//! The only bytes this module ever copies are the one or two final padded blocks, which do
//! not exist in the message and so must be built during finalization.
//!
//! [`finalize_fixed_core`]: MultiFixedOutputCore::finalize_fixed_core
//!
//! # What the types guarantee
//!
//! Every call supplies the same amount of data for every lane — the arguments are arrays of
//! equal-length pieces (`[&[u8; N]; MSGS]`) — so all lanes advance in step by construction.
//! No length check is needed at run time, and unequal lengths fail to compile rather than
//! panicking.
//!
//! # Example
//!
//! Hashing a batch of fixed-size records, each prefixed by a shared tag, without copying
//! any record. `Hash` here is some algorithm implementing [`MultiDigest`]:
//!
//! ```ignore
//! use digest::multi::{MultiDigest, MultiFixedOutputCore, MultiUpdateCore};
//!
//! const BATCH: usize = 64;
//!
//! let mut core = Hash::multi_core::<BATCH>();
//!
//! // A prefix shared by every message: stored once, absorbed once.
//! core.update_blocks_shared::<1>(&tag_block);
//!
//! // Each record is absorbed where it already lives; nothing is copied.
//! core.update_blocks::<RECORD_BLOCKS>(&records);
//!
//! // Finish: no trailing bytes in this example, so the tail is empty.
//! let mut out = core::array::from_fn(|_| Default::default());
//! core.finalize_fixed_core::<0>(&[&[]; BATCH], &mut out);
//! ```

use crate::array::{Array, ArraySize};
use crate::common::{Block, BlockSizeUser};
use crate::typenum::Unsigned;
use crate::{Digest, Output, OutputSizeUser};

/// Number of messages a [`MultiUpdateBackend`] processes at once.
///
/// The multi-message analogue of [`ParBlocksSizeUser`](crate::common::ParBlocksSizeUser).
pub trait LanesSizeUser {
    /// Number of lanes (messages processed simultaneously).
    type LanesSize: ArraySize;

    /// Return the lane count.
    #[inline(always)]
    #[must_use]
    fn lanes() -> usize {
        Self::LanesSize::USIZE
    }
}

/// One run of `BLOCKS` blocks per lane, borrowed from each lane's own memory.
///
/// The multi-message analogue of [`ParBlocks`](crate::common::ParBlocks).
pub type LaneBlocks<'a, T, const BLOCKS: usize> =
    Array<&'a [Block<T>; BLOCKS], <T as LanesSizeUser>::LanesSize>;

/// One chaining value per lane.
pub type LaneStates<T> = Array<<T as MultiUpdateBackend>::State, <T as LanesSizeUser>::LanesSize>;

/// A stateless fixed-width multi-buffer kernel, e.g. an AVX2 8-lane or AVX-512 16-lane
/// implementation of one compression function.
///
/// Backends absorb whole blocks only; padding, length accounting, and digest output all
/// belong to the core, so a single backend serves every variant of an algorithm that
/// differs only in IV or truncation (e.g. SHA-256 and SHA-224).
pub trait MultiUpdateBackend: BlockSizeUser + LanesSizeUser {
    /// One lane's chaining value, e.g. `[u32; 8]` for SHA-256.
    ///
    /// All backends of a given algorithm must agree on this type, so that a core can hold
    /// the state independently of which backend the current CPU selects.
    type State: Copy + Default;

    /// Compress `BLOCKS` blocks into each lane's chaining value, reading each lane's
    /// blocks in place.
    fn update_blocks<const BLOCKS: usize>(
        &self,
        state: &mut LaneStates<Self>,
        msgs: &LaneBlocks<'_, Self, BLOCKS>,
    );
}

/// Absorbs whole blocks for `MSGS` independent messages.
///
/// The multi-message analogue of [`UpdateCore`](crate::block_api::UpdateCore). The SIMD
/// lane width does not appear here: an implementation selects a [`MultiUpdateBackend`]
/// for the current CPU and splits `MSGS` across it.
pub trait MultiUpdateCore<const MSGS: usize>: BlockSizeUser + Sized {
    /// Absorb `BLOCKS` blocks into each lane, read in place from that lane's memory.
    fn update_blocks<const BLOCKS: usize>(&mut self, msgs: &[&[Block<Self>; BLOCKS]; MSGS]);

    /// Absorb the same `BLOCKS` blocks into every lane — a shared prefix such as a domain
    /// tag or transcript header — without materializing `MSGS` copies of it.
    fn update_blocks_shared<const BLOCKS: usize>(&mut self, blocks: &[Block<Self>; BLOCKS]);
}

/// Pads and writes fixed-size digests for `MSGS` messages.
///
/// The multi-message analogue of
/// [`FixedOutputCore`](crate::block_api::FixedOutputCore), which likewise receives the
/// leftover bytes separately from the absorbed blocks.
///
/// `update_blocks` takes whole blocks so absorption stays zero-copy; `finalize` is the last
/// call, so it may take a loose, non-block-sized tail and let the core pad it. The tail is
/// one byte slice per lane, all the same length (fewer than one block) — the length is the
/// slice length, so no separate count is needed, and equal length keeps the lanes in step.
pub trait MultiFixedOutputCore<const MSGS: usize>: MultiUpdateCore<MSGS> + OutputSizeUser {
    /// Absorb each lane's `TAIL` trailing bytes, pad, and write the digests. Equal length
    /// across lanes is guaranteed by the type; `TAIL` must be shorter than one block.
    fn finalize_fixed_core<const TAIL: usize>(
        &mut self,
        tails: &[&[u8; TAIL]; MSGS],
        out: &mut [Output<Self>; MSGS],
    );

    /// Absorb the same trailing bytes into every lane, pad, and write the digests. The
    /// final padded block is then identical in all lanes, so it is built once.
    fn finalize_fixed_core_shared<const TAIL: usize>(
        &mut self,
        tail: &[u8; TAIL],
        out: &mut [Output<Self>; MSGS],
    );
}

/// Hash many independent messages at once.
///
/// The multi-message analogue of [`Digest`].
pub trait MultiDigest: Digest {
    /// The block-oriented core backing a batch of `MSGS` messages.
    type MultiCore<const MSGS: usize>: MultiFixedOutputCore<MSGS, OutputSize = Self::OutputSize>;

    /// Create the block-oriented core for `MSGS` messages.
    fn multi_core<const MSGS: usize>() -> Self::MultiCore<MSGS>;
}
