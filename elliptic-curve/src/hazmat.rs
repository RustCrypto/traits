//! Hazardous materials (a.k.a. "hazmat"): low-level primitives.
//!
//! <div class="warning">
//! <b>Security️ Warning</b>
//!
//! YOU PROBABLY DON'T WANT TO USE THESE!
//!
//! If you are an end user / non-expert in cryptography, do not use these!
//! Failure to use them correctly can lead to catastrophic failures.
//! </div>

use crate::{
    CurveArithmetic, FieldBytes, Generate,
    ops::{BatchInvert, Invert, Retrieve},
};
use ff::PrimeField;
use subtle::CtOption;

/// Access to a curve's base field element type.
///
/// This trait is bounded on [`CurveArithmetic`] to provide a complete arithmetic implementation,
/// and also make the associated `FieldElement` type completely inaccessible unless this trait
/// is in scope, having been imported from this `hazmat` module so that text appears in the import.
/// We also explicitly recommend against re-exporting it so the `hazmat` keyword is easy to
/// search for.
///
/// <div class="warning">
/// <b>Security Warning</b>
///
/// Field elements are easily misused, unlike group-based abstractions. Some elliptic curves utilize
/// lazy normalization, meaning that field elements may be non-canonical leading to miscomputations.
/// We strongly recommend you avoid using this trait except for use cases that are truly dependent
/// on coordinates, such as curve point encodings or hash2curve.
/// </div>
pub trait FieldArithmetic: CurveArithmetic {
    /// Base field element type.
    type FieldElement: BatchInvert
        + Generate
        + Invert<Output = CtOption<Self::FieldElement>>
        + PrimeField<Repr = FieldBytes<Self>>
        + Retrieve<Output = Self::Uint>;
}
