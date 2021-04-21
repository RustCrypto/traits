//! Low-level elliptic curve parameters.

use crate::{Curve, FieldBytes};
use core::{convert::TryInto, fmt::Debug, mem};
use subtle::Choice;

// TODO(tarcieri): unify these into a target-width gated `sbb`
#[cfg(target_pointer_width = "32")]
use crate::util::sbb32;
#[cfg(target_pointer_width = "64")]
use crate::util::sbb64;

/// Order of an elliptic curve group.
///
/// This trait is available even when the `arithmetic` feature of the crate
/// is disabled and does not require any additional crate dependencies.
///
/// This trait is useful for supporting a baseline level of functionality
/// across curve implementations, even ones which do not provide a field
/// arithmetic backend.
// TODO(tarcieri): merge this with the `Curve` type in the next release?
pub trait Order: Curve {
    /// Type representing the "limbs" of the curves group's order on
    /// 32-bit platforms.
    #[cfg(target_pointer_width = "32")]
    type Limbs: AsRef<[u32]> + Copy + Debug;

    /// Type representing the "limbs" of the curves group's order on
    /// 64-bit platforms.
    #[cfg(target_pointer_width = "64")]
    type Limbs: AsRef<[u64]> + Copy + Debug;

    /// Order constant.
    ///
    /// Subdivided into either 32-bit or 64-bit "limbs" (depending on the
    /// target CPU's word size), specified from least to most significant.
    const ORDER: Self::Limbs;

    /// Check that the given serialized scalar field element is in range.
    ///
    /// Field element must be serialized as a big endian integer.
    #[cfg(target_pointer_width = "32")]
    fn is_scalar_repr_in_range(fe_bytes: &FieldBytes<Self>) -> Choice {
        assert_eq!(
            mem::size_of::<Self::Limbs>(),
            mem::size_of::<FieldBytes<Self>>()
        );

        let mut borrow = 0;

        for (i, chunk) in fe_bytes.as_ref().chunks(4).rev().enumerate() {
            let limb = u32::from_be_bytes(chunk.try_into().unwrap());
            borrow = sbb32(limb, Self::ORDER.as_ref()[i], borrow).1;
        }

        Choice::from((borrow as u8) & 1)
    }

    /// Check that the given scalar field repr is in range.
    ///
    /// Field element must be serialized as a big endian integer.
    #[cfg(target_pointer_width = "64")]
    fn is_scalar_repr_in_range(fe_bytes: &FieldBytes<Self>) -> Choice {
        assert_eq!(
            mem::size_of::<Self::Limbs>(),
            mem::size_of::<FieldBytes<Self>>()
        );

        let mut borrow = 0;

        for (i, chunk) in fe_bytes.as_ref().chunks(8).rev().enumerate() {
            let limb = u64::from_be_bytes(chunk.try_into().unwrap());
            borrow = sbb64(limb, Self::ORDER.as_ref()[i], borrow).1;
        }

        Choice::from((borrow as u8) & 1)
    }
}

#[cfg(all(test, feature = "dev"))]
mod tests {
    use super::Order;
    use crate::dev::MockCurve;
    use hex_literal::hex;

    const SCALAR_REPR_IN_RANGE: [u8; 32] =
        hex!("FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632550");

    const SCALAR_REPR_ORDER: [u8; 32] =
        hex!("FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551");

    const SCALAR_REPR_MAX: [u8; 32] =
        hex!("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF");

    #[test]
    fn scalar_in_range() {
        let zero_in_range = MockCurve::is_scalar_repr_in_range(&Default::default());
        assert!(bool::from(zero_in_range));

        let below_order_in_range = MockCurve::is_scalar_repr_in_range(&SCALAR_REPR_IN_RANGE.into());
        assert!(bool::from(below_order_in_range));
    }

    #[test]
    fn scalar_with_overflow() {
        let order_overflows = !MockCurve::is_scalar_repr_in_range(&SCALAR_REPR_ORDER.into());
        assert!(bool::from(order_overflows));

        let max_overflows = !MockCurve::is_scalar_repr_in_range(&SCALAR_REPR_MAX.into());
        assert!(bool::from(max_overflows));
    }
}
