//! Field element encoding support.

use crate::Curve;
use array::{Array, typenum::Unsigned};
use bigint::{ArrayEncoding, ByteOrder, Encoding};

/// Size of serialized field elements of this elliptic curve.
pub type FieldBytesSize<C> = <C as Curve>::FieldBytesSize;

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes<C> = Array<u8, FieldBytesSize<C>>;

/// Decode the provided [`FieldBytes`] as an integer.
///
/// Note that the resulting integer is the raw representation of the given `bytes` and is not
/// reduced by any modulus.
pub fn bytes_to_uint<C: Curve>(bytes: &FieldBytes<C>) -> C::Uint {
    C::Uint::from_slice_truncated(bytes, modulus_bits::<C>(), C::FIELD_ENDIANNESS)
}

/// Encode the provided integer as [`FieldBytes`].
///
/// Note that the output may be truncated if it overflows the width of [`FieldBytes`].
pub fn uint_to_bytes<C: Curve>(uint: &C::Uint) -> FieldBytes<C> {
    let field_bytes_len = FieldBytesSize::<C>::USIZE;
    let uint_bytes_len = <<C as Curve>::Uint as ArrayEncoding>::ByteSize::USIZE;
    debug_assert!(field_bytes_len <= uint_bytes_len);

    let mut field_bytes = FieldBytes::<C>::default();
    match C::FIELD_ENDIANNESS {
        ByteOrder::BigEndian => {
            let offset = uint_bytes_len.saturating_sub(field_bytes_len);
            field_bytes.copy_from_slice(&uint.to_be_byte_array()[offset..]);
        }
        ByteOrder::LittleEndian => {
            field_bytes.copy_from_slice(&uint.to_le_byte_array()[..field_bytes_len]);
        }
    }

    field_bytes
}

// TODO(tarcieri): store full bit precision of the modulus on `Curve`
#[allow(clippy::cast_possible_truncation)]
const fn modulus_bits<C: Curve>() -> u32 {
    (FieldBytesSize::<C>::USIZE * 8) as u32
}
