//! Traits for handling hash to curve.

use super::{ExpandMsg, MapToCurve, hash_to_field};
use crate::{ProjectivePoint, Result};
use hybrid_array::typenum::Unsigned;

/// Hash arbitrary byte sequences to a valid group element.
pub trait GroupDigest: MapToCurve {
    /// The target security level in bytes:
    /// <https://www.rfc-editor.org/rfc/rfc9380.html#section-8.9-2.2>
    /// <https://www.rfc-editor.org/rfc/rfc9380.html#name-target-security-levels>
    type K: Unsigned;

    /// Computes the hash to curve routine.
    ///
    /// From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html>:
    ///
    /// > Uniform encoding from byte strings to points in G.
    /// > That is, the distribution of its output is statistically close
    /// > to uniform in G.
    /// > This function is suitable for most applications requiring a random
    /// > oracle returning points in G assuming a cryptographically secure
    /// > hash function is used.
    ///
    /// # Examples
    ///
    /// ## Using a fixed size hash function
    ///
    /// ```ignore
    /// let pt = ProjectivePoint::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(b"test data", b"CURVE_XMD:SHA-256_SSWU_RO_");
    /// ```
    ///
    /// ## Using an extendable output function
    ///
    /// ```ignore
    /// let pt = ProjectivePoint::hash_from_bytes::<ExpandMsgXof<sha3::Shake256>>(b"test data", b"CURVE_XOF:SHAKE-256_SSWU_RO_");
    /// ```
    ///
    /// # Errors
    /// See implementors of [`ExpandMsg`] for errors:
    /// - [`ExpandMsgXmd`]
    /// - [`ExpandMsgXof`]
    ///
    /// `len_in_bytes = <Self::FieldElement as FromOkm>::Length * 2`
    ///
    /// [`ExpandMsgXmd`]: crate::hash2curve::ExpandMsgXmd
    /// [`ExpandMsgXof`]: crate::hash2curve::ExpandMsgXof
    fn hash_from_bytes<'a, X: ExpandMsg<'a>>(
        msgs: &[&[u8]],
        dsts: &'a [&'a [u8]],
    ) -> Result<ProjectivePoint<Self>> {
        let mut u = [Self::FieldElement::default(), Self::FieldElement::default()];
        hash_to_field::<X, _>(msgs, dsts, &mut u)?;
        let q0 = Self::map_to_curve(u[0]);
        let q1 = Self::map_to_curve(u[1]);
        Ok(Self::add_and_map_to_subgroup(q0, q1))
    }

    /// Computes the encode to curve routine.
    ///
    /// From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html>:
    ///
    /// > Nonuniform encoding from byte strings to
    /// > points in G. That is, the distribution of its output is not
    /// > uniformly random in G: the set of possible outputs of
    /// > encode_to_curve is only a fraction of the points in G, and some
    /// > points in this set are more likely to be output than others.
    ///
    /// # Errors
    /// See implementors of [`ExpandMsg`] for errors:
    /// - [`ExpandMsgXmd`]
    /// - [`ExpandMsgXof`]
    ///
    /// `len_in_bytes = <Self::FieldElement as FromOkm>::Length`
    ///
    /// [`ExpandMsgXmd`]: crate::hash2curve::ExpandMsgXmd
    /// [`ExpandMsgXof`]: crate::hash2curve::ExpandMsgXof
    fn encode_from_bytes<'a, X: ExpandMsg<'a>>(
        msgs: &[&[u8]],
        dsts: &'a [&'a [u8]],
    ) -> Result<ProjectivePoint<Self>> {
        let mut u = [Self::FieldElement::default()];
        hash_to_field::<X, _>(msgs, dsts, &mut u)?;
        let q0 = Self::map_to_curve(u[0]);
        Ok(Self::map_to_subgroup(q0))
    }

    /// Computes the hash to field routine according to
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5>
    /// and returns a scalar.
    ///
    /// # Errors
    /// See implementors of [`ExpandMsg`] for errors:
    /// - [`ExpandMsgXmd`]
    /// - [`ExpandMsgXof`]
    ///
    /// `len_in_bytes = <Self::Scalar as FromOkm>::Length`
    ///
    /// [`ExpandMsgXmd`]: crate::hash2curve::ExpandMsgXmd
    /// [`ExpandMsgXof`]: crate::hash2curve::ExpandMsgXof
    fn hash_to_scalar<'a, X: ExpandMsg<'a>>(
        msgs: &[&[u8]],
        dsts: &'a [&'a [u8]],
    ) -> Result<Self::Scalar> {
        let mut u = [Self::Scalar::default()];
        hash_to_field::<X, _>(msgs, dsts, &mut u)?;
        Ok(u[0])
    }
}
