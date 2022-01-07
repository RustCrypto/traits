//! Traits for handling hash to curve.

use super::MapToCurve;
use crate::{
    hash2field::{hash_to_field, ExpandMsg, FromOkm},
    Result,
};
use group::cofactor::CofactorGroup;

/// Adds hashing arbitrary byte sequences to a valid group element
pub trait GroupDigest {
    /// The field element representation for a group value with multiple elements
    type FieldElement: FromOkm + MapToCurve<Output = Self::Output> + Default + Copy;
    /// The resulting group element
    type Output: CofactorGroup<Subgroup = Self::Output>;

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
    /// let pt = ProjectivePoint::hash_from_bytes::<hash2field::ExpandMsgXmd<sha2::Sha256>>(b"test data", b"CURVE_XMD:SHA-256_SSWU_RO_");
    /// ```
    ///
    /// ## Using an extendable output function
    ///
    /// ```ignore
    /// let pt = ProjectivePoint::hash_from_bytes::<hash2field::ExpandMsgXof<sha3::Shake256>>(b"test data", b"CURVE_XOF:SHAKE-256_SSWU_RO_");
    /// ```
    ///
    fn hash_from_bytes<X: ExpandMsg>(msg: &[u8], dst: &'static [u8]) -> Result<Self::Output> {
        let mut u = [Self::FieldElement::default(), Self::FieldElement::default()];
        hash_to_field::<X, _>(msg, dst, &mut u)?;
        let q0 = u[0].map_to_curve();
        let q1 = u[1].map_to_curve();
        // Ideally we could add and then clear cofactor once
        // thus saving a call but the field elements may not
        // add properly due to the underlying implementation
        // which could result in an incorrect subgroup.
        // This is caused curve coefficients being different than
        // what is usually implemented.
        // FieldElement expects the `a` and `b` to be the original values
        // isogenies are different with curves like k256 and bls12-381.
        // This problem doesn't manifest for curves with no isogeny like p256.
        // For k256 and p256 clear_cofactor doesn't do anything anyway so it will be a no-op.
        Ok(q0.clear_cofactor() + q1.clear_cofactor())
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
    fn encode_from_bytes<X: ExpandMsg>(msg: &[u8], dst: &'static [u8]) -> Result<Self::Output> {
        let mut u = [Self::FieldElement::default()];
        hash_to_field::<X, _>(msg, dst, &mut u)?;
        let q0 = u[0].map_to_curve();
        Ok(q0.clear_cofactor())
    }
}
