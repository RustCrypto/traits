use core::ops::Mul;

use super::MapToCurve;
use crate::hash2field::{hash_to_field, ExpandMsg, FromOkm};
use generic_array::{
    typenum::{Prod, U1, U2},
    ArrayLength,
};
use group::cofactor::CofactorGroup;

/// Adds hashing arbitrary byte sequences to a valid group element
pub trait GroupDigest {
    /// The field element representation for a group value with multiple elements
    type FieldElement: FromOkm + Default + Copy;
    /// The resulting group element
    type Output: CofactorGroup<Subgroup = Self::Output>
        + MapToCurve<FieldElement = Self::FieldElement, Output = Self::Output>;

    /// Computes the hash to curve routine according to
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html>
    /// which says
    /// Uniform encoding from byte strings to points in G.
    /// That is, the distribution of its output is statistically close
    /// to uniform in G.
    /// This function is suitable for most applications requiring a random
    /// oracle returning points in G assuming a cryptographically secure
    /// hash function is used.
    ///
    /// Examples
    ///
    /// Using a fixed size hash function
    ///
    /// ```ignore
    /// let pt = ProjectivePoint::hash_from_bytes::<hash2field::ExpandMsgXmd<sha2::Sha256>>(b"test data", b"CURVE_XMD:SHA-256_SSWU_RO_");
    /// ```
    ///
    /// Using an extendable output function
    ///
    /// ```ignore
    /// let pt = ProjectivePoint::hash_from_bytes::<hash2field::ExpandMsgXof<sha3::Shake256>>(b"test data", b"CURVE_XOF:SHAKE-256_SSWU_RO_");
    /// ```
    ///
    fn hash_from_bytes<X>(msg: &[u8], dst: &'static [u8]) -> Self::Output
    where
        X: ExpandMsg<Prod<<Self::FieldElement as FromOkm>::Length, U2>>,
        <Self::FieldElement as FromOkm>::Length: Mul<U2>,
        Prod<<Self::FieldElement as FromOkm>::Length, U2>: ArrayLength<u8>,
    {
        let u = hash_to_field::<X, _, U2>(msg, dst);
        let q0 = Self::Output::map_to_curve(u[0]);
        let q1 = Self::Output::map_to_curve(u[1]);
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
        q0.clear_cofactor() + q1.clear_cofactor()
    }

    /// Computes the encode to curve routine according to
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html>
    /// which says
    /// Nonuniform encoding from byte strings to
    /// points in G. That is, the distribution of its output is not
    /// uniformly random in G: the set of possible outputs of
    /// encode_to_curve is only a fraction of the points in G, and some
    /// points in this set are more likely to be output than others.
    fn encode_from_bytes<X>(msg: &[u8], dst: &'static [u8]) -> Self::Output
    where
        X: ExpandMsg<Prod<<Self::FieldElement as FromOkm>::Length, U1>>,
        <Self::FieldElement as FromOkm>::Length: Mul<U1>,
        Prod<<Self::FieldElement as FromOkm>::Length, U1>: ArrayLength<u8>,
    {
        let u = hash_to_field::<X, _, U1>(msg, dst);
        let q0 = Self::Output::map_to_curve(u[0]);
        q0.clear_cofactor()
    }
}
