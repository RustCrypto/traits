//! Committing AEAD support.
//!
//! Marker trait for Committing AEADs along with constructions that give 
//! key-committing properties to normal AEADs.
//!
//! ## Why Committing AEADs?
//!
//! While AEADs provide confidentiality and integrity, many of them do not
//! provide a commitment for their inputs (which can equivalently be thought
//! of as collision resistance of an AEAD with respect to its inputs). The
//! lack of commitment properties has lead to breaks in real cryptographic
//! protocols, e.g. improper implementations of the password-authenticated
//! key exchange [OPAQUE][2] and the Shadowsocks proxy, as described in
//! a paper describing [partitioning oracle attacks][3].
//! 
//! Concrete examples of popular AEADs that lack commitment properties:
//! - AEADs using polynomial-based MACs (e.g. AES-GCM and ChaCha20Poly1305)
//!   do not commit to their inputs. [1] describes how to construct an 
//!   AES-GCM ciphertext that decrypts correctly under two different keys to
//!   two different, semantically meaningful plaintexts.
//! - AEADs where decryption can be separated into parallel always-successful
//!   plaintext recovery and tag computation+equality checking steps cannot
//!   provide commitment when the tag computation function is not preimage
//!   resistant. [5] provides concrete attacks against EAX, GCM, SIV, CCM,
//!   and OCB3 that demonstrate that they are not key-commiting.
//! 
//! ## Module contents
//! This module provides the [`KeyCommittingAead`] marker trait to indicate that
//! an AEAD commits to its key, along with the [`CommittingAead`] marker trait
//! to indicate that an AEAD commits to all of its inputs. When the `committing_ae` feature is enabled, it also
//! provides constructions that wrap an AEAD and make it committing.
//!
//! [1]: https://eprint.iacr.org/2019/016.pdf
//! [2]: https://eprint.iacr.org/2018/163.pdf
//! [3]: https://www.usenix.org/system/files/sec21summer_len.pdf
//! [4]: https://eprint.iacr.org/2020/1456.pdf
//! [5]: https://eprint.iacr.org/2023/526.pdf

use crate::AeadCore;

#[cfg(feature = "committing_ae")]
#[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
pub use padded_aead::PaddedAead;

#[cfg(feature = "committing_ae")]
#[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
pub use ctx::CtxAead;

#[cfg(feature = "committing_ae")]
#[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
pub use ctx::CtxishHmacAead;

/// Marker trait that signals that an AEAD commits to its key.
pub trait KeyCommittingAead: AeadCore {}
/// Marker trait that signals that an AEAD commits to all its inputs.
pub trait CommittingAead: AeadCore+KeyCommittingAead {}

#[cfg(feature = "committing_ae")]
#[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
mod padded_aead {
    use crate::{AeadCore, AeadInPlace};
    use crypto_common::{KeyInit, KeySizeUser};
    use core::ops::{Add, Mul};
    use generic_array::ArrayLength;
    use generic_array::typenum::{U3, Unsigned};
    use subtle::{Choice, ConstantTimeEq};
    use super::KeyCommittingAead;

    #[cfg(feature = "committing_ae")]
    #[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
    #[derive(Debug, Clone)]
    /// A wrapper around a non-committing AEAD that implements the
    /// [padding fix][1] of prepending zeros to the plaintext before encryption 
    /// and verifying their presence upon decryption. Based on the formulas
    /// of [2], we append `3*key_len` zeros to obtain `3/4*key_len` bits of
    /// key commitment security.
    /// 
    /// The padding fix paper proves that this construction is key-committing
    /// for AES-GCM, ChaCha20Poly1305, and other AEADs that internally use
    /// primitives that can be modelled as ideal. However, security is not
    /// guaranteed with weak primitives. For example, e.g. HMAC-SHA-1 can be
    /// used as a MAC in normal circumstances because HMAC does not require a
    /// collision resistant hash, but an AEAD using HMAC-SHA-1 to provide
    /// integrity cannot be made committing using this padding scheme.
    /// 
    /// [1]: https://eprint.iacr.org/2020/1456.pdf
    /// [2]: https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/The%20Landscape%20of%20Committing%20Authenticated%20Encryption.pdf
    pub struct PaddedAead<Aead: AeadCore> {
        inner_aead: Aead,
    }
    impl <Aead: AeadCore> PaddedAead<Aead> {
        /// Extracts the inner Aead object.
        #[inline]
        pub fn into_inner(self) -> Aead {
            self.inner_aead
        }
    }

    impl <Aead: AeadCore+KeySizeUser> KeySizeUser for PaddedAead<Aead> {
        type KeySize = Aead::KeySize;
    }
    impl <Aead: AeadCore+KeyInit> KeyInit for PaddedAead<Aead> {
        fn new(key: &crypto_common::Key<Self>) -> Self {
            PaddedAead {
                inner_aead: Aead::new(key),
            }
        }
    }
    impl <Aead: AeadCore+KeySizeUser> AeadCore for PaddedAead<Aead>
    where
        Aead::CiphertextOverhead: Add<<Aead::KeySize as Mul<U3>>::Output>,
        Aead::KeySize: Mul<U3>,
        <Aead::CiphertextOverhead as Add<<Aead::KeySize as Mul<U3>>::Output>>::Output: ArrayLength<u8>
    {
        type NonceSize = Aead::NonceSize;

        type TagSize = Aead::TagSize;

        type CiphertextOverhead = <Aead::CiphertextOverhead as Add<<Aead::KeySize as Mul<U3>>::Output>>::Output;
    }
    // TODO: don't see a way to provide impls for both AeadInPlace
    // and AeadMutInPlace, as having both would conflict with the blanket impl
    // Choose AeadInPlace because all the current rustcrypto/AEADs do not have
    // a mutable state
    impl <Aead: AeadCore+AeadInPlace+KeySizeUser> AeadInPlace for PaddedAead<Aead>
    where
        Self: AeadCore
    {
        fn encrypt_in_place_detached(
            &self,
            nonce: &crate::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
        ) -> crate::Result<crate::Tag<Self>> {
            let offset_amount = Aead::CiphertextOverhead::to_usize()
                +3*Aead::KeySize::to_usize();
            buffer.copy_within(..buffer.len()-offset_amount, offset_amount);
            buffer[..offset_amount].fill(0x00);

            // Compiler can't see that Self::NonceSize == Aead::NonceSize
            let nonce_recast = crate::Nonce::<Aead>::from_slice(nonce.as_slice());

            let tag_inner = self.inner_aead.encrypt_in_place_detached(nonce_recast, associated_data, buffer)?;

            // Compiler can't see that Self::TagSize == Aead::TagSize
            let tag_recast = crate::Tag::<Self>::clone_from_slice(tag_inner.as_slice());
            Ok(tag_recast)
        }

        fn decrypt_in_place_detached(
            &self,
            nonce: &crate::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
            tag: &crate::Tag<Self>,
        ) -> crate::Result<()> {
            // Compiler can't see that Self::NonceSize == Aead::NonceSize
            // Ditto for Self::TagSize == Aead::TagSize
            let nonce_recast = crate::Nonce::<Aead>::from_slice(nonce.as_slice());
            let tag_recast = crate::Tag::<Aead>::from_slice(tag.as_slice());

            let tag_is_ok = Choice::from(match self.inner_aead.decrypt_in_place_detached(nonce_recast, associated_data, buffer, tag_recast) {
                Ok(_) => 1,
                Err(_) => 0
            });

            let offset_amount = Aead::CiphertextOverhead::to_usize()
                +3*Aead::KeySize::to_usize();
            // Do the loop because the slice ct_eq requires constructing 
            // [0; offset_amount], which requires more memory
            let mut pad_is_ok = Choice::from(1);
            for element in &buffer[..offset_amount] {
                pad_is_ok = pad_is_ok & element.ct_eq(&0);
            }
            buffer.copy_within(offset_amount.., 0);
            if (tag_is_ok & pad_is_ok).into() {
                Ok(())
            } else {
                Err(crate::Error)
            }
        }
    }
    impl<Aead: AeadCore> KeyCommittingAead for PaddedAead<Aead>
        where Self: AeadCore {}
}

#[cfg(feature = "committing_ae")]
#[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
mod ctx {
    use crate::{AeadCore, AeadInPlace};
    use crypto_common::{KeyInit, KeySizeUser, BlockSizeUser};
    use core::ops::Add;
    use digest::{Digest, Mac, FixedOutput};
    use hmac::SimpleHmac;
    use generic_array::ArrayLength;
    use generic_array::typenum::Unsigned;
    use subtle::Choice;
    use super::{KeyCommittingAead, CommittingAead};

    #[cfg(feature = "committing_ae")]
    #[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
    #[derive(Debug, Clone)]
    /// Implementation of the encryption portion of the
    /// [CTX scheme](https://eprint.iacr.org/2022/1260.pdf).
    /// 
    /// CTX wraps an AEAD and replaces the tag with 
    /// `H(key || nonce || aad || orig_tag)`, which is shown in the paper to
    /// commit to all AEAD inputs as long as the hash is collision resistant.
    /// This provides `hash_output_len/2` bits of commitment security.
    /// 
    /// Unfortunately, there is currently no way to get the expected tag of the
    /// inner AEAD using the current trait interfaces, so this struct only
    /// implements the encryption direction. This may still be useful for 
    /// interfacing with other programs that use the CTX committing AE scheme.
    pub struct CtxAead<Aead: AeadCore, CrHash: Digest> {
        inner_aead: Aead,
        hasher: CrHash
    }
    impl <Aead: AeadCore, CrHash: Digest> CtxAead<Aead, CrHash> {
        /// Extracts the inner Aead object.
        #[inline]
        pub fn into_inner(self) -> Aead {
            self.inner_aead
        }
    }

    impl <Aead: AeadCore+KeySizeUser, CrHash: Digest> KeySizeUser for CtxAead<Aead, CrHash> {
        type KeySize = Aead::KeySize;
    }
    impl <Aead: AeadCore+KeyInit, CrHash: Digest> KeyInit for CtxAead<Aead, CrHash> {
        fn new(key: &crypto_common::Key<Self>) -> Self {
            CtxAead {
                inner_aead: Aead::new(key),
                hasher: Digest::new_with_prefix(key)
            }
        }
    }

    impl <Aead: AeadCore+KeySizeUser, CrHash: Digest> AeadCore for CtxAead<Aead, CrHash>
    {
        type NonceSize = Aead::NonceSize;

        type TagSize = CrHash::OutputSize;

        type CiphertextOverhead = Aead::CiphertextOverhead;
    }

    // TODO: don't see a way to provide impls for both AeadInPlace
    // and AeadMutInPlace, as having both would conflict with the blanket impl
    // Choose AeadInPlace because all the current rustcrypto/AEADs do not have
    // a mutable state
    impl <Aead: AeadCore+AeadInPlace+KeySizeUser, CrHash: Digest+Clone> AeadInPlace for CtxAead<Aead, CrHash>
    where
        Self: AeadCore
    {
        fn encrypt_in_place_detached(
            &self,
            nonce: &crate::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
        ) -> crate::Result<crate::Tag<Self>> {
            // Compiler can't see that Self::NonceSize == Aead::NonceSize
            let nonce_recast = crate::Nonce::<Aead>::from_slice(nonce.as_slice());

            let tag_inner = self.inner_aead.encrypt_in_place_detached(nonce_recast, associated_data, buffer)?;

            let mut tag_computer = self.hasher.clone();
            tag_computer.update(nonce);
            tag_computer.update(associated_data);
            tag_computer.update(tag_inner);
            let final_tag = tag_computer.finalize();

            // Compiler can't see that Self::TagSize == Digest::OutputSize
            let tag_recast = crate::Tag::<Self>::clone_from_slice(final_tag.as_slice());
            Ok(tag_recast)
        }

        /// Unimplemented decryption of the message in-place, which panics if
        /// called
        #[allow(unused_variables)]
        fn decrypt_in_place_detached(
            &self,
            nonce: &crate::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
            tag: &crate::Tag<Self>,
        ) -> crate::Result<()> {
            // Compiler can't see that Self::NonceSize == Aead::NonceSize
            let _nonce_recast = crate::Nonce::<Aead>::from_slice(nonce.as_slice());
            unimplemented!("Cannot get inner AEAD tag using current AEAD interfaces")
            // Remaning steps: compute expected tag during decryption, repeat
            // hasher steps analogously to encryption phase, and compare tag
        }
    }

    impl<Aead: AeadCore, CrHash: Digest> KeyCommittingAead for CtxAead<Aead, CrHash>
        where Self: AeadCore {}
    impl<Aead: AeadCore, CrHash: Digest> CommittingAead for CtxAead<Aead, CrHash>
        where Self: AeadCore {}

    #[cfg(feature = "committing_ae")]
    #[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
    #[derive(Debug, Clone)]
    /// Implementation of a modified version of the CTX scheme.
    /// 
    /// Instead of returning tag `H(key || nonce || aad || orig_tag)`, we return
    /// `orig_tag || HMAC_key(nonce || aad || orig_tag)`. The AEAD API requires
    /// that we treat the underlying AEAD as a black box, without access to the
    /// expected tag at decryption time, so we have to also send it along with
    /// the commitment to the other inputs to the AEAD. (Ideally, the need to
    /// send `orig_tag` as well can be removed in a future version of the 
    /// crate.) At decryption time, we verify both `orig_tag` and the hash
    /// commitment.
    /// 
    /// ## Security analysis for the modified construction
    /// 
    /// HMAC invokes the underlying hash function twice such that the inputs to
    /// the hash functions are computed only by XOR, concatenation, and hashing.
    /// Thus, if we trust the underlying hash function to serve as a commitment
    /// to its inputs, we can also trust HMAC-hash to commit to its inputs and
    /// provide `hash_output_len/2` bits of commitment security, as with CTX.
    /// 
    /// If the underlying AEAD provides proper confidentiality and integrity
    /// protections, we can assume that this new construction also provides
    /// proper confidentiality and integrity, since it has the same ciphertext
    /// and includes the original tag without exposing cryptographic secrets in
    /// a recoverable form. Moreover, HMAC is supposed to be a secure keyed MAC,
    /// so an attacker cannot forge a commitment without knowing the key, even
    /// with full knowledge of the other input to the HMAC.
    /// 
    /// We use `HMAC_key(nonce || aad || orig_tag)` instead of the original CTX
    /// construction of `H(key || nonce || aad || orig_tag)` to mitigate length
    /// extension attacks that may become possible when `orig_tag` is sent in
    /// the clear (with the result that `H(key || nonce || aad || orig_tag)`
    /// decomposes into `H(secret || public)`), even though returning
    /// `orig_tag || H(key || nonce || aad || orig_tag)` as the tag would allow
    /// for increased interoperability with other CTX implementations. (In fact,
    /// revealing `orig_tag` would be fatal for the CTX+ construction which
    /// omits `aad` from the `orig_tag` computation by allowing forgery of the
    /// hash commitment via length extension on `aad`.)
    pub struct CtxishHmacAead<Aead: AeadCore, CrHash: Digest+BlockSizeUser> {
        inner_aead: Aead,
        hasher: SimpleHmac<CrHash>
    }
    impl <Aead: AeadCore, CrHash: Digest+BlockSizeUser> CtxishHmacAead<Aead, CrHash> {
        /// Extracts the inner Aead object.
        #[inline]
        pub fn into_inner(self) -> Aead {
            self.inner_aead
        }
    }

    impl <Aead: AeadCore+KeySizeUser, CrHash: Digest+BlockSizeUser> KeySizeUser for CtxishHmacAead<Aead, CrHash> {
        type KeySize = Aead::KeySize;
    }
    impl <Aead: AeadCore+KeyInit, CrHash: Digest+BlockSizeUser> KeyInit for CtxishHmacAead<Aead, CrHash> {
        fn new(key: &crypto_common::Key<Self>) -> Self {
            CtxishHmacAead {
                inner_aead: Aead::new(key),
                hasher: <SimpleHmac<_> as KeyInit>::new_from_slice(key).unwrap()
            }
        }
    }
    impl <Aead: AeadCore+KeySizeUser, CrHash: Digest+BlockSizeUser> AeadCore for CtxishHmacAead<Aead, CrHash>
    where
        Aead::TagSize: Add<CrHash::OutputSize>,
        <Aead::TagSize as Add<CrHash::OutputSize>>::Output: ArrayLength<u8>
    {
        type NonceSize = Aead::NonceSize;

        type TagSize = <Aead::TagSize as Add<CrHash::OutputSize>>::Output;

        type CiphertextOverhead = Aead::CiphertextOverhead;
    }
    // TODO: don't see a way to provide impls for both AeadInPlace
    // and AeadMutInPlace, as having both would conflict with the blanket impl
    // Choose AeadInPlace because all the current rustcrypto/AEADs do not have
    // a mutable state
    impl <Aead: AeadCore+AeadInPlace+KeySizeUser, CrHash: Digest+BlockSizeUser+Clone> AeadInPlace for CtxishHmacAead<Aead, CrHash>
    where
        Self: AeadCore
    {
        fn encrypt_in_place_detached(
            &self,
            nonce: &crate::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
        ) -> crate::Result<crate::Tag<Self>> {
            // Compiler can't see that Self::NonceSize == Aead::NonceSize
            let nonce_recast = crate::Nonce::<Aead>::from_slice(nonce.as_slice());

            let tag_inner = self.inner_aead.encrypt_in_place_detached(nonce_recast, associated_data, buffer)?;

            let mut tag_computer = self.hasher.clone();
            tag_computer.update(nonce);
            tag_computer.update(associated_data);
            tag_computer.update(&tag_inner);
            let hmac_tag = tag_computer.finalize_fixed();

            let final_tag_iter = tag_inner.iter().copied().chain(hmac_tag);

            let final_tag = crate::Tag::<Self>::from_exact_iter(final_tag_iter).unwrap();
            Ok(final_tag)
        }

        #[allow(unused_variables)]
        fn decrypt_in_place_detached(
            &self,
            nonce: &crate::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
            tag: &crate::Tag<Self>,
        ) -> crate::Result<()> {
            // Compiler can't see that Self::NonceSize == Aead::NonceSize
            let nonce_recast = crate::Nonce::<Aead>::from_slice(nonce.as_slice());
            // Get the inner tag
            let tag_inner = crate::Tag::<Aead>::from_slice(&tag[..Aead::TagSize::to_usize()]);

            // Prevent timing side channels by not returning early on inner AEAD
            // decryption failure
            let tag_inner_is_ok = Choice::from(match self.inner_aead.decrypt_in_place_detached(nonce_recast, associated_data, buffer, tag_inner) {
                Ok(_) => 1,
                Err(_) => 0
            });

            let mut tag_computer = self.hasher.clone();
            tag_computer.update(nonce);
            tag_computer.update(associated_data);
            // At this point we know whether tag_inner has the correct value
            // If it doesn't then we'll likely get a mismatch here too
            // Regardless, we require both `Choice`s to be OK
            // So it doesn't matter if we ingest a potentially tainted tag here
            tag_computer.update(&tag_inner);

            // Get the HMAC tag
            let expected_hmac_tag = &tag[Aead::TagSize::to_usize()..];

            let hmac_tag_is_ok = Choice::from(match tag_computer.verify_slice(expected_hmac_tag) {
                Ok(_) => 1,
                Err(_) => 0
            });

            if (tag_inner_is_ok & hmac_tag_is_ok).into() {
                Ok(())
            } else {
                Err(crate::Error)
            }
        }
    }
    impl<Aead: AeadCore, CrHash: Digest+BlockSizeUser> KeyCommittingAead for CtxishHmacAead<Aead, CrHash>
        where Self: AeadCore {}
    impl<Aead: AeadCore, CrHash: Digest+BlockSizeUser> CommittingAead for CtxishHmacAead<Aead, CrHash>
        where Self: AeadCore {}
}
