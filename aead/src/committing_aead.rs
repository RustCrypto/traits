//! Committing AEAD support.
//!
//! Marker trait for Committing AEADs along with constructions that give 
//! key-committing properties to normal AEADs.
//!
//! ## About
//!
//! While AEADs provide confidentiality and integrity, many of them do not
//! provide a committment for their inputs. One consequence is that, for
//! example, [it is possible to construct an AES-GCM ciphertext that correctly
//! decrypts under two different keys into two different plaintexts][1].
//! Moreover, the lack of committment properties has lead to breaks in real
//! cryptographic protocols, e.g. the password-authenticated key exchange
//! [OPAQUE][2] and the Shadowsocks proxy, as described in [this paper
//! introducing partitioning oracle attacks].
//! 
//! This module provides the [`KeyCommittingAead`] marker trait to indicate that
//! an AEAD commits to its key, along with the [`CommittingAead`] marker trait
//! to incidate that an AEAD commits to all of its inputs. (This can
//! equivalently be thought of as collision resistance of an AEAD with respect
//! to its inputs.) When the `committing_ae` feature is enabled, it also
//! provides constructions that wrap an AEAD and make it committing.
//!
//! [1]: https://eprint.iacr.org/2019/016.pdf
//! [2]: https://eprint.iacr.org/2018/163.pdf
//! [3]: https://www.usenix.org/system/files/sec21summer_len.pdf
//! [4]: https://eprint.iacr.org/2020/1456.pdf
//! 

use crate::AeadCore;

#[cfg(feature = "committing_ae")]
#[cfg_attr(docsrs, doc(cfg(feature = "committing_ae")))]
pub use padded_aead::PaddedAead;

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
    /// key committment security.
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
                +2*Aead::KeySize::to_usize();
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
                +2*Aead::KeySize::to_usize();
            // Do the loop because the slice ct_eq requires constructing 
            // [0; offset_amount], which requires an allocation
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