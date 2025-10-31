# [RustCrypto]: Key Encapsulation Mechanisms (KEMs)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

This crate provides a common set of traits for [key encapsulation mechanisms][1]—algorithms for non-interactively establishing secrets between peers. This is intended to be implemented by libraries which produce or contain implementations of key encapsulation mechanisms, and used by libraries which want to produce or consume encapsulated secrets while generically supporting any compatible backend.

The crate exposes two traits, `Encapsulate` and `Decapsulate`, which are both generic over the encapsulated key type and the shared secret type. They are also agnostic about the structure of `Self`. For example, a simple Saber implementation may just impl `Encapsulate` for a single public key:
```rust
// Must make a newtype to implement the trait
struct MyPubkey(SaberPublicKey);

impl Encapsulate<SaberEncappedKey, SaberSharedSecret> for MyPubkey {
    // Encapsulation is infallible
    type Error = !;

    fn encapsulate(
        &self,
        csprng: impl CryptoRngCore,
    ) -> Result<(SaberEncappedKey, SaberSharedSecret), !> {
        let (ss, ek) = saber_encapsulate(&csprng, &self.0);
        Ok((ek, ss))
    }
}
```
And on the other end of complexity, an [X3DH](https://www.signal.org/docs/specifications/x3dh/) implementation might impl `Encapsulate` for a public key bundle plus a sender identity key:
```rust
struct PubkeyBundle {
    ik: IdentityPubkey,
    spk: SignedPrePubkey,
    sig: Signature,
    opk: OneTimePrePubkey,
}

// Encap context is the recipient's pubkeys and the sender's identity key
struct EncapContext(PubkeyBundle, IdentityPrivkey);

impl Encapsulate<EphemeralKey, SharedSecret> for EncapContext {
    // Encapsulation fails if signature verification fails
    type Error = SigError;

    fn encapsulate(
        &self,
        csprng: impl CryptoRngCore,
    ) -> Result<(EphemeralKey, SharedSecret), Self::Error> {
        // Make a new ephemeral key. This will be the encapped key
        let ek = EphemeralKey::gen(&mut csprng);

        // Deconstruct the recipient's pubkey bundle
        let PubkeyBundle {
            ref ik,
            ref spk,
            ref sig,
            ref opk,
        } = self.0;
        let my_ik = &self.1;

        // Verify the signature
        self.0.verify(&sig, &some_sig_pubkey)?;

        // Do the X3DH operation to get the shared secret
        let shared_secret = x3dh_a(sig, my_ik, spk, &ek, ik, opk)?;

        Ok((ek, shared_secret))
    }
}
```

## License

Licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/kem.svg
[crate-link]: https://crates.io/crates/kem
[docs-image]: https://docs.rs/kem/badge.svg
[docs-link]: https://docs.rs/kem/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260048-signatures
[build-image]: https://github.com/RustCrypto/traits/actions/workflows/kem.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/traits/actions/workflows/kem.yml?query=branch:master

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[1]: https://en.wikipedia.org/wiki/Key_encapsulation
