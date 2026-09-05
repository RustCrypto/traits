# RustCrypto: Digest Algorithm Traits

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Traits which describe functionality of [cryptographic hash functions][0], a.k.a.
digest algorithms.

See [RustCrypto/hashes][1] for implementations which use this trait.

## Usage

Let us demonstrate how to use crates in this repository using Sha256 as an
example.

First add the `sha2` crate to your `Cargo.toml`:

```toml
[dependencies]
sha2 = "0.11"
```

`sha2` and other crates re-export `digest` crate and `Digest` trait for
convenience, so you don't have to add `digest` crate as an explicit dependency.

Now you can write the following code:

```rust
use sha2::{Sha256, Digest};

let mut hasher = Sha256::new();
let data = b"Hello world!";
hasher.update(data);
// `input` can be called repeatedly and is generic over `AsRef<[u8]>`
hasher.update("String data");
// Note that calling `finalize()` consumes hasher
let hash = hasher.finalize();
println!("Result: {:?}", hash);
```

In this example `hash` has type [`Array<u8, U32>`][2], which is a generic
alternative to `[u8; 32]`.

Alternatively you can use chained approach, which is equivalent to the previous
example:

```rust
use sha2::{Sha256, Digest};

let hash = Sha256::new()
    .chain_update(b"Hello world!")
    .chain_update("String data")
    .finalize();

println!("Result: {:?}", hash);
```

If the whole message is available you also can use convenience `digest` method:

```rust
use sha2::{Sha256, Digest};

let hash = Sha256::digest(b"my message");
println!("Result: {:?}", hash);
```

### Format as hexadecimal string

Using the [`base16ct`] crate, you can quickly format the hash as a string. Let us demonstrate once again using Sha256.

Add the `base16ct` and `sha2` crates to your `Cargo.toml`:

```toml
[dependencies]
base16ct = "1.0.0"
sha2 = "0.11"
```

The struct [`HexDisplay`] accepts type [`&Array<u8, U32>`][2], while implementing [`Display`](core::fmt::Display), [`LowerHex`](core::fmt::LowerHex), and [`UpperHex`](core::fmt::UpperHex).

Now you can write the following code:

```rust
use base16ct::HexDisplay;
use sha2::{Sha256, Digest};

let hash = Sha256::digest(b"my message");
let hash_hex_string = HexDisplay(&hash);

assert_eq!(
    &format!("{:x}", hash_hex_string),
    "ea38e30f75767d7e6c21eba85b14016646a3b60ade426ca966dac940a5db1bab"
);
assert_eq!(
    &format!("{:X}", hash_hex_string),
    "EA38E30F75767D7E6C21EBA85B14016646A3B60ADE426CA966DAC940A5DB1BAB"
);
```

### Generic code

You can write generic code over `Digest` (or other traits from `digest` crate)
trait which will work over different hash functions:

```rust
use digest::Digest;

// Toy example, do not use it in practice!
// Instead use crates from: https://github.com/RustCrypto/password-hashing
fn hash_password<D: Digest>(password: &str, salt: &str, output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.update(password.as_bytes());
    hasher.update(b"$");
    hasher.update(salt.as_bytes());
    output.copy_from_slice(hasher.finalize().as_slice())
}

let mut buf1 = [0u8; 32];
let mut buf2 = [0u8; 64];

hash_password::<sha2::Sha256>("my_password", "abcd", &mut buf1);
hash_password::<sha2::Sha512>("my_password", "abcd", &mut buf2);
```

If you want to use hash functions with trait objects, use `digest::DynDigest`
trait.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/digest.svg
[crate-link]: https://crates.io/crates/digest
[docs-image]: https://docs.rs/digest/badge.svg
[docs-link]: https://docs.rs/digest/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/traits/actions/workflows/digest.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/traits/actions/workflows/digest.yml?query=branch:master

[//]: # (general links)

[`base16ct`]: https://docs.rs/base16ct
[`HexDisplay`]: https://docs.rs/base16ct/latest/base16ct/struct.HexDisplay.html
[0]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
[1]: https://github.com/RustCrypto/hashes
[2]: https://docs.rs/hybrid-array
[3]: https://doc.rust-lang.org/std/io/trait.Read.html
[4]: https://doc.rust-lang.org/std/io/trait.Write.html
[5]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
[6]: https://github.com/RustCrypto/MACs
