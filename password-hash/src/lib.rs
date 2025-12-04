#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    missing_debug_implementations
)]

//!
//! # Usage
//!
//! This crate represents password hashes using the [`PasswordHash`] type, which
//! represents a parsed "PHC string" with the following format:
//!
//! ```text
//! $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
//! ```
//!
//! For more information, please see the documentation for [`PasswordHash`].

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "rand_core")]
pub use rand_core;

pub mod errors;
pub mod phc;

mod traits;

pub use crate::{
    errors::{Error, Result},
    traits::{McfHasher, PasswordHasher, PasswordVerifier},
};

pub use phc::PasswordHash;

#[cfg(feature = "alloc")]
pub use phc::PasswordHashString;
