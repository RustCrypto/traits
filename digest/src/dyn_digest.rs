use super::{FixedOutput, FixedOutputReset, Reset, Update};
use core::fmt;
use generic_array::{typenum::Unsigned, GenericArray};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// The `DynDigest` trait is a modification of `Digest` trait suitable
/// for trait objects.
pub trait DynDigest {
    /// Digest input data.
    ///
    /// This method can be called repeatedly for use with streaming messages.
    fn update(&mut self, data: &[u8]);

    /// Retrieve result and reset hasher instance
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_reset(&mut self) -> Box<[u8]> {
        let mut result = vec![0; self.output_size()];
        self.finalize_into_reset(&mut result).unwrap();
        result.into_boxed_slice()
    }

    /// Retrieve result and consume boxed hasher instance
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[allow(clippy::boxed_local)]
    fn finalize(mut self: Box<Self>) -> Box<[u8]> {
        let mut result = vec![0; self.output_size()];
        self.finalize_into_reset(&mut result).unwrap();
        result.into_boxed_slice()
    }

    /// Write result into provided array and consume the hasher instance.
    ///
    /// Returns error if buffer length is not equal to `output_size`.
    fn finalize_into(self, buf: &mut [u8]) -> Result<(), InvalidBufferLength>;

    /// Write result into provided array and reset the hasher instance.
    ///
    /// Returns error if buffer length is not equal to `output_size`.
    fn finalize_into_reset(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferLength>;

    /// Reset hasher instance to its initial state.
    fn reset(&mut self);

    /// Get output size of the hasher
    fn output_size(&self) -> usize;

    /// Clone hasher state into a boxed trait object
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn box_clone(&self) -> Box<dyn DynDigest>;
}

impl<D: Update + FixedOutputReset + Clone + 'static> DynDigest for D {
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[cfg(feature = "alloc")]
    fn finalize_reset(&mut self) -> Box<[u8]> {
        self.finalize_fixed_reset().to_vec().into_boxed_slice()
    }

    #[cfg(feature = "alloc")]
    fn finalize(self: Box<Self>) -> Box<[u8]> {
        self.finalize_fixed().to_vec().into_boxed_slice()
    }

    fn finalize_into(self, buf: &mut [u8]) -> Result<(), InvalidBufferLength> {
        if buf.len() == self.output_size() {
            self.finalize_into(GenericArray::from_mut_slice(buf));
            Ok(())
        } else {
            Err(InvalidBufferLength)
        }
    }

    fn finalize_into_reset(&mut self, buf: &mut [u8]) -> Result<(), InvalidBufferLength> {
        if buf.len() == self.output_size() {
            self.finalize_into_reset(GenericArray::from_mut_slice(buf));
            Ok(())
        } else {
            Err(InvalidBufferLength)
        }
    }

    fn reset(&mut self) {
        Reset::reset(self);
    }

    fn output_size(&self) -> usize {
        <Self as FixedOutput>::OutputSize::to_usize()
    }

    #[cfg(feature = "alloc")]
    fn box_clone(&self) -> Box<dyn DynDigest> {
        Box::new(self.clone())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Clone for Box<dyn DynDigest> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// Buffer length is not equal to the hash output size.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidBufferLength;

impl fmt::Display for InvalidBufferLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid buffer length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBufferLength {}
