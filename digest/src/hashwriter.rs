//! Adds hashing to any writer. Inspired by implemention in phase2 crate.
use super::{Digest, FixedOutputReset, Output, Reset};
use std::io;

/// Abstraction over a writer which hashes the data being written.
#[derive(Debug)]
pub struct HashWriter<D: Digest, W: io::Write> {
    writer: W,
    hasher: D,
}

impl<D: Digest, W: io::Write> HashWriter<D, W> {
    /// Construct a new `HashWriter` given an existing `writer` by value.
    pub fn new(writer: W) -> Self {
        Self::new_from_parts(D::new(), writer)
    }

    /// Construct a new `HashWriter` given an existing `hasher` and `writer` by value.
    pub fn new_from_parts(hasher: D, writer: W) -> Self {
        HashWriter { writer, hasher }
    }

    /// Replace the writer with another writer
    pub fn replace_writer(&mut self, writer: W) {
        self.writer = writer;
    }

    /// Gets a reference to the underlying hasher
    pub fn get_hasher(&self) -> &D {
        &self.hasher
    }

    /// Gets a reference to the underlying writer
    pub fn get_writer(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying hasher
    /// Updates to the digest are not written to the underlying writer
    pub fn get_hasher_mut(&mut self) -> &mut D {
        &mut self.hasher
    }

    /// Gets a mutable reference to the underlying writer
    /// Direct writes to the underlying writer are not hashed
    pub fn get_writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Consume the HashWriter and return its hasher
    pub fn into_hasher(self) -> D {
        self.hasher
    }

    /// Consume the HashWriter and return its internal writer
    pub fn into_inner_writer(self) -> W {
        self.writer
    }

    /// Consume the HashWriter and return its hasher and internal writer
    pub fn into_parts(self) -> (D, W) {
        (self.hasher, self.writer)
    }

    /// Retrieve result and consume HashWriter instance.
    pub fn finalize(self) -> Output<D> {
        self.hasher.finalize()
    }

    /// Write result into provided array and consume the HashWriter instance.
    pub fn finalize_into(self, out: &mut Output<D>) {
        self.hasher.finalize_into(out)
    }

    /// Get output size of the hasher
    pub fn output_size() -> usize {
        <D as Digest>::output_size()
    }
}

impl<D: Digest + Clone, W: io::Write + Clone> Clone for HashWriter<D, W> {
    fn clone(&self) -> HashWriter<D, W> {
        HashWriter {
            writer: self.writer.clone(),
            hasher: self.hasher.clone(),
        }
    }
}

impl<D: Digest, W: io::Write> io::Write for HashWriter<D, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.writer.write(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<D: Digest + FixedOutputReset, W: io::Write> HashWriter<D, W> {
    /// Retrieve result and reset hasher instance.
    pub fn finalize_reset(&mut self) -> Output<D> {
        Digest::finalize_reset(&mut self.hasher)
    }

    /// Write result into provided array and reset the hasher instance.
    pub fn finalize_into_reset(&mut self, out: &mut Output<D>) {
        Digest::finalize_into_reset(&mut self.hasher, out)
    }
}
impl<D: Digest + Reset, W: io::Write> Reset for HashWriter<D, W> {
    fn reset(&mut self) {
        Digest::reset(&mut self.hasher)
    }
}
