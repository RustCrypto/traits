//! Adds hashing to any reader
use super::{Digest, FixedOutputReset, Output, Reset};
use std::io;

/// Abstraction over a reader which hashes the data being read
#[derive(Debug)]
pub struct HashReader<D: Digest, R: io::Read> {
    reader: R,
    hasher: D,
}

impl<D: Digest, R: io::Read> HashReader<D, R> {
    /// Construct a new `HashReader` given an existing `reader` by value.
    pub fn new(reader: R) -> Self {
        Self::new_from_parts(D::new(), reader)
    }

    /// Construct a new `HashReader` given an existing `hasher` and `reader` by value.
    pub fn new_from_parts(hasher: D, reader: R) -> Self {
        HashReader { reader, hasher }
    }

    /// Replace the reader with another reader
    pub fn replace_reader(&mut self, reader: R) {
        self.reader = reader;
    }

    /// Gets a reference to the underlying hasher
    pub fn get_hasher(&self) -> &D {
        &self.hasher
    }

    /// Gets a reference to the underlying reader
    pub fn get_reader(&self) -> &R {
        &self.reader
    }

    /// Gets a mutable reference to the underlying hasher
    pub fn get_hasher_mut(&mut self) -> &mut D {
        &mut self.hasher
    }

    /// Gets a mutable reference to the underlying reader
    /// Direct reads from the underlying reader are not hashed
    pub fn get_reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume the HashReader and return its hasher
    pub fn into_hasher(self) -> D {
        self.hasher
    }

    /// Consume the HashReader and return its internal reader
    pub fn into_inner_reader(self) -> R {
        self.reader
    }

    /// Consume the HashReader and return its hasher and internal reader
    pub fn into_parts(self) -> (D, R) {
        (self.hasher, self.reader)
    }

    /// Retrieve result and consume HashReader instance.
    pub fn finalize(self) -> Output<D> {
        self.hasher.finalize()
    }

    /// Write result into provided array and consume the HashReader instance.
    pub fn finalize_into(self, out: &mut Output<D>) {
        self.hasher.finalize_into(out)
    }

    /// Get output size of the hasher
    pub fn output_size() -> usize {
        <D as Digest>::output_size()
    }
}

impl<D: Digest + Clone, R: io::Read + Clone> Clone for HashReader<D, R> {
    fn clone(&self) -> HashReader<D, R> {
        HashReader {
            reader: self.reader.clone(),
            hasher: self.hasher.clone(),
        }
    }
}

impl<D: Digest, R: io::Read> io::Read for HashReader<D, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }
}

impl<D: Digest + FixedOutputReset, R: io::Read> HashReader<D, R> {
    /// Retrieve result and reset hasher instance.
    pub fn finalize_reset(&mut self) -> Output<D> {
        Digest::finalize_reset(&mut self.hasher)
    }

    /// Rrite result into provided array and reset the hasher instance.
    pub fn finalize_into_reset(&mut self, out: &mut Output<D>) {
        Digest::finalize_into_reset(&mut self.hasher, out)
    }
}
impl<D: Digest + Reset, R: io::Read> Reset for HashReader<D, R> {
    fn reset(&mut self) {
        Digest::reset(&mut self.hasher)
    }
}

impl<D: Digest, R: io::BufRead> HashReader<D, R> {
    /// Read and hash all bytes remaining in the reader, discarding the data
    /// Based on implementation in b2sum crate, MIT License Copyright (c) 2017 John Downey
    pub fn hash_to_end(&mut self) {
        loop {
            let count = {
                let data = self.reader.fill_buf().unwrap();
                if data.is_empty() {
                    break;
                }

                self.hasher.update(data);
                data.len()
            };

            self.reader.consume(count);
        }
    }
}
