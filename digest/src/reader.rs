use std::io;
use super::{Input, FixedOutput, GenericArray};

const BUFFER_SIZE: usize = 1024;

/// Trait to digest data from `std::io::Read` trait (e.g. from open files).
/// It's implemented for all `digest::Input` trait implementators
pub trait DigestReader {
    /// Read data from source and digest it
    fn read_from(&mut self, source: &mut io::Read) -> io::Result<()>;
}

impl<T: Input> DigestReader for T {
    fn read_from(&mut self, source: &mut io::Read) -> io::Result<()> {
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let bytes_read = source.read(&mut buffer)?;
            self.digest(&buffer[..bytes_read]);
            if bytes_read != buffer.len() {
                break;
            }
        }
        Ok(())
    }
}

/// Convinience function which takes `std::io::Read` as a source and computes
/// value of digest function `D`, e.g. SHA-2, SHA-3, BLAKE2, etc.
///
/// Usage example:
///
/// ```rust,ignore
/// let file = fs::File::open(&path)?;
/// let result = digest_reader<blake2::Blake2b>(&mut file)?;
/// println!("{:x}", result);
/// ```
pub fn digest_reader<D>(source: &mut io::Read)
    -> io::Result<GenericArray<u8, D::OutputSize>>
    where D: Default + DigestReader + FixedOutput
{
    let mut digest: D = Default::default();
    digest.read_from(source)?;
    Ok(digest.fixed_result())
}
