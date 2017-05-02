use std::io;
use super::Input;

const BUFFER_SIZE: usize = 1024;

pub trait DigestReader {
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
