use cipher::{
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, ParBlocksSizeUser, StreamCipherBackend,
    StreamCipherClosure, StreamCipherCore, StreamCipherSeekCore,
    consts::{U1, U4, U16},
};
use hex_literal::hex;

const KEY: [u8; 4] = hex!("00010203");
const IV: [u8; 4] = hex!("04050607");

/// Core of dummy insecure stream cipher.
pub struct DummyStreamCipherCore {
    key_iv: u64,
    pos: u64,
}

impl KeySizeUser for DummyStreamCipherCore {
    type KeySize = U4;
}

impl IvSizeUser for DummyStreamCipherCore {
    type IvSize = U4;
}

impl KeyIvInit for DummyStreamCipherCore {
    fn new(key: &cipher::Key<Self>, iv: &cipher::Iv<Self>) -> Self {
        let mut key_iv = [0u8; 8];
        key_iv[..4].copy_from_slice(key);
        key_iv[4..].copy_from_slice(iv);
        Self {
            key_iv: u64::from_le_bytes(key_iv),
            pos: 0,
        }
    }
}

impl BlockSizeUser for DummyStreamCipherCore {
    type BlockSize = U16;
}

impl StreamCipherCore for DummyStreamCipherCore {
    fn remaining_blocks(&self) -> Option<usize> {
        let rem = u64::MAX - self.pos;
        usize::try_from(rem).ok()
    }

    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = U16>) {
        f.call(self);
    }
}

impl ParBlocksSizeUser for DummyStreamCipherCore {
    type ParBlocksSize = U1;
}

impl StreamCipherBackend for DummyStreamCipherCore {
    fn gen_ks_block(&mut self, block: &mut cipher::Block<Self>) {
        const C1: u64 = 0x87c3_7b91_1142_53d5;
        const C2: u64 = 0x4cf5_ad43_2745_937f;

        let a = self.key_iv ^ C1;
        let b = self.pos ^ C2;
        let a = a.rotate_left(13).wrapping_mul(b);
        let b = b.rotate_left(13).wrapping_mul(a);

        block[..8].copy_from_slice(&a.to_le_bytes());
        block[8..].copy_from_slice(&b.to_le_bytes());
        self.pos = self.pos.wrapping_add(1);
    }
}

impl StreamCipherSeekCore for DummyStreamCipherCore {
    type Counter = u64;

    fn get_block_pos(&self) -> Self::Counter {
        self.pos
    }

    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.pos = pos;
    }
}

#[test]
fn dummy_stream_cipher_core() {
    let mut cipher = DummyStreamCipherCore::new(&KEY.into(), &IV.into());
    assert_eq!(cipher.get_block_pos(), 0);

    let mut block = [0u8; 16].into();
    cipher.write_keystream_block(&mut block);
    assert_eq!(block, hex!("e82393543cc96089305116003a417acc"));
    assert_eq!(cipher.get_block_pos(), 1);

    cipher.set_block_pos(200);
    assert_eq!(cipher.get_block_pos(), 200);

    cipher.write_keystream_block(&mut block);
    assert_eq!(block, hex!("28a96998fe4874ffb0ce9b046c6a9ddb"));
    assert_eq!(cipher.get_block_pos(), 201);
}

#[cfg(feature = "stream-wrapper")]
mod wrapper {
    use core::panic;

    use super::*;
    use cipher::{StreamCipher, StreamCipherCoreWrapper, StreamCipherSeek};

    /// Dummy insecure stream cipher.
    pub type DummyStreamCipher = StreamCipherCoreWrapper<DummyStreamCipherCore>;

    #[test]
    fn dummy_stream_cipher_basic() {
        let mut cipher = DummyStreamCipher::new(&KEY.into(), &IV.into());
        assert_eq!(cipher.current_pos::<u64>(), 0);

        let mut buf = [0u8; 20];
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, hex!("e82393543cc96089305116003a417accd073384a"));
        assert_eq!(cipher.current_pos::<usize>(), buf.len());

        const SEEK_POS: usize = 500;
        cipher.seek(SEEK_POS);
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, hex!("6b014c6a3c376b13c4720590d26147c5ebf334c5"));
        assert_eq!(cipher.current_pos::<usize>(), SEEK_POS + buf.len());
    }

    #[test]
    fn dummy_stream_cipher_seek_limit() {
        let mut cipher = DummyStreamCipher::new(&KEY.into(), &IV.into());
        let mut buf = [0u8; 64];

        let block_size = DummyStreamCipherCore::block_size();
        let block_size_u128 = u128::try_from(block_size).unwrap();
        let keystream_end = 1u128 << 68;
        let last_block_pos = keystream_end - block_size_u128;

        // Seeking to the last block or past it should return error
        for offset in 0..block_size_u128 {
            let res = cipher.try_seek(keystream_end - offset);
            assert!(res.is_err());
            let res = cipher.try_seek(keystream_end + offset);
            assert!(res.is_err());
        }

        // Trying to apply the last keystream block should return error
        for offset in block_size..buf.len() {
            for len in 0..buf.len() {
                let pos = keystream_end - u128::try_from(offset).unwrap();
                let res = cipher.try_seek(pos);
                assert!(res.is_ok());
                let res = cipher.try_apply_keystream(&mut buf[..len]);
                let expected_pos = pos + u128::try_from(len).unwrap();
                if expected_pos > last_block_pos {
                    assert!(res.is_err());
                } else {
                    assert!(res.is_ok());
                    assert_eq!(cipher.current_pos::<u128>(), expected_pos);
                }
            }
        }
    }

    #[cfg(feature = "dev")]
    cipher::stream_cipher_test!(
        dummy_stream_cipher,
        "dummy_stream_cipher",
        DummyStreamCipher,
    );
    #[cfg(feature = "dev")]
    cipher::stream_cipher_seek_test!(dummy_stream_cipher_seek, DummyStreamCipher);
}
