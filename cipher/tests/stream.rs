use cipher::{
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, ParBlocksSizeUser, StreamCipherBackend,
    StreamCipherClosure, StreamCipherCore, StreamCipherSeekCore,
    consts::{U1, U4, U16},
};
#[cfg(feature = "stream-wrapper")]
use cipher::{StreamCipher, StreamCipherCoreWrapper, StreamCipherSeek};
use hex_literal::hex;

const KEY: [u8; 4] = [0, 1, 2, 3];
const IV: [u8; 4] = [4, 5, 6, 7];

/// Dummy insecure stream cipher.
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
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(key);
        buf[4..].copy_from_slice(iv);
        let pos = u64::from_le_bytes(buf);
        Self {
            key_iv: pos,
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

#[cfg(feature = "stream-wrapper")]
pub type DummyStreamCipher = StreamCipherCoreWrapper<DummyStreamCipherCore>;

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

#[test]
#[cfg(feature = "stream-wrapper")]
fn dummy_stream_cipher() {
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
#[cfg(feature = "stream-wrapper")]
fn dummy_stream_cipher_seek_limit() {
    let mut cipher = DummyStreamCipher::new(&KEY.into(), &IV.into());

    let pos = ((u64::MAX as u128) << 4) - 20;
    cipher.try_seek(pos).unwrap();

    let mut buf = [0u8; 30];
    let res = cipher.try_apply_keystream(&mut buf);
    assert!(res.is_err());
    let cur_pos: u128 = cipher.current_pos();
    assert_eq!(cur_pos, pos);

    let res = cipher.try_apply_keystream(&mut buf[..19]);
    assert!(res.is_ok());
    let cur_pos: u128 = cipher.current_pos();
    assert_eq!(cur_pos, pos + 19);

    cipher.try_seek(pos).unwrap();

    // TODO: fix as part of https://github.com/RustCrypto/traits/issues/1808
    // let res = cipher.try_apply_keystream(&mut buf[..20]);
    // assert!(res.is_err());
}

#[cfg(all(feature = "dev", feature = "stream-wrapper"))]
cipher::stream_cipher_seek_test!(dummy_stream_cipher_seek, DummyStreamCipher);
