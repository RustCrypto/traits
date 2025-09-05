/// Define block encryptor benchmark
#[macro_export]
macro_rules! block_encryptor_bench {
    (Key: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_encryptor_bench!(
            {
                use $crate::KeyInit;
                let key = test::black_box(Default::default());
                <$cipher>::new(&key)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    (KeyIv: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_encryptor_bench!(
            {
                use $crate::KeyIvInit;
                let key = test::black_box(Default::default());
                let iv = test::black_box(Default::default());
                <$cipher>::new(&key, &iv)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    ($init:block, $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        #[bench]
        pub fn $block_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherEncrypt, BlockModeEncrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                for block in blocks.iter_mut() {
                    cipher.encrypt_block(block);
                }
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }

        #[bench]
        pub fn $blocks_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherEncrypt, BlockModeEncrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                cipher.encrypt_blocks(&mut blocks);
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }
    };
}

/// Define block decryptor benchmark
#[macro_export]
macro_rules! block_decryptor_bench {
    (Key: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_decryptor_bench!(
            {
                use $crate::KeyInit;
                let key = test::black_box(Default::default());
                <$cipher>::new(&key)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    (KeyIv: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_decryptor_bench!(
            {
                use $crate::KeyIvInit;
                let key = test::black_box(Default::default());
                let iv = test::black_box(Default::default());
                <$cipher>::new(&key, &iv)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    ($init:block, $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        #[bench]
        pub fn $block_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherDecrypt, BlockModeDecrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                for block in blocks.iter_mut() {
                    cipher.decrypt_block(block);
                }
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }

        #[bench]
        pub fn $blocks_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherDecrypt, BlockModeDecrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                cipher.decrypt_blocks(&mut blocks);
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }
    };
}
