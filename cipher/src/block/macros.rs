/// Implement simple block backend
#[macro_export]
macro_rules! impl_simple_block_encdec {
    (
        <$($N:ident$(:$b0:ident$(+$b:ident)*)?),*>
        $cipher:ident, $block_size:ty, $state:ident, $block:ident,
        encrypt: $enc_block:block
        decrypt: $dec_block:block
    ) => {
        impl<$($N$(:$b0$(+$b)*)?),*> $crate::BlockSizeUser for $cipher<$($N),*> {
            type BlockSize = $block_size;
        }

        impl<$($N$(:$b0$(+$b)*)?),*> $crate::BlockCipherEncrypt for $cipher<$($N),*> {
            fn encrypt_with_backend(&self, f: impl $crate::BlockCipherEncClosure<BlockSize = $block_size>) {
                struct EncBack<'a, $($N$(:$b0$(+$b)*)?),* >(&'a $cipher<$($N),*>);

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockSizeUser for EncBack<'a, $($N),*> {
                    type BlockSize = $block_size;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::ParBlocksSizeUser for EncBack<'a, $($N),*> {
                    type ParBlocksSize = $crate::consts::U1;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockCipherEncBackend for EncBack<'a, $($N),*> {
                    #[inline(always)]
                    fn proc_block(
                        &mut self,
                        mut $block: $crate::inout::InOut<'_, '_, $crate::Block<Self>>
                    ) {
                        let $state: &$cipher<$($N),*> = self.0;
                        $enc_block
                    }
                }

                f.call(&mut EncBack(self))
            }
        }

        impl<$($N$(:$b0$(+$b)*)?),*> $crate::BlockCipherDecrypt for $cipher<$($N),*> {
            fn decrypt_with_backend(&self, f: impl $crate::BlockCipherDecClosure<BlockSize = $block_size>) {
                struct DecBack<'a, $($N$(:$b0$(+$b)*)?),* >(&'a $cipher<$($N),*>);

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockSizeUser for DecBack<'a, $($N),*> {
                    type BlockSize = $block_size;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::ParBlocksSizeUser for DecBack<'a, $($N),*> {
                    type ParBlocksSize = $crate::consts::U1;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockCipherDecBackend for DecBack<'a, $($N),*> {
                    #[inline(always)]
                    fn proc_block(
                        &mut self,
                        mut $block: $crate::inout::InOut<'_, '_, $crate::Block<Self>>
                    ) {
                        let $state: &$cipher<$($N),*> = self.0;
                        $dec_block
                    }
                }

                f.call(&mut DecBack(self))
            }
        }
    };
    (
        $cipher:ident, $block_size:ty, $state:ident, $block:ident,
        encrypt: $enc_block:block
        decrypt: $dec_block:block
    ) => {
        $crate::impl_simple_block_encdec!(
            <> $cipher, $block_size, $state, $block,
            encrypt: $enc_block
            decrypt: $dec_block
        );
    };
}
