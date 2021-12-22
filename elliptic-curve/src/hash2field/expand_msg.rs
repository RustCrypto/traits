/// Trait for types implementing expand_message interface for hash_to_field
pub trait ExpandMsg<const OUT: usize> {
    /// Expands `msg` to the required number of bytes in `buf`
    fn expand_message(msg: &[u8], dst: &[u8]) -> [u8; OUT];
}
