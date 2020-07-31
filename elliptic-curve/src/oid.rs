//! Object identifiers (OIDs)

use core::fmt;

/// Object identifier (OID)
pub struct ObjectIdentifier(&'static [u32]);

impl ObjectIdentifier {
    /// Create a new OID
    pub const fn new(nodes: &'static [u32]) -> Self {
        // TODO(tarcieri): validate nodes
        Self(nodes)
    }
}

impl AsRef<[u32]> for ObjectIdentifier {
    fn as_ref(&self) -> &[u32] {
        self.0
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, node) in self.0.iter().enumerate() {
            write!(f, "{}", node)?;

            if i < self.0.len() - 1 {
                write!(f, ".")?;
            }
        }

        Ok(())
    }
}

#[cfg(all(test, std))]
mod tests {
    use super::ObjectIdentifier;
    use std::string::ToString;

    const EXAMPLE_OID: ObjectIdentifier = ObjectIdentifier::new(&[1, 2, 840, 10045, 3, 1, 7]);

    #[test]
    fn display_test() {
        let oid = EXAMPLE_OID.to_string();
        assert_eq!(oid, "1.2.840.10045.3.1.7");
    }
}
