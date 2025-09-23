use group::{Group, GroupEncoding};

///! Elliptic Curve Verifiable Random Function (ECVRF)

//
fn prove<G: Group + GroupEncoding>(sk: G::Scalar, alpha_string: &[u8]) {
}
