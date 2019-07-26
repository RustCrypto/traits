# Authenticated Encryption with Additional Data

This crate provides the rust trait equivilent of the AEAD API defined in
RFC5116. As a result, it should provide nearly drop-in support for any
compliant AEAD scheme, including AES-GCM, AES-CCM, ChaCha20-Poly1305,
AES-CBC-HMAC, etc.
