use secp256k1::{SecretKey, PublicKey};
use bitcoin_hashes::{Ripemd160, Sha256};
use bs58;

pub const SK_LENGTH: usize = 32usize;
pub const PKH_LENGTH: usize = 20usize;
pub type SK = [u8; SK_LENGTH];
pub type PKH = [u8; PKH_LENGTH];

#[inline]
fn sk_from_slice(bytes: &SK) -> Option<SecretKey> {
    match SecretKey::from_slice(bytes) {
        Ok(sk) => Some(sk),
        Err(_) => None,
    }
}
pub fn sk_to_pk_compressed(bytes: &SK) -> Option<[u8; 33]> {
    if let Some(sk) = sk_from_slice(bytes) {
        Some(PublicKey::from_secret_key_global(&sk).serialize())
    } else {
        None
    }
}

#[allow(dead_code)]
pub fn sk_to_pk_uncompressed(bytes: &SK) -> Option<[u8; 65]> {
    if let Some(sk) = sk_from_slice(bytes) {
        Some(PublicKey::from_secret_key_global(&sk).serialize_uncompressed())
    } else {
        None
    }
}

pub fn sk_to_pk_hash(bytes: &SK) -> Option<PKH> {
    if let Some(pk_compressed) = sk_to_pk_compressed(&bytes) {
        let sha256_hash = Sha256::hash(&pk_compressed).to_byte_array();
        let ripemd160_hash = Ripemd160::hash(&sha256_hash).to_byte_array();
        Some(ripemd160_hash)
    } else {
        None
    }
}

pub fn pkh_to_bitcoin_address(pkh: &[u8; 20]) -> String {
    let mut bytes = [0u8; 25];
    bytes[0] = 0x00;
    bytes[1..21].copy_from_slice(pkh);
    let checksum = Sha256::hash(&Sha256::hash(&bytes[..21]).to_byte_array()).to_byte_array();
    bytes[21..].copy_from_slice(&checksum[..4]);
    bs58::encode(bytes).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    static SK_BYTES: [u8; 32] = hex!("0000000000000000000000000000000000000000000000000000000000000008");

    #[test]
    fn test_sk_to_pk_compressed() {
        assert_eq!(
            sk_to_pk_compressed(&SK_BYTES).unwrap(),
            hex!("022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01")
        );
    }

    #[test]
    fn test_sk_to_pk_uncompressed() {
        assert_eq!(
            sk_to_pk_uncompressed(&SK_BYTES).unwrap(),
            hex!(
                "04\
                2f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01\
                5c4da8a741539949293d082a132d13b4c2e213d6ba5b7617b5da2cb76cbde904"
            )
        );
    }

    #[test]
    fn test_sk_to_pk_hash() {
        assert_eq!(
            sk_to_pk_hash(&SK_BYTES).unwrap(),
            hex!("9652d86bedf43ad264362e6e6eba6eb764508127")
        );
    }

    #[test]
    fn test_pkh_to_bitcoin_address() {
        assert_eq!(
            pkh_to_bitcoin_address(&hex!("9652d86bedf43ad264362e6e6eba6eb764508127")),
            "1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e"
        )
    }

}
