use generic_array::GenericArray;
use sha2::{Digest, Sha256};
use twofish::block_cipher::{BlockCipher, NewBlockCipher};
use twofish::Twofish;

// TODO If this is in a crypto library that would be better than here
// I see a blocksize trait I may be able to use
const SHA256_SIZE: usize = 32;

// Preamble is all the fields in the Password Safe V3 format which are not part of the encrypted block.
#[derive(Debug)]
pub(super) struct Preamble {
    ///Random initial value for CBC
    pub(super) cbciv: [u8; 16],
    encryption_key: [u8; 32],
    hmac_key: [u8; 32],
    //the number of iterations on the hash function to create the stretched key
    iter: u32,
    salt: [u8; 32],
    pub(super) stretched_key: [u8; SHA256_SIZE],
}

impl Preamble {
    // new extracts the preamble fields from the given bytes. As part of this it does initial password verification.
    pub(super) fn new(bytes: Vec<u8>, password: &str) -> Result<Preamble, String> {
        if bytes.len() != 152 {
            return Err("Expected a preamble to be exactly 152 bytes".to_string());
        }
        match std::str::from_utf8(&bytes[0..4]) {
            Ok(tag) => {
                if tag != "PWS3" {
                    return Err("Data is not a Password Safe V3 DB".to_string());
                }
            }
            Err(_) => return Err("Data is not a Password Safe V3 DB".to_string()),
        };

        let key_hash = &bytes[40..72];
        let salt: [u8; 32] = copy_into_array(&bytes[4..36]);
        let iter = u32::from_le_bytes(copy_into_array(&bytes[36..40]));
        let cbciv: [u8; 16] = copy_into_array(&bytes[136..152]);

        let stretched_key = calculate_stretch_key(password, iter, salt);
        if key_hash[..] != Sha256::digest(&stretched_key[..])[..] {
            return Err("Invalid Password".to_string());
        }

        let keys = extract_keys(&bytes[72..136], &stretched_key);

        Ok(Preamble {
            cbciv,
            encryption_key: keys.0,
            hmac_key: keys.1,
            iter,
            salt,
            stretched_key,
        })
    }
}

fn calculate_stretch_key(password: &str, iterations: u32, salt: [u8; 32]) -> [u8; SHA256_SIZE] {
    let salted = [password.as_bytes(), &salt].concat();
    let mut stretched = Sha256::digest(&salted);
    for _ in 0..iterations {
        stretched = Sha256::digest(&stretched[..]);
    }
    stretched.into()
}

fn extract_keys(data: &[u8], stretched_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // TODO don't panic if this unwraps a failure
    let cipher = Twofish::new_varkey(stretched_key).unwrap();

    let mut encryption_key = [0u8; 32];
    encryption_key[..32].copy_from_slice(&data[0..32]);
    let mut hmac_key = [0u8; 32];
    hmac_key[..32].copy_from_slice(&data[32..64]);
    // TODO a better way to do this?
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut encryption_key[..16]));
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut encryption_key[16..32]));
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut hmac_key[..16]));
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut hmac_key[16..32]));
    (encryption_key, hmac_key)
}

// TODO make sure I understand this and try out the try_into variants
// Also make it so that returns an error rather than panic on failure
// this code was copied from https://stackoverflow.com/questions/25428920/how-to-get-a-slice-as-an-array-in-rust
fn copy_into_array<A, T>(slice: &[T]) -> A
    where
        A: Default + AsMut<[T]>,
        T: Copy,
{
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
    a
}
