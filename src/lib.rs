use crate::Error::Decrypt;
use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use pqc_kyber::{
    Keypair, KyberError, PublicKey, SecretKey, KYBER_CIPHERTEXTBYTES, KYBER_SECRETKEYBYTES,
};

use pqc_kyber::indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair};
pub use pqc_kyber::{decapsulate, encapsulate};

const KYBER_BLOCK_SIZE: usize = 32;
const LENGTH_FIELD: usize = 8;

pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
    public_key: T,
    plaintext: R,
    nonce: V,
) -> Result<Vec<u8>, Error> {
    let full_ciphertext_len = ct_len(plaintext.as_ref().len());
    let mut out = vec![0u8; full_ciphertext_len];
    encrypt_into(public_key, plaintext, nonce, out.as_mut_slice())?;
    Ok(out)
}

/// returns the ciphertext expected length given an input plaintext length
pub fn ct_len(plaintext_len: usize) -> usize {
    std::cmp::max(
        KYBER_CIPHERTEXTBYTES,
        div_ceil(plaintext_len as f32, KYBER_BLOCK_SIZE as f32) * KYBER_CIPHERTEXTBYTES,
    ) + LENGTH_FIELD
}

pub fn plaintext_len(ciphertext: &[u8]) -> Option<usize> {
    // The final 8 bytes are for the original length of the plaintext
    let split_pt = ciphertext.len().saturating_sub(8);
    if split_pt > ciphertext.len() || split_pt == 0 {
        return None;
    }

    let (_, field_length_be) = ciphertext.split_at(split_pt);
    let plaintext_length = byteorder::NetworkEndian::read_u64(field_length_be) as usize;
    Some(plaintext_length)
}

pub fn encrypt_into<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>, O: AsMut<[u8]>>(
    public_key: T,
    plaintext: R,
    nonce: V,
    mut ret: O,
) -> Result<(), Error> {
    let public_key = public_key.as_ref();
    let nonce = nonce.as_ref();
    let plaintext = plaintext.as_ref();
    let plaintext_length = plaintext.len();
    let ret = ret.as_mut();

    if ret.len() < ct_len(plaintext.len()) {
        return Err(Error::Encrypt(format!(
            "Bad output buffer len {}",
            ret.len()
        )));
    }

    if plaintext_length != 0 {
        let chunks = plaintext.chunks(KYBER_BLOCK_SIZE);

        for (chunk, output) in chunks.zip(ret.chunks_mut(KYBER_CIPHERTEXTBYTES)) {
            if chunk.len() < KYBER_BLOCK_SIZE {
                // fit the buffer to KYBER_BLOCK_SIZE
                let mut buf = [0u8; KYBER_BLOCK_SIZE];
                let slice = &mut buf[..chunk.len()];
                slice.copy_from_slice(chunk);
                indcpa_enc(output, &buf, public_key, nonce);
            } else {
                indcpa_enc(output, chunk, public_key, nonce);
            }
        }
    } else {
        // fill with zeroes
        let zeroes = [0u8; KYBER_BLOCK_SIZE];
        indcpa_enc(ret, &zeroes, public_key, nonce);
    }

    // append the plaintext len
    let length_pos = ret.len() - 8;
    (&mut ret[length_pos..])
        .write_u64::<NetworkEndian>(plaintext_length as u64)
        .unwrap();

    Ok(())
}

pub fn decrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(
    secret_key: T,
    ciphertext: R,
) -> Result<Vec<u8>, Error> {
    let ciphertext = ciphertext.as_ref();
    let secret_key = secret_key.as_ref();
    // calculate the length of each block
    const CIPHERTEXT_BLOCK_LEN: usize = pqc_kyber::KYBER_CIPHERTEXTBYTES;

    if ciphertext.len() < CIPHERTEXT_BLOCK_LEN {
        return Err(Decrypt(format!("The input ciphertext is too short")));
    }

    let plaintext_length = plaintext_len(ciphertext)
        .ok_or_else(|| Error::Decrypt("Invalid ciphertext input length".to_string()))?;
    let split_pt = ciphertext.len().saturating_sub(8);
    let (concatenated_ciphertexts, _) = ciphertext.split_at(split_pt);
    // pt len < 32: size must be 32
    // pt len = 32: size must be 32
    // pt len > 32: size must be div.ceil(pt.len()/32)*32
    let buffer_len = div_ceil(plaintext_length as f32, KYBER_BLOCK_SIZE as f32) * KYBER_BLOCK_SIZE;
    let mut ret = vec![0u8; buffer_len];
    // split the concatenated ciphertexts
    for (chunk, output) in concatenated_ciphertexts
        .chunks(CIPHERTEXT_BLOCK_LEN)
        .zip(ret.chunks_mut(KYBER_BLOCK_SIZE))
    {
        indcpa_dec(output, chunk, secret_key);
    }

    // finally, truncate the vec, as the final block is 32 in length, and may be more
    // than what the plaintext requires
    ret.truncate(plaintext_length);

    Ok(ret)
}

pub fn pke_keypair() -> Result<(PublicKey, SecretKey), KyberError> {
    let mut rng = rand::rngs::OsRng::default();
    let mut public = [0u8; pqc_kyber::KYBER_PUBLICKEYBYTES];
    let mut secret = [0u8; KYBER_SECRETKEYBYTES];
    indcpa_keypair(&mut public, &mut secret, None, &mut rng)?;
    Ok((public, secret))
}

pub fn kem_keypair() -> Result<Keypair, KyberError> {
    let mut rng = rand::rngs::OsRng::default();
    pqc_kyber::keypair(&mut rng)
}

#[derive(Debug, Clone)]
pub enum Error {
    Encrypt(String),
    Decrypt(String),
}

fn div_ceil(a: f32, b: f32) -> usize {
    ((a + b - 1.0) / b) as _
}

#[cfg(test)]
mod tests {
    use crate::pke_keypair;

    #[test]
    fn test_pke() {
        let (pk, sk) = pke_keypair().unwrap();
        let nonce = (0..32).into_iter().collect::<Vec<u8>>();
        let mut message = vec![];
        for x in 0..1000 {
            // test encryption of zero-sized inputs when x=0
            if x != 0 {
                message.push(x as u8);
            }

            let ciphertext = crate::encrypt(&pk, &message, &nonce).unwrap();
            assert_ne!(ciphertext, message);
            let plaintext = crate::decrypt(&sk, &ciphertext).unwrap();
            assert_eq!(plaintext, message);
        }
    }

    #[test]
    fn test_pke_large() {
        let (pk, sk) = pke_keypair().unwrap();
        let nonce = (0..32).into_iter().collect::<Vec<u8>>();
        let message = (0..10000)
            .into_iter()
            .map(|r| (r % 256) as u8)
            .collect::<Vec<u8>>();
        let ciphertext = crate::encrypt(&pk, &message, &nonce).unwrap();
        assert_ne!(ciphertext, message);
        let plaintext = crate::decrypt(&sk, &ciphertext).unwrap();
        assert_eq!(plaintext, message);
    }
}
