use crate::Error::Decrypt;
use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use pqc_kyber::{PublicKey, SecretKey, KYBER_CIPHERTEXTBYTES};

const KYBER_BLOCK_SIZE: usize = 32;

pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
    public_key: T,
    plaintext: R,
    nonce: V,
) -> Result<Vec<u8>, Error> {
    let public_key = public_key.as_ref();
    let nonce = nonce.as_ref();
    let plaintext = plaintext.as_ref();

    let chunks = plaintext.chunks(KYBER_BLOCK_SIZE);
    let full_ciphertext_output_len = chunks.len() * KYBER_CIPHERTEXTBYTES;
    const LENGTH_FIELD: usize = 8;

    let mut ret = vec![0u8; full_ciphertext_output_len + LENGTH_FIELD];

    for (chunk, output) in chunks.zip(ret.chunks_mut(KYBER_CIPHERTEXTBYTES)) {
        if chunk.len() < KYBER_BLOCK_SIZE {
            // fit the buffer to KYBER_BLOCK_SIZE
            let mut buf = vec![0u8; KYBER_BLOCK_SIZE];
            let slice = &mut buf.as_mut_slice()[..chunk.len()];
            slice.copy_from_slice(chunk);
            pqc_kyber::indcpa_enc(output, &buf, public_key, nonce);
        } else {
            pqc_kyber::indcpa_enc(output, chunk, public_key, nonce);
        }
    }

    // append the plaintext len
    ret.write_u64::<NetworkEndian>(plaintext.len() as u64)
        .unwrap();

    Ok(ret)
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

    // The final 8 bytes are for the original length of the plaintext
    let split_pt = ciphertext.len().saturating_sub(8);
    if split_pt > ciphertext.len() || split_pt == 0 {
        return Err(Error::Decrypt(
            "Invalid ciphertext input length".to_string(),
        ));
    }

    let (concatenated_ciphertexts, field_length_be) = ciphertext.split_at(split_pt);
    let plaintext_length = byteorder::NetworkEndian::read_u64(field_length_be) as usize;
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
        pqc_kyber::indcpa_dec(output, chunk, secret_key);
    }

    // finally, truncate the vec, as the final block is 32 in length, and may be more
    // than what the plaintext requires
    ret.truncate(plaintext_length);

    Ok(ret)
}

pub fn pke_keypair() -> (PublicKey, SecretKey) {
    let mut rng = rand::rngs::OsRng::default();
    let keys = pqc_kyber::keypair(&mut rng);
    (keys.public, keys.secret)
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
        let (pk, sk) = pke_keypair();
        let nonce = (0..32).into_iter().collect::<Vec<u8>>();
        let mut message = vec![];
        for x in 0..100 {
            message.push(x as u8);
            let ciphertext = crate::encrypt(&pk, &message, &nonce).unwrap();
            let plaintext = crate::decrypt(&sk, &ciphertext).unwrap();
            assert_eq!(plaintext, message);
        }
    }
}