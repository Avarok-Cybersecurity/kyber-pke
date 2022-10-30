pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
    &self,
    public_key: T,
    plaintext: R,
    nonce: V,
) -> Result<Vec<u8>, Error> {
    let public_key = public_key.as_ref();
    let nonce = nonce.as_ref();
    let plaintext = plaintext.as_ref();

    let mut ret = ByteArray::new();

    let chunks = plaintext.chunks(KYBER_BLOCK_SIZE);

    for chunk in chunks {
        let ciphertext_chunk = pqc_kyber::ret
            .data
            .extend_from_slice(self.encrypt_block(public_key, chunk, nonce)?.as_ref());
    }

    // append the plaintext len
    ret.data
        .write_u64::<NetworkEndian>(plaintext.len() as u64)
        .unwrap();

    Ok(ret)
}

pub fn decrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(
    secret_key: T,
    ciphertext: R,
) -> Result<Vec<u8>, Error> {
    let ciphertext = ciphertext.as_ref();
    let secret_key = secret_key.as_ref();
    let (du, dv) = self.d;
    // calculate the length of each block
    let ciphertext_block_len = (du * K * N / 8) + (dv * N / 8);

    // The final 8 bytes are for the original length of the plaintext
    let split_pt = ciphertext.len() - 8;
    if split_pt > ciphertext.len() {
        return Err(Error::Decrypt(
            "Invalid ciphertext input length".to_string(),
        ));
    }

    let (concatenated_ciphertexts, field_length_be) = ciphertext.split_at(split_pt);
    let plaintext_length = byteorder::NetworkEndian::read_u64(field_length_be) as usize;

    let mut ret = ByteArray {
        data: Vec::with_capacity(plaintext_length),
    };
    // split the concatenated ciphertexts
    for chunk in concatenated_ciphertexts.chunks(ciphertext_block_len) {
        let plaintext = self.decrypt_block(secret_key, chunk)?;
        ret.data.extend_from_slice(plaintext.as_ref());
    }

    // finally, truncate the vec, as the final block is 32 in length, and may be more
    // than what the plaintext requires
    ret.data.truncate(plaintext_length);

    Ok(ret)
}

#[derive(Debug, Clone)]
pub enum Error {
    Encrypt(String),
    Decrypt(String),
}
