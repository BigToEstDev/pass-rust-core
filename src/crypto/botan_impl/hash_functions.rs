use crate::error::Result;

pub fn verify_hmac_sha256(key: &[u8], data: &[&[u8]], test_hash: &[u8]) -> Result<bool> {
    let mut hmac = botan::MsgAuthCode::new("HMAC(SHA-256)")?;
    hmac.set_key(key)?;
    for v in data {
        hmac.update(v)?;
    }
    let calculated = hmac.finish()?;
    let r = calculated == test_hash;
    Ok(r)
}

fn hmac_from_slices(hash_algorithm: &str, key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    let mut hmac = botan::MsgAuthCode::new(hash_algorithm)?;
    hmac.set_key(key)?;
    for v in data {
        hmac.update(v)?;
    }
    let result = hmac.finish()?;
    Ok(result)
}

// Creates HMAC hash of data coming in slices
pub fn hmac_sha256_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-256)", key, data)
}

pub fn hmac_sha256_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-256)", key, &[data])
}

pub fn _hmac_sha512_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-512)", key, data)
}

pub fn hmac_sha512_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-512)", key, &[data])
}

pub fn _hmac_sha1_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-1)", key, data)
}

pub fn hmac_sha1_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices("HMAC(SHA-1)", key, &[data])
}

fn hash_from_slice_vecs(hash_algorithm: &str, data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    let mut hasher = botan::HashFunction::new(hash_algorithm)?;
    for v in data {
        hasher.update(v)?;
    }
    let result = hasher.finish()?;
    //32 bytes hash output
    Ok(result)
}

// Returns 32 bytes (256 bits) hash of input data 'a slice of vecs'
pub fn sha256_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    hash_from_slice_vecs("SHA-256", data)
}

// Returns 64 bytes (512 bits) hash of input data 'a slice of vecs'
pub fn sha512_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    hash_from_slice_vecs("SHA-512", data)
}

//32 bytes hash output of input data 'a vec of vecs'
pub fn sha256_hash_vec_vecs(data: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    let mut hasher = botan::HashFunction::new("SHA-256")?;
    for v in data {
        hasher.update(v)?;
    }
    let result = hasher.finish()?;
    //32 bytes hash output
    Ok(result)
}

pub fn sha256_hash_from_slice(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = botan::HashFunction::new("SHA-256")?;
    hasher.update(data)?;
    Ok(hasher.finish()?)
}

#[cfg(test)]
mod tests {
    #[ignore]
    #[test]
    fn check_hmac_sha256() {
        use super::*;
        let key = "my secret and secure key of bytes with any size".as_bytes();
        let data1 = "input message".as_bytes();

        let h1 = hmac_sha256_from_slices(&key, &[&data1]).unwrap();

        let r = verify_hmac_sha256(&key, &[&data1], &h1).unwrap();
        println!("r is {}", r);
        assert!(r);
    }
}
