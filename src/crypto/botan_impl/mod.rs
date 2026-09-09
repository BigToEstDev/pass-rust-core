// The botan src used by rust botan v0.10.7 is https://github.com/randombit/botan/blob/f60608b8818c7bb8579fe797122ed6116f4134af/src
// This is linked as git submodule in https://github.com/randombit/botan-rs/tree/0.10.7/botan-src

// See https://github.com/randombit/botan/blob/f60608b8818c7bb8579fe797122ed6116f4134af/src/lib/ffi/ffi.h to see all
// exposed C APIs by Botan lib. Botan’s ffi module provides a C89 binding intended to be easily
// usable with other language’s foreign function interface (FFI) libraries

// Also see https://github.com/randombit/botan/blob/f60608b8818c7bb8579fe797122ed6116f4134af/doc/api_ref/ffi.rst

mod block_cipher;
mod hash_functions;
mod key_cipher;
mod random;
mod stream_cipher;

pub use hash_functions::*;
pub use key_cipher::*;
pub use random::*;
pub use stream_cipher::ProtectedContentStreamCipher;

pub fn print_crypto_lib_info() {
    log::info!("The botan crypto impl module is used for all encryptions and decryptions");
}

// Тесты, дёргавшие botan:: напрямую (AES-CBC, ChaCha20, Argon2id round-trip), удалены:
// они проверяли чужую библиотеку, а не наш код, и всё равно исчезнут вместе с Botan в Step 10.
// Наши примитивы проверяются векторами из спецификаций в crypto/mod.rs и crypto/kdf.rs,
// а совместимость формата — tests/foreign_fixtures.rs и tools/kdbx-oracle/verify_roundtrip.py.
