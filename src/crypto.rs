//! Envelope format, Argon2id key derivation and XChaCha20-Poly1305 AEAD. Pure: no I/O.
//!
//! Envelope v1 layout (see README → *Security design*):
//!
//! ```text
//! offset  size    field
//! 0       8       magic       "PEMVAULT"
//! 8       1       version     0x01
//! 9       16      salt        Argon2id salt (CSPRNG)
//! 25      24      nonce       XChaCha20 nonce (CSPRNG)
//! 49      N + 16  ciphertext  encrypted PEM + Poly1305 tag
//! ```
//!
//! The AEAD associated data is `header (bytes 0..49) ‖ key name`, so tampering with any
//! header byte, or renaming/swapping envelopes between key names, fails authentication.

use std::fmt;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit, Nonce, Tag};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"PEMVAULT";
pub const VERSION: u8 = 0x01;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;
pub const TAG_LEN: usize = 16;
/// Smallest valid envelope: header + tag over an empty plaintext.
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + TAG_LEN;

const KEY_LEN: usize = 32;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    /// Frozen parameters for envelope version `0x01`. Existing vaults depend on these:
    /// changing them requires a new `VERSION` (CLAUDE.md invariant 5).
    const V1: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 4,
    };

    /// Cheap parameters so tests can run hundreds of derivations. Never used in production.
    #[cfg(test)]
    const FAST_TEST: Self = Self {
        m_cost_kib: 32,
        t_cost: 1,
        p_cost: 4,
    };

    fn for_version(version: u8) -> Result<Self, CryptoError> {
        match version {
            VERSION => Ok(Self::V1),
            other => Err(CryptoError::UnsupportedVersion(other)),
        }
    }
}

/// Errors from envelope handling.
///
/// Every authentication failure maps to the single [`CryptoError::Decrypt`] variant so callers
/// cannot tell a wrong passphrase from corrupted data or a name mismatch (invariant 6).
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u8),
    Decrypt,
    Encrypt,
    Kdf,
    Rng,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => {
                f.write_str("encrypted data is truncated or not a pem-vault envelope")
            }
            Self::BadMagic => f.write_str("not a pem-vault envelope (bad magic header)"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported envelope version {v:#04x}; a newer pem-vault is required"
            ),
            Self::Decrypt => {
                f.write_str("decryption failed: wrong passphrase, corrupted data, or name mismatch")
            }
            Self::Encrypt => f.write_str("encryption failed"),
            Self::Kdf => f.write_str("Argon2id key derivation failed"),
            Self::Rng => f.write_str("the operating system's random number generator failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Envelope header. Contains no secrets: salt and nonce are public by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    /// A current-version header with a fresh salt and nonce from the OS CSPRNG.
    fn random() -> Result<Self, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(|_| CryptoError::Rng)?;
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Rng)?;
        Ok(Self {
            version: VERSION,
            salt,
            nonce,
        })
    }

    /// Serializes the header to its fixed 49-byte wire form.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8] = self.version;
        out[9..9 + SALT_LEN].copy_from_slice(&self.salt);
        out[9 + SALT_LEN..].copy_from_slice(&self.nonce);
        out
    }

    /// Parses and validates the header of `envelope`, returning it with the remaining
    /// `ciphertext ‖ tag` bytes. Checks length, magic and version before any slicing.
    pub fn parse(envelope: &[u8]) -> Result<(Self, &[u8]), CryptoError> {
        if envelope.len() < MIN_ENVELOPE_LEN {
            return Err(CryptoError::Truncated);
        }
        let (header, body) = envelope.split_at(HEADER_LEN);
        if &header[..8] != MAGIC {
            return Err(CryptoError::BadMagic);
        }
        if header[8] != VERSION {
            return Err(CryptoError::UnsupportedVersion(header[8]));
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.copy_from_slice(&header[9..9 + SALT_LEN]);
        nonce.copy_from_slice(&header[9 + SALT_LEN..]);
        Ok((
            Self {
                version: header[8],
                salt,
                nonce,
            },
            body,
        ))
    }
}

/// Derives a 256-bit key from `passphrase` and `salt` with Argon2id v0x13.
///
/// The key is returned in a [`Zeroizing`] buffer and scrubbed when dropped.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::Kdf)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    // We supply Argon2's working memory (64 MiB for v1) ourselves: the argon2 crate frees its
    // own buffer without wiping it, and that memory is derived from the passphrase.
    let mut memory = Zeroizing::new(vec![Block::new(); params.block_count()]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(passphrase, salt, key.as_mut_slice(), memory.as_mut_slice())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

fn cipher_for(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Kdf)
}

/// AAD = the full 49-byte header followed by the UTF-8 key name.
fn associated_data(header: &[u8], key_name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + key_name.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(key_name.as_bytes());
    aad
}

/// Encrypts `plaintext` into a v1 envelope bound to `key_name`.
///
/// A fresh salt and nonce are drawn from the OS CSPRNG for every call, and the key is derived
/// with the frozen v1 Argon2id parameters. The plaintext is only ever copied into a
/// pre-sized, zeroize-on-drop buffer where it is encrypted in place.
pub fn encrypt(
    plaintext: &[u8],
    passphrase: &[u8],
    key_name: &str,
) -> Result<Vec<u8>, CryptoError> {
    encrypt_with(
        plaintext,
        passphrase,
        key_name,
        &Header::random()?,
        KdfParams::V1,
    )
}

fn encrypt_with(
    plaintext: &[u8],
    passphrase: &[u8],
    key_name: &str,
    header: &Header,
    params: KdfParams,
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_key(passphrase, &header.salt, params)?;
    let cipher = cipher_for(&key)?;
    let header_bytes = header.to_bytes();
    let aad = associated_data(&header_bytes, key_name);
    let nonce = Nonce::<XChaCha20Poly1305>::from(header.nonce);

    // Capacity is exact, so the buffer never reallocates and leaves no plaintext copies behind.
    // It is zeroized if encryption fails while it still holds plaintext.
    let mut envelope = Zeroizing::new(Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN));
    envelope.extend_from_slice(&header_bytes);
    envelope.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut envelope[HEADER_LEN..]).into())
        .map_err(|_| CryptoError::Encrypt)?;
    envelope.extend_from_slice(&tag);

    // Now ciphertext only: hand ownership out of the zeroizing wrapper.
    Ok(std::mem::take(&mut *envelope))
}

/// Decrypts a v1 envelope, verifying the Poly1305 tag over `header ‖ key_name` before any
/// plaintext is produced.
///
/// Structural problems (truncation, bad magic, unknown version) are reported specifically;
/// every authentication failure is reported as the generic [`CryptoError::Decrypt`].
pub fn decrypt(
    envelope: &[u8],
    passphrase: &[u8],
    key_name: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (header, _) = Header::parse(envelope)?;
    decrypt_with(
        envelope,
        passphrase,
        key_name,
        KdfParams::for_version(header.version)?,
    )
}

fn decrypt_with(
    envelope: &[u8],
    passphrase: &[u8],
    key_name: &str,
    params: KdfParams,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (header, body) = Header::parse(envelope)?;
    // `parse` guarantees body.len() >= TAG_LEN.
    let (ciphertext, tag) = body.split_at(body.len() - TAG_LEN);
    let tag = Tag::<XChaCha20Poly1305>::try_from(tag).map_err(|_| CryptoError::Decrypt)?;

    let key = derive_key(passphrase, &header.salt, params)?;
    let cipher = cipher_for(&key)?;
    let aad = associated_data(&envelope[..HEADER_LEN], key_name);
    let nonce = Nonce::<XChaCha20Poly1305>::from(header.nonce);

    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&nonce, &aad, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct horse battery staple";
    const NAME: &str = "prod-bastion.pem";
    const PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n";

    fn fast_encrypt(plaintext: &[u8], passphrase: &[u8], key_name: &str) -> Vec<u8> {
        encrypt_with(
            plaintext,
            passphrase,
            key_name,
            &Header::random().unwrap(),
            KdfParams::FAST_TEST,
        )
        .unwrap()
    }

    fn fast_decrypt(
        envelope: &[u8],
        passphrase: &[u8],
        key_name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        decrypt_with(envelope, passphrase, key_name, KdfParams::FAST_TEST)
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ---- Spec constants -------------------------------------------------------------------

    #[test]
    fn constants_match_spec() {
        assert_eq!(MAGIC, b"PEMVAULT");
        assert_eq!(VERSION, 0x01);
        assert_eq!(HEADER_LEN, 49);
        assert_eq!(MIN_ENVELOPE_LEN, 65);
        assert_eq!(
            KdfParams::V1,
            KdfParams {
                m_cost_kib: 65536,
                t_cost: 3,
                p_cost: 4
            }
        );
    }

    #[test]
    fn header_round_trips() {
        let header = Header::random().unwrap();
        let mut envelope = header.to_bytes().to_vec();
        envelope.extend_from_slice(&[0u8; TAG_LEN]);
        let (parsed, body) = Header::parse(&envelope).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(body.len(), TAG_LEN);
    }

    // ---- Known-answer test (independent reference: argon2-cffi + libsodium) -------------

    /// Generated with argon2-cffi `hash_secret_raw(Type.ID, v19, t=3, m=65536, p=4)` and
    /// libsodium `crypto_aead_xchacha20poly1305_ietf_encrypt(pt, header ‖ name, nonce, key)`.
    const KAT_ENVELOPE: &str = "50454d5641554c5401000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262715bd928d4838eda41f989fff4e231abdb3f8ce5747903105cff7e9b1cc356c3aadea2900cdb9878ba35b03424747026d2fffb4a360099df0a823c1eeefa5a33d4ec6d7b04285a8af2b9d2d209af8a353265e22090a";
    const KAT_KEY: &str = "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e";

    fn kat_header() -> Header {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        nonce
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = 0x10 + i as u8);
        Header {
            version: VERSION,
            salt,
            nonce,
        }
    }

    #[test]
    fn kat_v1_key_derivation_matches_reference() {
        let key = derive_key(PASS, &kat_header().salt, KdfParams::V1).unwrap();
        assert_eq!(key.as_slice(), hex(KAT_KEY).as_slice());
    }

    #[test]
    fn kat_v1_encrypt_matches_reference() {
        let envelope = encrypt_with(PEM, PASS, NAME, &kat_header(), KdfParams::V1).unwrap();
        assert_eq!(envelope, hex(KAT_ENVELOPE));
    }

    #[test]
    fn kat_v1_reference_envelope_decrypts_via_public_api() {
        let plaintext = decrypt(&hex(KAT_ENVELOPE), PASS, NAME).unwrap();
        assert_eq!(plaintext.as_slice(), PEM);
    }

    // ---- Round trips ----------------------------------------------------------------------

    #[test]
    fn public_api_round_trip() {
        let envelope = encrypt(PEM, PASS, NAME).unwrap();
        assert_eq!(envelope.len(), HEADER_LEN + PEM.len() + TAG_LEN);
        assert_eq!(decrypt(&envelope, PASS, NAME).unwrap().as_slice(), PEM);
    }

    #[test]
    fn round_trip_empty_payload() {
        let envelope = fast_encrypt(b"", PASS, NAME);
        assert_eq!(envelope.len(), MIN_ENVELOPE_LEN);
        assert!(fast_decrypt(&envelope, PASS, NAME).unwrap().is_empty());
    }

    #[test]
    fn round_trip_one_mib_payload() {
        let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let envelope = fast_encrypt(&payload, PASS, NAME);
        assert_eq!(
            fast_decrypt(&envelope, PASS, NAME).unwrap().as_slice(),
            payload
        );
    }

    // ---- Authentication failures ------------------------------------------------------------

    #[test]
    fn wrong_passphrase_fails() {
        let envelope = fast_encrypt(PEM, PASS, NAME);
        assert_eq!(
            fast_decrypt(&envelope, b"wrong passphrase", NAME),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn wrong_key_name_fails() {
        let envelope = fast_encrypt(PEM, PASS, NAME);
        assert_eq!(
            fast_decrypt(&envelope, PASS, "other.pem"),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn swapped_envelopes_fail() {
        let a = fast_encrypt(b"key A", PASS, "a.pem");
        let b = fast_encrypt(b"key B", PASS, "b.pem");
        // An attacker swaps the two files in Drive: each is now fetched under the other's name.
        assert_eq!(fast_decrypt(&b, PASS, "a.pem"), Err(CryptoError::Decrypt));
        assert_eq!(fast_decrypt(&a, PASS, "b.pem"), Err(CryptoError::Decrypt));
    }

    #[test]
    fn flipping_any_header_byte_fails() {
        let envelope = fast_encrypt(PEM, PASS, NAME);
        for i in 0..HEADER_LEN {
            let mut tampered = envelope.clone();
            tampered[i] ^= 0x01;
            let expected = match i {
                0..=7 => CryptoError::BadMagic,
                8 => CryptoError::UnsupportedVersion(VERSION ^ 0x01),
                _ => CryptoError::Decrypt,
            };
            assert_eq!(
                fast_decrypt(&tampered, PASS, NAME),
                Err(expected),
                "byte {i}"
            );
        }
    }

    #[test]
    fn flipping_ciphertext_or_tag_byte_fails() {
        let envelope = fast_encrypt(PEM, PASS, NAME);
        for i in [HEADER_LEN, envelope.len() - TAG_LEN - 1, envelope.len() - 1] {
            let mut tampered = envelope.clone();
            tampered[i] ^= 0x80;
            assert_eq!(
                fast_decrypt(&tampered, PASS, NAME),
                Err(CryptoError::Decrypt),
                "byte {i}"
            );
        }
    }

    #[test]
    fn truncated_inputs_fail() {
        for len in [0, 48, 64] {
            assert_eq!(
                fast_decrypt(&vec![0u8; len], PASS, NAME),
                Err(CryptoError::Truncated),
                "len {len}"
            );
        }
        let envelope = fast_encrypt(PEM, PASS, NAME);
        assert_eq!(
            fast_decrypt(&envelope[..envelope.len() - 1], PASS, NAME),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn decrypt_error_message_is_generic() {
        let msg = CryptoError::Decrypt.to_string();
        for needle in ["passphrase", "corrupted", "name"] {
            assert!(msg.contains(needle), "{msg}");
        }
    }

    // ---- Randomness ---------------------------------------------------------------------------

    #[test]
    fn each_encryption_uses_fresh_salt_and_nonce() {
        let a = fast_encrypt(PEM, PASS, NAME);
        let b = fast_encrypt(PEM, PASS, NAME);
        let (ha, _) = Header::parse(&a).unwrap();
        let (hb, _) = Header::parse(&b).unwrap();
        assert_ne!(ha.salt, hb.salt);
        assert_ne!(ha.nonce, hb.nonce);
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    }
}
