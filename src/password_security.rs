use crate::config::Config;
use sha2::{Digest, Sha256};
use sodiumoxide::base64;
use std::{
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

const DERIVED_TEMPORARY_PASSWORD_VERSION: &str = "rustdesk-derived-temporary-password-v1";
const DERIVED_TEMPORARY_PASSWORD_WINDOW_TOLERANCE: i64 = 1;
const DERIVED_TEMPORARY_PASSWORD_NUM_CHARS: &[char] =
    &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
const DERIVED_TEMPORARY_PASSWORD_CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

lazy_static::lazy_static! {
    pub static ref TEMPORARY_PASSWORD:Arc<RwLock<String>> = Arc::new(RwLock::new(get_auto_password()));
    static ref DERIVED_TEMPORARY_PASSWORD_LOCKED_WINDOW: RwLock<Option<i64>> =
        RwLock::new(None);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationMethod {
    OnlyUseTemporaryPassword,
    OnlyUsePermanentPassword,
    UseBothPasswords,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveMode {
    Both,
    Password,
    Click,
}

fn derived_temporary_password_enabled() -> bool {
    !crate::config::TEMPORARY_PASSWORD_DERIVE_SALT.is_empty()
}

pub fn temporary_password_supports_rotation() -> bool {
    !derived_temporary_password_enabled()
}

pub fn lock_temporary_password_until_next_window() {
    if !derived_temporary_password_enabled() {
        return;
    }
    *DERIVED_TEMPORARY_PASSWORD_LOCKED_WINDOW.write().unwrap() =
        Some(current_temporary_password_window());
}

fn derived_temporary_password_lock_is_active(current_window: i64) -> bool {
    let mut locked_window = DERIVED_TEMPORARY_PASSWORD_LOCKED_WINDOW.write().unwrap();
    match *locked_window {
        Some(window) if window >= current_window => true,
        Some(_) => {
            *locked_window = None;
            false
        }
        None => false,
    }
}

fn temporary_password_window_seconds() -> i64 {
    crate::config::TEMPORARY_PASSWORD_WINDOW_SECONDS.max(1)
}

fn current_temporary_password_window() -> i64 {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    now_secs.div_euclid(temporary_password_window_seconds())
}

fn temporary_password_chars() -> &'static [char] {
    if Config::get_bool_option(crate::config::keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD) {
        DERIVED_TEMPORARY_PASSWORD_NUM_CHARS
    } else {
        DERIVED_TEMPORARY_PASSWORD_CHARS
    }
}

fn temporary_password_uuid_base64() -> String {
    base64::encode(&crate::get_uuid(), base64::Variant::Original)
}

fn derive_temporary_password_from_inputs(
    uuid_base64: &str,
    salt: &str,
    window_seconds: i64,
    window_index: i64,
    length: usize,
    chars: &[char],
) -> String {
    if uuid_base64.is_empty() || salt.is_empty() || length == 0 || chars.is_empty() {
        return String::new();
    }

    let charset_name = if chars == DERIVED_TEMPORARY_PASSWORD_NUM_CHARS {
        "numeric"
    } else {
        "mixed"
    };
    let mut password = String::with_capacity(length);
    let mut block_index = 0usize;

    while password.len() < length {
        let window_seconds_str = window_seconds.to_string();
        let window_index_str = window_index.to_string();
        let length_str = length.to_string();
        let block_index_str = block_index.to_string();
        let mut hasher = Sha256::new();
        for field in [
            DERIVED_TEMPORARY_PASSWORD_VERSION,
            salt,
            uuid_base64,
            &window_seconds_str,
            &window_index_str,
            &length_str,
            charset_name,
            &block_index_str,
        ] {
            hasher.update(field.as_bytes());
            hasher.update([0]);
        }

        for byte in hasher.finalize() {
            password.push(chars[byte as usize % chars.len()]);
            if password.len() == length {
                break;
            }
        }

        block_index += 1;
    }

    password
}

fn derived_temporary_password_for_window(window_index: i64) -> String {
    derive_temporary_password_from_inputs(
        &temporary_password_uuid_base64(),
        crate::config::TEMPORARY_PASSWORD_DERIVE_SALT,
        temporary_password_window_seconds(),
        window_index,
        temporary_password_length(),
        temporary_password_chars(),
    )
}

fn get_auto_password() -> String {
    if derived_temporary_password_enabled() {
        return derived_temporary_password_for_window(current_temporary_password_window());
    }

    let len = temporary_password_length();
    if Config::get_bool_option(crate::config::keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD) {
        Config::get_auto_numeric_password(len)
    } else {
        Config::get_auto_password(len)
    }
}

// Should only be called in server
pub fn update_temporary_password() {
    *TEMPORARY_PASSWORD.write().unwrap() = get_auto_password();
}

// Should only be called in server
pub fn temporary_password() -> String {
    if derived_temporary_password_enabled() {
        return derived_temporary_password_for_window(current_temporary_password_window());
    }
    TEMPORARY_PASSWORD.read().unwrap().clone()
}

pub fn temporary_password_candidates() -> Vec<String> {
    if !derived_temporary_password_enabled() {
        let password = TEMPORARY_PASSWORD.read().unwrap().clone();
        return if password.is_empty() {
            vec![]
        } else {
            vec![password]
        };
    }

    let current_window = current_temporary_password_window();
    if derived_temporary_password_lock_is_active(current_window) {
        return vec![];
    }

    let mut passwords = Vec::with_capacity(3);
    for offset in [
        0,
        -DERIVED_TEMPORARY_PASSWORD_WINDOW_TOLERANCE,
        DERIVED_TEMPORARY_PASSWORD_WINDOW_TOLERANCE,
    ] {
        let password = derived_temporary_password_for_window(current_window + offset);
        if !password.is_empty() && !passwords.contains(&password) {
            passwords.push(password);
        }
    }
    passwords
}

fn verification_method() -> VerificationMethod {
    let method = Config::get_option("verification-method");
    if method == "use-temporary-password" {
        VerificationMethod::OnlyUseTemporaryPassword
    } else if method == "use-permanent-password" {
        VerificationMethod::OnlyUsePermanentPassword
    } else {
        VerificationMethod::UseBothPasswords // default
    }
}

pub fn temporary_password_length() -> usize {
    let length = Config::get_option("temporary-password-length");
    if length == "8" {
        8
    } else if length == "10" {
        10
    } else {
        6 // default
    }
}

pub fn temporary_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUsePermanentPassword
}

pub fn permanent_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUseTemporaryPassword
}

pub fn has_valid_password() -> bool {
    temporary_enabled() && !temporary_password().is_empty()
        || permanent_enabled() && Config::has_permanent_password()
}

pub fn approve_mode() -> ApproveMode {
    let mode = Config::get_option("approve-mode");
    if mode == "password" {
        ApproveMode::Password
    } else if mode == "click" {
        ApproveMode::Click
    } else {
        ApproveMode::Both
    }
}

pub fn hide_cm() -> bool {
    approve_mode() == ApproveMode::Password
        && verification_method() == VerificationMethod::OnlyUsePermanentPassword
        && crate::config::option2bool("allow-hide-cm", &Config::get_option("allow-hide-cm"))
}

const VERSION_LEN: usize = 2;

// Check if data is already encrypted by verifying:
// 1) version prefix "00"
// 2) valid base64 payload
// 3) decoded payload length >= secretbox::MACBYTES
//
// We intentionally avoid trying to decrypt here because key mismatch would cause
// false negatives.
// Reference: secretbox::seal returns ciphertext length = plaintext length + MACBYTES
// https://github.com/sodiumoxide/sodiumoxide/blob/3057acb1a030ad86ed8892a223d64036ab5e8523/src/crypto/secretbox/xsalsa20poly1305.rs#L67
fn is_encrypted(v: &[u8]) -> bool {
    if v.len() <= VERSION_LEN || !v.starts_with(b"00") {
        return false;
    }
    match base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
        Ok(decoded) => decoded.len() >= sodiumoxide::crypto::secretbox::MACBYTES,
        Err(_) => false,
    }
}

pub fn encrypt_str_or_original(s: &str, version: &str, max_len: usize) -> String {
    if is_encrypted(s.as_bytes()) {
        log::error!("Duplicate encryption!");
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        return String::default();
    }
    if version == "00" {
        if let Ok(s) = encrypt(s.as_bytes()) {
            return version.to_owned() + &s;
        }
    }
    s.to_owned()
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       &[..2] return the left 2 bytes, s.chars().take(2) return the left 2 chars
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    if s.len() > VERSION_LEN {
        if s.starts_with("00") {
            if let Ok(v) = decrypt(s[VERSION_LEN..].as_bytes()) {
                return (
                    String::from_utf8_lossy(&v).to_string(),
                    true,
                    "00" != current_version,
                );
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (
        s.to_owned(),
        false,
        !s.is_empty() && !is_encrypted(s.as_bytes()),
    )
}

pub fn encrypt_vec_or_original(v: &[u8], version: &str, max_len: usize) -> Vec<u8> {
    if is_encrypted(v) {
        log::error!("Duplicate encryption!");
        return v.to_owned();
    }
    if v.len() > max_len {
        return vec![];
    }
    if version == "00" {
        if let Ok(s) = encrypt(v) {
            let mut version = version.to_owned().into_bytes();
            version.append(&mut s.into_bytes());
            return version;
        }
    }
    v.to_owned()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    if v.len() > VERSION_LEN {
        let version = String::from_utf8_lossy(&v[..VERSION_LEN]);
        if version == "00" {
            if let Ok(v) = decrypt(&v[VERSION_LEN..]) {
                return (v, true, version != current_version);
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (v.to_owned(), false, !v.is_empty() && !is_encrypted(v))
}

fn encrypt(v: &[u8]) -> Result<String, ()> {
    if !v.is_empty() {
        symmetric_crypt(v, true).map(|v| base64::encode(v, base64::Variant::Original))
    } else {
        Err(())
    }
}

fn decrypt(v: &[u8]) -> Result<Vec<u8>, ()> {
    if !v.is_empty() {
        base64::decode(v, base64::Variant::Original).and_then(|v| symmetric_crypt(&v, false))
    } else {
        Err(())
    }
}

pub fn symmetric_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let uuid = crate::get_uuid();
    let mut keybuf = uuid.clone();
    keybuf.resize(secretbox::KEYBYTES, 0);
    let key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);
    let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

    if encrypt {
        Ok(secretbox::seal(data, &nonce, &key))
    } else {
        let res = secretbox::open(data, &nonce, &key);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if res.is_err() {
            // Fallback: try pk if uuid decryption failed (in case encryption used pk due to machine_uid failure)
            if let Some(key_pair) = Config::get_existing_key_pair() {
                let pk = key_pair.1;
                if pk != uuid {
                    let mut keybuf = pk;
                    keybuf.resize(secretbox::KEYBYTES, 0);
                    let pk_key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);
                    return secretbox::open(data, &nonce, &pk_key);
                }
            }
        }
        res
    }
}

mod test {

    #[test]
    fn test() {
        use super::*;
        use rand::{thread_rng, Rng};
        use std::time::Instant;

        let version = "00";
        let max_len = 128;

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, version, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, version, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test original");
        let data = version.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version).0, data);

        // Base64-shaped "00" prefixed values shorter than MACBYTES are treated
        // as original/plain values and should be stored.
        let data = "00YWJjZA==";
        let (decrypted, succ, store) = decrypt_str_or_original(data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
        let data = b"00YWJjZA==".to_vec();
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);

        // When decoded length reaches MACBYTES, it is treated as encrypted-like
        // and should not trigger repeated store.
        let exact_mac = vec![0u8; sodiumoxide::crypto::secretbox::MACBYTES];
        let exact_mac_b64 =
            sodiumoxide::base64::encode(&exact_mac, sodiumoxide::base64::Variant::Original);
        let data = format!("00{exact_mac_b64}");
        let (_, succ, store) = decrypt_str_or_original(&data, version);
        assert!(!succ);
        assert!(!store);
        let data = data.into_bytes();
        let (_, succ, store) = decrypt_vec_or_original(&data, version);
        assert!(!succ);
        assert!(!store);

        println!("test speed");
        let test_speed = |len: usize, name: &str| {
            let mut data: Vec<u8> = vec![];
            let mut rng = thread_rng();
            for _ in 0..len {
                data.push(rng.gen_range(0..255));
            }
            let start: Instant = Instant::now();
            let encrypted = encrypt_vec_or_original(&data, version, len);
            assert_ne!(data, decrypted);
            let t1 = start.elapsed();
            let start = Instant::now();
            let (decrypted, _, _) = decrypt_vec_or_original(&encrypted, version);
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("{name}");
            println!("encrypt:{:?}, decrypt:{:?}", t1, t2);

            let start: Instant = Instant::now();
            let encrypted = base64::encode(&data, base64::Variant::Original);
            let t1 = start.elapsed();
            let start = Instant::now();
            let decrypted = base64::decode(&encrypted, base64::Variant::Original).unwrap();
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("base64, encrypt:{:?}, decrypt:{:?}", t1, t2,);
        };
        test_speed(128, "128");
        test_speed(1024, "1k");
        test_speed(1024 * 1024, "1M");
        test_speed(10 * 1024 * 1024, "10M");
        test_speed(100 * 1024 * 1024, "100M");
    }

    #[test]
    fn test_is_encrypted() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;

        // Empty data should not be considered encrypted
        assert!(!is_encrypted(b""));
        assert!(!is_encrypted(b"0"));
        assert!(!is_encrypted(b"00"));

        // Data without "00" prefix should not be considered encrypted
        assert!(!is_encrypted(b"01abcd"));
        assert!(!is_encrypted(b"99abcd"));
        assert!(!is_encrypted(b"hello world"));

        // Data with "00" prefix but invalid base64 should not be considered encrypted
        assert!(!is_encrypted(b"00!!!invalid base64!!!"));
        assert!(!is_encrypted(b"00@#$%"));

        // Data with "00" prefix and valid base64 but shorter than MACBYTES is not encrypted
        assert!(!is_encrypted(b"00YWJjZA==")); // "abcd" in base64
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=")); // "Hello World" in base64

        // Data with "00" prefix and valid base64 with decoded len == MACBYTES is considered encrypted
        let exact_mac = vec![0u8; secretbox::MACBYTES];
        let exact_mac_b64 = encode(&exact_mac, Variant::Original);
        let exact_mac_candidate = format!("00{exact_mac_b64}");
        assert!(is_encrypted(exact_mac_candidate.as_bytes()));

        // Real encrypted data should be detected
        let version = "00";
        let max_len = 128;
        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        assert!(is_encrypted(encrypted_str.as_bytes()));
        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        assert!(is_encrypted(&encrypted_vec));

        // Original unencrypted data should not be detected as encrypted
        assert!(!is_encrypted(b"1"));
        assert!(!is_encrypted("1".as_bytes()));
    }

    #[test]
    fn test_encrypted_payload_min_len_macbytes() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};
        use sodiumoxide::crypto::secretbox;

        let version = "00";
        let max_len = 128;

        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        let decoded = decode(&encrypted_str.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );

        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        let decoded = decode(&encrypted_vec[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );
    }

    // Test decryption fallback when data was encrypted with key_pair but decryption tries machine_uid first
    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_with_pk_fallback() {
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let uuid = crate::get_uuid();
        let pk = crate::config::Config::get_key_pair().1;

        // Ensure uuid != pk, otherwise fallback branch won't be tested
        if uuid == pk {
            eprintln!("skip: uuid == pk, fallback branch won't be tested");
            return;
        }

        let data = b"test password 123";
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        // Encrypt with pk (simulating machine_uid failure during encryption)
        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let encrypted = secretbox::seal(data, &nonce, &pk_key);

        // Decrypt using symmetric_crypt (should fallback to pk since uuid differs)
        let decrypted = super::symmetric_crypt(&encrypted, false);
        assert!(
            decrypted.is_ok(),
            "Decryption with pk fallback should succeed"
        );
        assert_eq!(decrypted.unwrap(), data);
    }

    #[test]
    fn test_derived_temporary_password_is_stable() {
        let password_a = derive_temporary_password_from_inputs(
            "dGVzdC11dWlkLWJhc2U2NA==",
            "demo-salt",
            300,
            5_712_345,
            8,
            DERIVED_TEMPORARY_PASSWORD_CHARS,
        );
        let password_b = derive_temporary_password_from_inputs(
            "dGVzdC11dWlkLWJhc2U2NA==",
            "demo-salt",
            300,
            5_712_345,
            8,
            DERIVED_TEMPORARY_PASSWORD_CHARS,
        );
        let password_next_window = derive_temporary_password_from_inputs(
            "dGVzdC11dWlkLWJhc2U2NA==",
            "demo-salt",
            300,
            5_712_346,
            8,
            DERIVED_TEMPORARY_PASSWORD_CHARS,
        );

        assert_eq!(password_a, password_b);
        assert_eq!(password_a.len(), 8);
        assert_ne!(password_a, password_next_window);
    }

    #[test]
    fn test_derived_temporary_password_numeric_mode() {
        let password = derive_temporary_password_from_inputs(
            "dGVzdC11dWlkLWJhc2U2NA==",
            "demo-salt",
            300,
            5_712_345,
            6,
            DERIVED_TEMPORARY_PASSWORD_NUM_CHARS,
        );

        assert_eq!(password.len(), 6);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }
}
