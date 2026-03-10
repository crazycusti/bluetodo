use super::paths::default_secret_key_path;
use super::*;

#[derive(Clone)]
pub(super) struct SecretStorageInfo {
    pub(super) storage_version: String,
    pub(super) migrated_at: String,
    pub(super) configured_secrets: usize,
    pub(super) encrypted_secrets: usize,
    pub(super) key_source: String,
    pub(super) key_location: String,
    pub(super) key_status: String,
    pub(super) preferred_setup: String,
}

pub(super) fn is_secret_setting_key(key: &str) -> bool {
    SECRET_SETTING_KEYS.contains(&key)
}

pub(super) fn is_encrypted_secret_value(value: &str) -> bool {
    value.starts_with(SECRET_VALUE_PREFIX)
}

fn secret_setting_aad(key: &str) -> String {
    format!("{}:{}", APP_ID, key)
}

pub(super) fn secret_storage_error(message: impl Into<String>) -> sqlx::Error {
    sqlx::Error::Protocol(message.into())
}

fn decode_secret_key_material(raw: &str) -> Result<[u8; SECRET_MASTER_KEY_LEN], String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|err| format!("Secret-Key ist kein gültiges Base64: {err}"))?;
    if decoded.len() != SECRET_MASTER_KEY_LEN {
        return Err(format!(
            "Secret-Key muss {} Bytes haben, gefunden: {}",
            SECRET_MASTER_KEY_LEN,
            decoded.len()
        ));
    }
    let mut key = [0u8; SECRET_MASTER_KEY_LEN];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn load_existing_secret_key() -> Result<Option<[u8; SECRET_MASTER_KEY_LEN]>, String> {
    if let Ok(raw) = env::var(SECRET_MASTER_KEY_ENV) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return decode_secret_key_material(trimmed).map(Some);
        }
    }

    let path = default_secret_key_path();
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "Secret-Key-Datei konnte nicht gelesen werden ({}): {}",
                path.display(),
                err
            ));
        }
    };

    decode_secret_key_material(&content).map(Some)
}

fn load_or_create_secret_key() -> Result<[u8; SECRET_MASTER_KEY_LEN], String> {
    if let Some(key) = load_existing_secret_key()? {
        return Ok(key);
    }

    let path = default_secret_key_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "Secret-Key-Verzeichnis konnte nicht erstellt werden ({}): {}",
                    parent.display(),
                    err
                )
            })?;
        }
    }

    let mut key = [0u8; SECRET_MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(encoded.as_bytes()).map_err(|err| {
                    format!(
                        "Secret-Key-Datei konnte nicht geschrieben werden ({}): {}",
                        path.display(),
                        err
                    )
                })?;
                file.write_all(b"\n").map_err(|err| {
                    format!(
                        "Secret-Key-Datei konnte nicht geschrieben werden ({}): {}",
                        path.display(),
                        err
                    )
                })?;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                if let Some(existing) = load_existing_secret_key()? {
                    return Ok(existing);
                }
                return Err(format!(
                    "Secret-Key-Datei existiert bereits, konnte aber nicht geladen werden ({})",
                    path.display()
                ));
            }
            Err(err) => {
                return Err(format!(
                    "Secret-Key-Datei konnte nicht erstellt werden ({}): {}",
                    path.display(),
                    err
                ));
            }
        }
    }

    #[cfg(not(unix))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(encoded.as_bytes()).map_err(|err| {
                    format!(
                        "Secret-Key-Datei konnte nicht geschrieben werden ({}): {}",
                        path.display(),
                        err
                    )
                })?;
                file.write_all(b"\n").map_err(|err| {
                    format!(
                        "Secret-Key-Datei konnte nicht geschrieben werden ({}): {}",
                        path.display(),
                        err
                    )
                })?;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                if let Some(existing) = load_existing_secret_key()? {
                    return Ok(existing);
                }
                return Err(format!(
                    "Secret-Key-Datei existiert bereits, konnte aber nicht geladen werden ({})",
                    path.display()
                ));
            }
            Err(err) => {
                return Err(format!(
                    "Secret-Key-Datei konnte nicht erstellt werden ({}): {}",
                    path.display(),
                    err
                ));
            }
        }
    }

    eprintln!("BlueTodo Secret-Key erzeugt unter {}", path.display());
    Ok(key)
}

pub(super) fn encrypt_secret_value(setting_key: &str, plaintext: &str) -> Result<String, String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }

    let key = load_or_create_secret_key()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Secret-Key konnte nicht initialisiert werden".to_string())?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: secret_setting_aad(setting_key).as_bytes(),
            },
        )
        .map_err(|_| format!("Secret '{}' konnte nicht verschlüsselt werden", setting_key))?;

    let mut blob = Vec::with_capacity(SECRET_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(format!(
        "{}{}",
        SECRET_VALUE_PREFIX,
        base64::engine::general_purpose::STANDARD.encode(blob)
    ))
}

pub(super) fn decrypt_secret_value(setting_key: &str, stored: &str) -> Result<String, String> {
    if stored.is_empty() || !is_encrypted_secret_value(stored) {
        return Ok(stored.to_string());
    }

    let key = load_existing_secret_key()?.ok_or_else(|| {
        format!(
            "Verschlüsselter Secret-Wert für '{}' gefunden, aber kein Master-Key verfügbar",
            setting_key
        )
    })?;
    let encoded = stored
        .strip_prefix(SECRET_VALUE_PREFIX)
        .ok_or_else(|| format!("Ungültiges Secret-Format für '{}'", setting_key))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|err| format!("Secret '{}' ist kein gültiges Base64: {}", setting_key, err))?;
    if blob.len() < SECRET_NONCE_LEN {
        return Err(format!("Secret '{}' ist zu kurz", setting_key));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Secret-Key konnte nicht initialisiert werden".to_string())?;
    let nonce = XNonce::from_slice(&blob[..SECRET_NONCE_LEN]);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob[SECRET_NONCE_LEN..],
                aad: secret_setting_aad(setting_key).as_bytes(),
            },
        )
        .map_err(|_| format!("Secret '{}' konnte nicht entschlüsselt werden", setting_key))?;
    String::from_utf8(plaintext)
        .map_err(|_| format!("Secret '{}' ist kein gültiges UTF-8", setting_key))
}

pub(super) fn inspect_secret_key_runtime() -> (String, String, String) {
    if let Ok(raw) = env::var(SECRET_MASTER_KEY_ENV) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let status = match decode_secret_key_material(trimmed) {
                Ok(_) => "geladen".to_string(),
                Err(message) => format!("ungültig: {}", message),
            };
            return (
                format!("Umgebung ({})", SECRET_MASTER_KEY_ENV),
                "direkt in der Prozessumgebung".to_string(),
                status,
            );
        }
    }

    let path = default_secret_key_path();
    let source = if env::var(SECRET_MASTER_KEY_FILE_ENV)
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        format!("Datei ({})", SECRET_MASTER_KEY_FILE_ENV)
    } else {
        "Default-Datei".to_string()
    };
    let status = match fs::read_to_string(&path) {
        Ok(content) => match decode_secret_key_material(&content) {
            Ok(_) => "geladen".to_string(),
            Err(message) => format!("ungültig: {}", message),
        },
        Err(err) if err.kind() == ErrorKind::NotFound => "noch nicht erzeugt".to_string(),
        Err(err) => format!("Fehler beim Lesen: {}", err),
    };
    (source, path.to_string_lossy().to_string(), status)
}
