use crate::error::AppError;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const SERVICE: &str = "com.kovaron.tessera";
const ACCOUNT: &str = "passphrase";

#[tauri::command]
#[specta::specta]
pub fn keychain_save(passphrase: String) -> Result<(), AppError> {
    set_generic_password(SERVICE, ACCOUNT, passphrase.as_bytes())
        .map_err(|e| AppError::Http(e.to_string()))
}

#[tauri::command]
#[specta::specta]
pub fn keychain_load() -> Result<Option<String>, AppError> {
    match get_generic_password(SERVICE, ACCOUNT) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(_) => Ok(None),
    }
}

#[tauri::command]
#[specta::specta]
pub fn keychain_delete() -> Result<(), AppError> {
    let _ = delete_generic_password(SERVICE, ACCOUNT);
    Ok(())
}
