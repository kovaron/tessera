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
pub fn keychain_save_with_biometry(passphrase: String) -> Result<(), AppError> {
    // Biometry is enforced at the UI layer via biometry_authenticate before
    // calling keychain_load. The keychain item itself is plain (no ACL), which
    // avoids errSecMissingEntitlement (-34018) on unsigned / dev builds.
    keychain_save(passphrase)
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

#[tauri::command]
#[specta::specta]
pub fn biometry_available() -> Result<bool, AppError> {
    #[cfg(target_os = "macos")]
    {
        Ok(can_evaluate_policy())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

#[tauri::command]
#[specta::specta]
pub fn biometry_authenticate(reason: String) -> Result<bool, AppError> {
    #[cfg(target_os = "macos")]
    {
        evaluate_policy(&reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        Ok(true)
    }
}

#[cfg(target_os = "macos")]
mod biometry {
    use crate::error::AppError;
    use block2::RcBlock;
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2_foundation::NSString;
    use std::sync::mpsc;
    use std::time::Duration;

    #[link(name = "LocalAuthentication", kind = "framework")]
    extern "C" {}

    // LAPolicyDeviceOwnerAuthentication = 2 (Touch ID OR device password fallback).
    // LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1 (biometry only).
    const POLICY: i64 = 2;

    fn la_context_class() -> Option<&'static AnyClass> {
        AnyClass::get(c"LAContext")
    }

    unsafe fn new_context(cls: &'static AnyClass) -> Option<Retained<AnyObject>> {
        let raw: *mut AnyObject = msg_send![cls, new];
        Retained::from_raw(raw)
    }

    pub(super) fn can_evaluate_policy() -> bool {
        let Some(cls) = la_context_class() else { return false; };
        unsafe {
            let Some(ctx) = new_context(cls) else { return false; };
            let mut err: *mut AnyObject = std::ptr::null_mut();
            let can: bool = msg_send![&*ctx, canEvaluatePolicy: POLICY, error: &mut err];
            can
        }
    }

    pub(super) fn evaluate_policy(reason: &str) -> Result<bool, AppError> {
        let Some(cls) = la_context_class() else {
            return Err(AppError::Http("LAContext class missing".into()));
        };
        let (tx, rx) = mpsc::sync_channel::<bool>(1);
        let block = RcBlock::new(move |success: Bool, _err: *mut AnyObject| {
            let _ = tx.send(success.as_bool());
        });
        unsafe {
            let Some(ctx) = new_context(cls) else {
                return Err(AppError::Http("LAContext alloc failed".into()));
            };
            let reason_ns = NSString::from_str(reason);
            let _: () = msg_send![
                &*ctx,
                evaluatePolicy: POLICY,
                localizedReason: &*reason_ns,
                reply: &*block,
            ];
        }
        rx.recv_timeout(Duration::from_secs(120))
            .map_err(|_| AppError::Http("biometry prompt timed out".into()))
    }
}

#[cfg(target_os = "macos")]
use biometry::{can_evaluate_policy, evaluate_policy};
