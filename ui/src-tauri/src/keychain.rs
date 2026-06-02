use crate::error::AppError;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFGetTypeID, CFRelease, CFTypeRef};
use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID, CFDataRef};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlOr, kSecAccessControlUserPresence,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, SecAccessControlCreateWithFlags,
};
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess, SecAccessControlRef};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
use std::ptr;

const SERVICE: &str = "com.kovaron.tessera";
const ACCOUNT: &str = "passphrase";

// Wrap a SecAccessControlRef as a CFType so we can put it in a CFDictionary.
struct AccessControl(SecAccessControlRef);
impl Drop for AccessControl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0 as CFTypeRef) };
        }
    }
}
impl AccessControl {
    fn as_cftype(&self) -> CFType {
        unsafe { CFType::wrap_under_get_rule(self.0 as CFTypeRef) }
    }
}

fn make_access_control(allow_biometry_change: bool) -> Result<AccessControl, AppError> {
    let mut err_ptr: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
    let flags = if allow_biometry_change {
        kSecAccessControlUserPresence
    } else {
        kSecAccessControlBiometryCurrentSet | kSecAccessControlOr
    };
    let ac = unsafe {
        SecAccessControlCreateWithFlags(
            ptr::null(),
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            flags,
            &mut err_ptr,
        )
    };
    if ac.is_null() {
        if !err_ptr.is_null() {
            unsafe { CFRelease(err_ptr as CFTypeRef) };
        }
        return Err(AppError::Http("SecAccessControlCreateWithFlags failed".into()));
    }
    Ok(AccessControl(ac))
}

fn delete_existing() {
    let service = CFString::new(SERVICE);
    let account = CFString::new(ACCOUNT);
    let class = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let mut q = CFMutableDictionary::new();
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecClass) }.as_CFType(),
        &class.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecAttrService) }.as_CFType(),
        &service.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) }.as_CFType(),
        &account.as_CFType(),
    );
    unsafe {
        SecItemDelete(q.as_concrete_TypeRef() as _);
    }
}

#[tauri::command]
#[specta::specta]
pub fn keychain_save(passphrase: String) -> Result<(), AppError> {
    save_internal(&passphrase, None)
}

#[tauri::command]
#[specta::specta]
pub fn keychain_save_with_biometry(passphrase: String) -> Result<(), AppError> {
    let ac = make_access_control(true)?;
    save_internal(&passphrase, Some(&ac))
}

fn save_internal(passphrase: &str, ac: Option<&AccessControl>) -> Result<(), AppError> {
    delete_existing();

    let service = CFString::new(SERVICE);
    let account = CFString::new(ACCOUNT);
    let data = CFData::from_buffer(passphrase.as_bytes());
    let class = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };

    let mut q = CFMutableDictionary::new();
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecClass) }.as_CFType(),
        &class.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecAttrService) }.as_CFType(),
        &service.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) }.as_CFType(),
        &account.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecValueData) }.as_CFType(),
        &data.as_CFType(),
    );
    if let Some(ac) = ac {
        q.add(
            &unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) }.as_CFType(),
            &ac.as_cftype(),
        );
    }

    let status = unsafe { SecItemAdd(q.as_concrete_TypeRef() as _, ptr::null_mut()) };
    if status != errSecSuccess {
        return Err(AppError::Http(format!("SecItemAdd status {}", status)));
    }
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn keychain_load() -> Result<Option<String>, AppError> {
    let service = CFString::new(SERVICE);
    let account = CFString::new(ACCOUNT);
    let class = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };

    let mut q = CFMutableDictionary::new();
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecClass) }.as_CFType(),
        &class.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecAttrService) }.as_CFType(),
        &service.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) }.as_CFType(),
        &account.as_CFType(),
    );
    q.add(
        &unsafe { CFString::wrap_under_get_rule(kSecReturnData) }.as_CFType(),
        &CFBoolean::true_value().as_CFType(),
    );

    let mut result: CFTypeRef = ptr::null();
    let status =
        unsafe { SecItemCopyMatching(q.as_concrete_TypeRef() as _, &mut result) };
    if status == errSecItemNotFound {
        return Ok(None);
    }
    if status != errSecSuccess {
        return Err(AppError::Http(format!("SecItemCopyMatching status {}", status)));
    }
    if result.is_null() {
        return Ok(None);
    }
    let type_id = unsafe { CFGetTypeID(result) };
    if type_id != unsafe { CFDataGetTypeID() } {
        unsafe { CFRelease(result) };
        return Err(AppError::Http("unexpected keychain item type".into()));
    }
    let data_ref = result as CFDataRef;
    let len = unsafe { CFDataGetLength(data_ref) } as usize;
    let bytes_ptr = unsafe { CFDataGetBytePtr(data_ref) };
    let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, len) }.to_vec();
    unsafe { CFRelease(result) };
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

#[tauri::command]
#[specta::specta]
pub fn keychain_delete() -> Result<(), AppError> {
    delete_existing();
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn biometry_available() -> Result<bool, AppError> {
    // V1: assume yes on macOS, no elsewhere. macOS itself falls back to
    // device password if biometry is unenrolled, so kSecAccessControlUserPresence
    // still works on Macs without Touch ID — they'll just see a password prompt.
    Ok(cfg!(target_os = "macos"))
}
