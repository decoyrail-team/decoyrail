//! macOS login-keychain storage for the vault key.
//!
//! One generic-password item per Decoyrail home: service is fixed
//! ([`SERVICE`]), account is the canonicalized home path (the home-binding
//! attribute). Lookup is by (service, account), so an item bound to home A is
//! simply not found when running against home B.
//!
//! The item is created in-process via `SecKeychainAddGenericPassword`, whose
//! default ACL trusts exactly the creating application: this binary reads the
//! key silently, and any other process (including `security
//! find-generic-password -w`) triggers the macOS consent prompt or is denied.
//! An unsigned dev build re-prompts after every rebuild because the trusted
//! application is then identified by the binary itself rather than a stable
//! code signature; that's why the file backend stays the default for
//! development.
//!
//! `fetch` distinguishes "no item" (`Ok(None)`, lets backend selection route
//! to the file key) from "item exists but the read was denied or failed"
//! (`Err`, which callers must treat as fatal, never as a cue to mint a fresh
//! file key).

/// Keychain service name for the vault-key item.
pub const SERVICE: &str = "dev.decoyrail.vault-key";

#[cfg(target_os = "macos")]
mod imp {
    use super::SERVICE;
    use anyhow::{anyhow, Result};
    use std::os::raw::c_void;

    type OsStatus = i32;
    type SecKeychainItemRef = *mut c_void;

    const ERR_SEC_ITEM_NOT_FOUND: OsStatus = -25300;
    const ERR_SEC_DUPLICATE_ITEM: OsStatus = -25299;
    const ERR_SEC_AUTH_FAILED: OsStatus = -25293;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: OsStatus = -25308;
    const ERR_SEC_USER_CANCELED: OsStatus = -128;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecKeychainAddGenericPassword(
            keychain: *mut c_void,
            service_name_length: u32,
            service_name: *const u8,
            account_name_length: u32,
            account_name: *const u8,
            password_length: u32,
            password_data: *const u8,
            item_ref: *mut SecKeychainItemRef,
        ) -> OsStatus;
        fn SecKeychainFindGenericPassword(
            keychain_or_array: *const c_void,
            service_name_length: u32,
            service_name: *const u8,
            account_name_length: u32,
            account_name: *const u8,
            password_length: *mut u32,
            password_data: *mut *mut c_void,
            item_ref: *mut SecKeychainItemRef,
        ) -> OsStatus;
        fn SecKeychainItemFreeContent(attr_list: *mut c_void, data: *mut c_void) -> OsStatus;
        fn SecKeychainItemDelete(item_ref: SecKeychainItemRef) -> OsStatus;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: *const c_void);
    }

    fn describe(status: OsStatus) -> String {
        match status {
            ERR_SEC_USER_CANCELED => "the user denied the keychain prompt".into(),
            ERR_SEC_AUTH_FAILED => "keychain authorization failed".into(),
            ERR_SEC_INTERACTION_NOT_ALLOWED => {
                "keychain interaction not allowed (no UI session?)".into()
            }
            s => format!("keychain error (OSStatus {s})"),
        }
    }

    /// Store `key` as the vault-key item bound to `home`. Errors if an item
    /// for this home already exists (callers decide idempotency above this).
    pub fn store(home: &str, key: &[u8; 32]) -> Result<()> {
        let status = unsafe {
            SecKeychainAddGenericPassword(
                std::ptr::null_mut(),
                SERVICE.len() as u32,
                SERVICE.as_ptr(),
                home.len() as u32,
                home.as_ptr(),
                key.len() as u32,
                key.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        match status {
            0 => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => Err(anyhow!(
                "a keychain item for this home already exists (service {SERVICE})"
            )),
            s => Err(anyhow!("storing the vault key failed: {}", describe(s))),
        }
    }

    /// Read the key bound to `home`. `Ok(None)` means no item exists; any
    /// other failure (denied prompt, wrong size, OS error) is an `Err` the
    /// caller must treat as fatal.
    pub fn fetch(home: &str) -> Result<Option<[u8; 32]>> {
        let mut len: u32 = 0;
        let mut data: *mut c_void = std::ptr::null_mut();
        let status = unsafe {
            SecKeychainFindGenericPassword(
                std::ptr::null(),
                SERVICE.len() as u32,
                SERVICE.as_ptr(),
                home.len() as u32,
                home.as_ptr(),
                &mut len,
                &mut data,
                std::ptr::null_mut(),
            )
        };
        match status {
            0 => {
                let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, len as usize) };
                let result = if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(bytes);
                    Ok(Some(key))
                } else {
                    Err(anyhow!(
                        "keychain vault key is corrupt (expected 32 bytes, got {})",
                        bytes.len()
                    ))
                };
                // Zero the OS-owned copy before handing the buffer back.
                unsafe {
                    std::ptr::write_bytes(data as *mut u8, 0, len as usize);
                    SecKeychainItemFreeContent(std::ptr::null_mut(), data);
                }
                result
            }
            ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            s => Err(anyhow!("reading the vault key failed: {}", describe(s))),
        }
    }

    /// Whether an item bound to `home` exists. Attribute-only lookup (no
    /// password data requested), so it never triggers a consent prompt.
    pub fn exists(home: &str) -> Result<bool> {
        let mut item: SecKeychainItemRef = std::ptr::null_mut();
        let status = unsafe {
            SecKeychainFindGenericPassword(
                std::ptr::null(),
                SERVICE.len() as u32,
                SERVICE.as_ptr(),
                home.len() as u32,
                home.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut item,
            )
        };
        match status {
            0 => {
                unsafe { CFRelease(item) };
                Ok(true)
            }
            ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            s => Err(anyhow!("keychain lookup failed: {}", describe(s))),
        }
    }

    /// Delete the item bound to `home`. Returns false if none existed.
    pub fn delete(home: &str) -> Result<bool> {
        let mut item: SecKeychainItemRef = std::ptr::null_mut();
        let status = unsafe {
            SecKeychainFindGenericPassword(
                std::ptr::null(),
                SERVICE.len() as u32,
                SERVICE.as_ptr(),
                home.len() as u32,
                home.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut item,
            )
        };
        match status {
            0 => {
                let deleted = unsafe { SecKeychainItemDelete(item) };
                unsafe { CFRelease(item) };
                if deleted == 0 {
                    Ok(true)
                } else {
                    Err(anyhow!(
                        "deleting the keychain item failed: {}",
                        describe(deleted)
                    ))
                }
            }
            ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            s => Err(anyhow!("keychain lookup failed: {}", describe(s))),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use anyhow::{anyhow, Result};

    fn unsupported<T>() -> Result<T> {
        Err(anyhow!("the keychain backend is only supported on macOS"))
    }

    pub fn store(_home: &str, _key: &[u8; 32]) -> Result<()> {
        unsupported()
    }
    pub fn fetch(_home: &str) -> Result<Option<[u8; 32]>> {
        unsupported()
    }
    pub fn exists(_home: &str) -> Result<bool> {
        unsupported()
    }
    pub fn delete(_home: &str) -> Result<bool> {
        unsupported()
    }
}

pub use imp::{delete, exists, fetch, store};

/// Live round-trip against the real login keychain, bound to a throwaway
/// fake home so it can't collide with a genuine Decoyrail binding. Ignored by
/// default: it touches user state outside the repo (an item is created and
/// removed) and would be meaningless in CI. Run it by hand on macOS with
/// `cargo test -p decoyrail --lib keyring -- --ignored`.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[test]
    #[ignore = "touches the real login keychain; run manually"]
    fn live_keychain_roundtrip() {
        let home = "/tmp/decoyrail-keyring-live-test";
        // Clean up any residue from an earlier interrupted run.
        let _ = super::delete(home);

        assert!(!super::exists(home).unwrap());
        assert_eq!(super::fetch(home).unwrap(), None);

        let key = [7u8; 32];
        super::store(home, &key).unwrap();
        assert!(super::exists(home).unwrap());
        assert_eq!(super::fetch(home).unwrap(), Some(key));

        // A second store for the same home must collide, not duplicate.
        assert!(super::store(home, &key).is_err());

        assert!(super::delete(home).unwrap());
        assert!(!super::exists(home).unwrap());
        assert!(!super::delete(home).unwrap());
    }
}
