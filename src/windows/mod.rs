mod context;
mod win;

use super::{Error, Revocation, VerifyPolicy};
use context::close_data;
use win::*;

#[derive(Debug, Clone)]
pub(crate) struct Verifier {
    policy: VerifyPolicy,
}
pub(crate) use context::Context;

/// What `WinVerifyTrust` should verify: a file's embedded signature or its catalog entry.
enum TrustSubject {
    File(*mut WINTRUST_FILE_INFO),
    Catalog(*mut WINTRUST_CATALOG_INFO),
}

struct CleanupContext {
    h_file: HANDLE,
    h_cat_admin: isize,
    h_cat_info: isize,
}

impl CleanupContext {
    pub fn new(h_file: HANDLE) -> Self {
        CleanupContext {
            h_file,
            h_cat_admin: 0,
            h_cat_info: 0,
        }
    }
}

impl Drop for CleanupContext {
    fn drop(&mut self) {
        if !self.h_file.is_null() {
            unsafe { CloseHandle(self.h_file) };
        }

        if self.h_cat_info != 0 {
            unsafe { CryptCATAdminReleaseCatalogContext(self.h_cat_admin, self.h_cat_info, 0) };
        }

        if self.h_cat_admin != 0 {
            unsafe { CryptCATAdminReleaseContext(self.h_cat_admin, 0) };
        }
    }
}

impl Verifier {
    // Every policy is valid on Windows; this is fallible only to match the macOS backend.
    pub fn new(policy: VerifyPolicy) -> Result<Self, Error> {
        Ok(Self { policy })
    }

    pub fn policy(&self) -> &VerifyPolicy {
        &self.policy
    }

    pub fn verify_file(&self, path: &std::path::Path) -> Result<Context, Error> {
        let path = wide_path(path)?;

        let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = path.as_ptr();

        match unsafe { self.verify_internal(TrustSubject::File(&mut file_info)) } {
            Ok(context) => Ok(context),
            Err(TRUST_E_NOSIGNATURE) => self.verify_catalog_signed(&path),
            Err(err) => Err(Error::OsError(err)),
        }
    }

    // Extract the path of a pid, then verify that file
    pub fn verify_pid(&self, pid: u32) -> Result<Context, Error> {
        let path = get_process_path(pid)?;
        self.verify_file(path.as_ref())
    }

    /// Looks the file at `path` (null terminated) up in the system catalogs, first by SHA256
    /// hash and then by SHA1 hash (which older and some third-party catalogs still use).
    fn verify_catalog_signed(&self, path: &[u16]) -> Result<Context, Error> {
        for algorithm in [BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA1_ALGORITHM] {
            match unsafe { self.verify_catalog_signed_with(path, algorithm) } {
                Err(Error::Unsigned) => continue,
                result => return result,
            }
        }

        Err(Error::Unsigned)
    }

    /// Verifies the file at `path` (null terminated) against each catalog containing its
    /// `algorithm` hash, returning `Error::Unsigned` if no catalog contains it.
    unsafe fn verify_catalog_signed_with(&self, path: &[u16], algorithm: PCWSTR) -> Result<Context, Error> {
        let h_file = unsafe { CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        ) };

        if h_file == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() } as i32;
            return Err(Error::OsError(err));
        }

        let mut ctx = CleanupContext::new(h_file);

        let mut h_cat_admin: isize = 0;
        let result = unsafe { CryptCATAdminAcquireContext2(
            &mut h_cat_admin,
            std::ptr::null(),
            algorithm,
            std::ptr::null(),
            0,
        ) };
        if result == 0 {
            let err = unsafe { GetLastError() } as i32;
            return Err(Error::OsError(err));
        }

        ctx.h_cat_admin = h_cat_admin;

        // Large enough for any supported digest; the call sets hash_size to the actual length.
        let mut hash_buffer = [0u8; 64];
        let mut hash_size = hash_buffer.len() as u32;
        let result = unsafe { CryptCATAdminCalcHashFromFileHandle2(
            h_cat_admin,
            h_file,
            &mut hash_size,
            hash_buffer.as_mut_ptr(),
            0,
        ) };
        if result == 0 {
            let err = unsafe { GetLastError() } as i32;
            return Err(Error::OsError(err));
        }
        let hash_buffer = &hash_buffer[..hash_size as usize];

        let mut hash: Vec<u16> = crate::to_hex(hash_buffer).encode_utf16().collect();
        hash.push(0); // Make sure hash is null terminated

        // A hash may be listed in several catalogs; accept the file if any of them verifies.
        let mut last_err = None;
        loop {
            // Per the docs, each call is passed the previous call's return value to continue the
            // enumeration, and only the context from the final call is released by the caller.
            let prev = if ctx.h_cat_info == 0 {
                std::ptr::null_mut()
            } else {
                &mut ctx.h_cat_info as *mut isize
            };
            let h_cat_info = unsafe { CryptCATAdminEnumCatalogFromHash(
                h_cat_admin,
                hash_buffer.as_ptr(),
                hash_size,
                0,
                prev,
            ) };
            ctx.h_cat_info = h_cat_info;
            if h_cat_info == 0 {
                break;
            }

            let mut ci: CATALOG_INFO = unsafe { std::mem::zeroed() };
            ci.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;

            if unsafe { CryptCATCatalogInfoFromContext(h_cat_info, &mut ci, 0) } == 0 {
                last_err = Some(unsafe { GetLastError() } as i32);
                continue;
            }

            let mut wci: WINTRUST_CATALOG_INFO = unsafe { std::mem::zeroed() };
            wci.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
            wci.pcwszCatalogFilePath = ci.wszCatalogFile.as_ptr();
            wci.pcwszMemberFilePath = path.as_ptr();
            wci.pcwszMemberTag = hash.as_ptr();

            match unsafe { self.verify_internal(TrustSubject::Catalog(&mut wci)) } {
                Ok(context) => return Ok(context),
                Err(err) => last_err = Some(err),
            }
        }

        match last_err {
            Some(err) => Err(Error::OsError(err)),
            None => Err(Error::Unsigned),
        }
    }

    /// Runs `WinVerifyTrust`, returning its HRESULT status on failure.
    unsafe fn verify_internal(&self, subject: TrustSubject) -> Result<Context, i32> {
        // Initialize the WINTRUST_DATA structure
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwUIContext = WTD_UICONTEXT_EXECUTE;

        let (revocation_checks, prov_flags) = trust_flags(&self.policy);
        data.fdwRevocationChecks = revocation_checks;

        match subject {
            TrustSubject::File(fi) => {
                data.dwUnionChoice = WTD_CHOICE_FILE;
                data.Anonymous.pFile = fi;
                data.dwProvFlags = prov_flags | WTD_NO_IE4_CHAIN_FLAG;
            }
            TrustSubject::Catalog(ci) => {
                data.dwUnionChoice = WTD_CHOICE_CATALOG;
                data.Anonymous.pCatalog = ci;
                data.dwProvFlags = prov_flags | WTD_USE_DEFAULT_OSVER_CHECK;
            }
        }

        let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // Verify that the signature is actually valid. The status is the function's return
        // value; GetLastError isn't reliable here.
        let status = unsafe { WinVerifyTrust(
            INVALID_HANDLE_VALUE as _,
            &mut guid,
            &mut data as *mut _ as _,
        ) };

        if status != 0 {
            close_data(data.hWVTStateData);
            return Err(status);
        }

        Context::new(data.hWVTStateData)
    }
}

/// Translates a policy into `WINTRUST_DATA`'s `fdwRevocationChecks` and the `dwProvFlags`
/// shared by file and catalog verification.
fn trust_flags(policy: &VerifyPolicy) -> (u32, u32) {
    let mut prov_flags = WTD_DISABLE_MD2_MD4;

    let revocation_checks = match policy.revocation {
        Revocation::None => WTD_REVOKE_NONE,
        Revocation::EndCertificate => {
            prov_flags |= WTD_REVOCATION_CHECK_END_CERT;
            WTD_REVOKE_WHOLECHAIN
        }
        Revocation::Chain => {
            prov_flags |= WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
            WTD_REVOKE_WHOLECHAIN
        }
    };

    // By default only go to the network when revocation checking needs it.
    if !policy.allow_network.unwrap_or(policy.revocation != Revocation::None) {
        prov_flags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
    }

    if policy.strict_expiration {
        prov_flags |= WTD_LIFETIME_SIGNING_FLAG;
    }

    (revocation_checks, prov_flags)
}

/// Encodes `path` as a null terminated UTF-16 string for the Win32 APIs.
fn wide_path(path: &std::path::Path) -> Result<Vec<u16>, Error> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();

    // An interior null would silently truncate the path and verify a different file.
    if wide.contains(&0) {
        return Err(Error::InvalidPath);
    }
    wide.push(0);

    Ok(wide)
}

/// Attempts to get the full system path for a given process id
fn get_process_path(proc_id: u32) -> Result<std::ffi::OsString, Error> {
    use std::os::windows::ffi::OsStringExt;

    // Longest path Windows supports (in UTF-16 units), with the \\?\ prefix.
    const MAX_LEN: usize = 32 * 1024;

    unsafe {
        let proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc_id);
        if proc_handle.is_null() {
            return Err(Error::OsError(GetLastError() as i32));
        }

        let mut buf = vec![0u16; 1024];
        let result = loop {
            let mut path_len = buf.len() as u32;

            if QueryFullProcessImageNameW(proc_handle, 0, buf.as_mut_ptr(), &mut path_len) != 0 {
                break Ok(std::ffi::OsString::from_wide(&buf[..path_len as usize]));
            }

            let err = GetLastError();
            if err != ERROR_INSUFFICIENT_BUFFER || buf.len() >= MAX_LEN {
                break Err(Error::OsError(err as i32));
            }
            buf.resize(buf.len() * 2, 0);
        };

        CloseHandle(proc_handle);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_flags() {
        // Exactly what verification used before policies existed.
        assert_eq!(
            trust_flags(&VerifyPolicy::default()),
            (WTD_REVOKE_NONE, WTD_DISABLE_MD2_MD4 | WTD_CACHE_ONLY_URL_RETRIEVAL)
        );
    }

    #[test]
    fn test_revocation_flags() {
        // Revocation implies network access unless explicitly forbidden.
        assert_eq!(
            trust_flags(&VerifyPolicy::new().revocation(Revocation::EndCertificate)),
            (WTD_REVOKE_WHOLECHAIN, WTD_DISABLE_MD2_MD4 | WTD_REVOCATION_CHECK_END_CERT)
        );
        assert_eq!(
            trust_flags(&VerifyPolicy::new().revocation(Revocation::Chain)),
            (WTD_REVOKE_WHOLECHAIN, WTD_DISABLE_MD2_MD4 | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT)
        );
    }

    #[test]
    fn test_network_flags() {
        let offline_revocation = VerifyPolicy::new().revocation(Revocation::Chain).allow_network(false);
        let online = VerifyPolicy::new().allow_network(true);

        assert_ne!(trust_flags(&offline_revocation).1 & WTD_CACHE_ONLY_URL_RETRIEVAL, 0);
        assert_eq!(trust_flags(&online).1 & WTD_CACHE_ONLY_URL_RETRIEVAL, 0);
    }

    #[test]
    fn test_expiration_flags() {
        let policy = VerifyPolicy::new().strict_expiration(true);

        assert_ne!(trust_flags(&policy).1 & WTD_LIFETIME_SIGNING_FLAG, 0);
    }
}
