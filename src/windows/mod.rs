mod context;
mod win;

use std::sync::{Arc, Mutex, PoisonError};

use super::{Error, Revocation, VerifyPolicy};
use context::close_data;
use win::*;

#[derive(Debug, Clone)]
pub(crate) struct Verifier {
    policy: VerifyPolicy,
    catalog_admins: Arc<CatalogAdmins>,
}
pub(crate) use context::Context;

/// What `WinVerifyTrust` should verify: a file's embedded signature or its catalog entry.
enum TrustSubject {
    File(*mut WINTRUST_FILE_INFO),
    Catalog(*mut WINTRUST_CATALOG_INFO),
}

/// The hash a file is looked up by in the catalog database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatalogHash {
    Sha256,
    Sha1,
}

impl CatalogHash {
    fn algorithm(self) -> PCWSTR {
        match self {
            CatalogHash::Sha256 => BCRYPT_SHA256_ALGORITHM,
            CatalogHash::Sha1 => BCRYPT_SHA1_ALGORITHM,
        }
    }
}

/// Catalog administrator contexts (`HCATADMIN`) kept for the verifier's lifetime.
///
/// Acquiring a context is cheap, but a context that has already looked files up has the
/// catalog database warm, which makes the next lookup several times faster. A context is used
/// by one verification at a time, so a verifier shared between threads holds up to one per
/// concurrent verification.
#[derive(Debug, Default)]
struct CatalogAdmins {
    sha256: Mutex<Vec<isize>>,
    sha1: Mutex<Vec<isize>>,
}

impl CatalogAdmins {
    fn pool(&self, hash: CatalogHash) -> &Mutex<Vec<isize>> {
        match hash {
            CatalogHash::Sha256 => &self.sha256,
            CatalogHash::Sha1 => &self.sha1,
        }
    }

    /// Takes an idle context from the pool, or acquires a new one.
    fn acquire(self: &Arc<Self>, hash: CatalogHash) -> Result<CatalogAdmin, Error> {
        let pooled = self.pool(hash).lock().unwrap_or_else(PoisonError::into_inner).pop();

        let handle = match pooled {
            Some(handle) => handle,
            None => {
                let mut handle: isize = 0;
                let result = unsafe { CryptCATAdminAcquireContext2(
                    &mut handle,
                    std::ptr::null(),
                    hash.algorithm(),
                    std::ptr::null(),
                    0,
                ) };
                if result == 0 {
                    return Err(Error::OsError(last_error()));
                }
                handle
            }
        };

        Ok(CatalogAdmin { admins: Arc::clone(self), hash, handle })
    }
}

impl Drop for CatalogAdmins {
    fn drop(&mut self) {
        for pool in [&self.sha256, &self.sha1] {
            for handle in pool.lock().unwrap_or_else(PoisonError::into_inner).drain(..) {
                unsafe { CryptCATAdminReleaseContext(handle, 0) };
            }
        }
    }
}

/// A catalog administrator context borrowed from a [`CatalogAdmins`] pool, returned on drop.
///
/// It keeps the pool alive, so a context referenced by open WinTrust state data is neither
/// released nor used by another verification until that state is closed.
pub(super) struct CatalogAdmin {
    admins: Arc<CatalogAdmins>,
    hash: CatalogHash,
    handle: isize,
}

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        self.admins.pool(self.hash).lock().unwrap_or_else(PoisonError::into_inner).push(self.handle);
    }
}

/// The file being verified, open for reading; closed on drop.
pub(super) struct FileHandle(std::fs::File);

impl FileHandle {
    /// Opens the file at `path` for reading, returning the HRESULT of a failure.
    fn open(path: &std::path::Path) -> Result<Self, i32> {
        use std::os::windows::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .read(true)
            // Allow others to read, rename or delete the file meanwhile, but not to write it
            // while it is being hashed.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .open(path)
            .map(FileHandle)
            .map_err(|err| hresult_from_win32(err.raw_os_error().unwrap_or(ERROR_OPEN_FAILED as i32) as u32))
    }

    fn handle(&self) -> HANDLE {
        use std::os::windows::io::AsRawHandle;

        self.0.as_raw_handle() as HANDLE
    }

    /// Whether the file starts with the `MZ` magic of a PE image. Leaves the file position at
    /// the start of the file.
    fn is_pe(&self) -> bool {
        use std::io::Read;

        let mut magic = [0u8; 2];
        let is_pe = (&self.0).read_exact(&mut magic).is_ok() && &magic == b"MZ";
        self.rewind();

        is_pe
    }

    fn rewind(&self) {
        use std::io::Seek;

        let _ = (&self.0).seek(std::io::SeekFrom::Start(0));
    }
}

/// A catalog context from `CryptCATAdminEnumCatalogFromHash`, released on drop.
struct CatalogContext<'a> {
    admin: &'a CatalogAdmin,
    handle: isize,
}

impl Drop for CatalogContext<'_> {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe { CryptCATAdminReleaseCatalogContext(self.admin.handle, self.handle, 0) };
        }
    }
}

/// Everything a catalog verification's WinTrust state data may still refer to, kept alive by
/// the [`Context`] until that state is closed.
pub(super) struct CatalogResources {
    #[allow(dead_code)]
    file: FileHandle,
    #[allow(dead_code)]
    admin: CatalogAdmin,
}

impl Verifier {
    // Every policy is valid on Windows; this is fallible only to match the macOS backend.
    pub fn new(policy: VerifyPolicy) -> Result<Self, Error> {
        Ok(Self { policy, catalog_admins: Arc::default() })
    }

    pub fn policy(&self) -> &VerifyPolicy {
        &self.policy
    }

    pub fn verify_file(&self, path: &std::path::Path) -> Result<Context, Error> {
        let wide = wide_path(path)?;

        let file = match FileHandle::open(path) {
            Ok(file) => file,
            // Let WinVerifyTrust report the error it would have given for this file (e.g.
            // CRYPT_E_FILE_ERROR for a missing one), falling back to the open error.
            Err(open_err) => {
                return match unsafe { self.verify_embedded(&wide) } {
                    Ok(context) => Ok(context),
                    Err(TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN) => Err(Error::OsError(open_err)),
                    Err(err) => Err(Error::OsError(err)),
                };
            }
        };

        if file.is_pe() {
            // A PE file usually carries its signature, and finding out that it doesn't is
            // cheap, so look there first.
            match unsafe { self.verify_embedded(&wide) } {
                Ok(context) => return Ok(context),
                // No embedded signature: it may still be signed through a system catalog.
                Err(TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN) => {}
                Err(err) => return Err(Error::OsError(err)),
            }

            return self.verify_catalog_signed(path, &wide, file, true);
        }

        // For any other file type, finding out whether it can carry an embedded signature at
        // all takes WinTrust several milliseconds, while a catalog lookup takes about one, and
        // most signed non-PE files (.inf, .xml, .mui, ...) are catalog signed. So the catalog
        // comes first, and the embedded signature is only looked for when no catalog lists
        // the file.
        let catalog_err = match self.verify_catalog_signed(path, &wide, file, false) {
            Ok(context) => return Ok(context),
            Err(Error::Unsigned) => None,
            Err(err) => Some(err),
        };

        match unsafe { self.verify_embedded(&wide) } {
            Ok(context) => return Ok(context),
            Err(TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN) => {}
            Err(err) => return Err(Error::OsError(err)),
        }

        if let Some(err) = catalog_err {
            return Err(err);
        }

        // The SHA-256 lookup already missed, so only the SHA-1 one is left.
        if self.policy.sha1_catalogs {
            let file = FileHandle::open(path).map_err(Error::OsError)?;
            self.verify_catalog_signed_with(&wide, file, CatalogHash::Sha1)
        } else {
            Err(Error::Unsigned)
        }
    }

    // Extract the path of a pid, then verify that file
    pub fn verify_pid(&self, pid: u32) -> Result<Context, Error> {
        let path = get_process_path(pid)?;
        self.verify_file(path.as_ref())
    }

    /// Verifies the embedded signature of the file at `path` (null terminated).
    unsafe fn verify_embedded(&self, path: &[u16]) -> Result<Context, i32> {
        let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = path.as_ptr();

        unsafe { self.verify_internal(TrustSubject::File(&mut file_info)) }
    }

    /// Looks `file` (opened from `path`, also given null terminated as `wide`) up in the
    /// system catalogs by SHA-256 hash and, if `with_sha1` and the policy allow it, by SHA-1
    /// hash.
    fn verify_catalog_signed(&self, path: &std::path::Path, wide: &[u16], file: FileHandle, with_sha1: bool) -> Result<Context, Error> {
        match self.verify_catalog_signed_with(wide, file, CatalogHash::Sha256) {
            Err(Error::Unsigned) if with_sha1 && self.policy.sha1_catalogs => {}
            result => return result,
        }

        // The SHA-256 lookup took the file handle with it (it may live on in a result).
        let file = FileHandle::open(path).map_err(Error::OsError)?;
        self.verify_catalog_signed_with(wide, file, CatalogHash::Sha1)
    }

    /// Verifies `file` (opened from `path`, null terminated) against each catalog containing
    /// its `hash`, returning `Error::Unsigned` if no catalog contains it.
    fn verify_catalog_signed_with(&self, path: &[u16], file: FileHandle, hash: CatalogHash) -> Result<Context, Error> {
        let admin = self.catalog_admins.acquire(hash)?;

        // Large enough for any supported digest; the call sets hash_size to the actual length.
        let mut hash_buffer = [0u8; 64];
        let mut hash_size = hash_buffer.len() as u32;
        file.rewind();
        let result = unsafe { CryptCATAdminCalcHashFromFileHandle2(
            admin.handle,
            file.handle(),
            &mut hash_size,
            hash_buffer.as_mut_ptr(),
            0,
        ) };
        if result == 0 {
            return Err(Error::OsError(last_error()));
        }
        let hash_buffer = &mut hash_buffer[..hash_size as usize];

        let mut tag: Vec<u16> = crate::to_hex(hash_buffer).encode_utf16().collect();
        tag.push(0); // Make sure the member tag is null terminated

        // A hash may be listed in several catalogs; accept the file if any of them verifies.
        let mut catalog = CatalogContext { admin: &admin, handle: 0 };
        let mut last_err = None;
        loop {
            // Per the docs, each call is passed the previous call's return value to continue the
            // enumeration, and only the context from the final call is released by the caller.
            let prev = if catalog.handle == 0 {
                std::ptr::null_mut()
            } else {
                &mut catalog.handle as *mut isize
            };
            catalog.handle = unsafe { CryptCATAdminEnumCatalogFromHash(
                admin.handle,
                hash_buffer.as_ptr(),
                hash_size,
                0,
                prev,
            ) };
            if catalog.handle == 0 {
                break;
            }

            let mut ci: CATALOG_INFO = unsafe { std::mem::zeroed() };
            ci.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;

            if unsafe { CryptCATCatalogInfoFromContext(catalog.handle, &mut ci, 0) } == 0 {
                last_err = Some(last_error());
                continue;
            }

            let mut wci: WINTRUST_CATALOG_INFO = unsafe { std::mem::zeroed() };
            wci.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
            wci.pcwszCatalogFilePath = ci.wszCatalogFile.as_ptr();
            wci.pcwszMemberFilePath = path.as_ptr();
            wci.pcwszMemberTag = tag.as_ptr();
            // Hand over the open file and its hash so WinTrust doesn't reopen and rehash it.
            // The hash is only accepted together with the context that computed it.
            wci.hMemberFile = file.handle();
            wci.pbCalculatedFileHash = hash_buffer.as_mut_ptr();
            wci.cbCalculatedFileHash = hash_size;
            wci.hCatAdmin = admin.handle;

            file.rewind();
            match unsafe { self.verify_internal(TrustSubject::Catalog(&mut wci)) } {
                Ok(context) => {
                    drop(catalog);
                    return Ok(context.with_catalog_resources(CatalogResources { file, admin }));
                }
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

/// The calling thread's last error, as an HRESULT.
fn last_error() -> i32 {
    hresult_from_win32(unsafe { GetLastError() })
}

/// `HRESULT_FROM_WIN32`: maps a Win32 error code into the `0x8007xxxx` HRESULT range, so
/// `Error::OsError` holds an HRESULT on every path. Values already in HRESULT form (some
/// crypto APIs set those as the last error) and zero are returned unchanged.
fn hresult_from_win32(code: u32) -> i32 {
    if code as i32 <= 0 {
        code as i32
    } else {
        ((code & 0xFFFF) | 0x8007_0000) as i32
    }
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
            return Err(Error::OsError(last_error()));
        }

        let mut buf = vec![0u16; 1024];
        let result = loop {
            let mut path_len = buf.len() as u32;

            if QueryFullProcessImageNameW(proc_handle, 0, buf.as_mut_ptr(), &mut path_len) != 0 {
                break Ok(std::ffi::OsString::from_wide(&buf[..path_len as usize]));
            }

            let err = GetLastError();
            if err != ERROR_INSUFFICIENT_BUFFER || buf.len() >= MAX_LEN {
                break Err(Error::OsError(hresult_from_win32(err)));
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
    fn test_hresult_from_win32() {
        assert_eq!(hresult_from_win32(0), 0);
        // ERROR_FILE_NOT_FOUND
        assert_eq!(hresult_from_win32(2), 0x8007_0002_u32 as i32);
        // Already an HRESULT (TRUST_E_NOSIGNATURE): unchanged.
        assert_eq!(hresult_from_win32(TRUST_E_NOSIGNATURE as u32), TRUST_E_NOSIGNATURE);
    }

    #[test]
    fn test_expiration_flags() {
        let policy = VerifyPolicy::new().strict_expiration(true);

        assert_ne!(trust_flags(&policy).1 & WTD_LIFETIME_SIGNING_FLAG, 0);
    }

    #[test]
    fn test_catalog_admin_pool_reuses_contexts() {
        let admins: Arc<CatalogAdmins> = Arc::default();
        let pool_len = |hash| admins.pool(hash).lock().unwrap().len();

        // Nothing is acquired until it is needed, and a returned context is kept for reuse.
        assert_eq!(pool_len(CatalogHash::Sha256), 0);
        let first = admins.acquire(CatalogHash::Sha256).unwrap();
        let handle = first.handle;
        assert_ne!(handle, 0);
        drop(first);
        assert_eq!(pool_len(CatalogHash::Sha256), 1);

        let second = admins.acquire(CatalogHash::Sha256).unwrap();
        assert_eq!(second.handle, handle);
        assert_eq!(pool_len(CatalogHash::Sha256), 0);

        // A concurrent borrower gets its own context; both go back to the pool.
        let third = admins.acquire(CatalogHash::Sha256).unwrap();
        assert_ne!(third.handle, handle);
        drop((second, third));
        assert_eq!(pool_len(CatalogHash::Sha256), 2);

        // The pools are per algorithm.
        let sha1 = admins.acquire(CatalogHash::Sha1).unwrap();
        assert_eq!(pool_len(CatalogHash::Sha256), 2);
        drop(sha1);
        assert_eq!(pool_len(CatalogHash::Sha1), 1);
    }

    #[test]
    fn test_pe_detection() {
        let dir = std::env::temp_dir().join(format!("verifysign-pe-detection-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let check = |name: &str, content: &[u8]| {
            let path = dir.join(name);
            std::fs::write(&path, content).unwrap();
            FileHandle::open(&path).unwrap().is_pe()
        };

        assert!(check("exe.bin", b"MZ\x90\x00 rest of the image"));
        assert!(!check("text.txt", b"the MZ magic is not at the start"));
        assert!(!check("short.bin", b"M"));
        assert!(!check("empty.bin", b""));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
