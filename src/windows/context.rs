use super::win::*;
use crate::{Name, to_hex};

pub(crate) struct Context {
    data: HANDLE,
    leaf_cert_ptr: *const CERT_CONTEXT,
}

// SAFETY: the Context exclusively owns the WinTrust state data, which has no thread affinity
// and is closed exactly once, on drop. The leaf certificate belongs to that state and is only
// read through CryptoAPI certificate functions, which are safe to call concurrently.
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        close_data(self.data);
    }
}

pub(super) fn close_data(handle: HANDLE) {
    // Initialize the WINTRUST_DATA structure
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    data.dwUIContext = WTD_UICONTEXT_EXECUTE;
    data.hWVTStateData = handle;

    let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut guid,
            &mut data as *mut _ as *mut std::ffi::c_void,
        )
    };
}

impl Context {
    /// Takes ownership of `state_data`, closing it on drop (or on error).
    pub fn new(state_data: HANDLE) -> Result<Self, i32> {
        let mut ret = Context {
            data: state_data,
            leaf_cert_ptr: std::ptr::null(),
        };

        unsafe {
            let crypt_prov_data = match WTHelperProvDataFromStateData(state_data) {
                data if data.is_null() => return Err(TRUST_E_NO_SIGNER_CERT),
                data => data,
            };

            let crypt_prov_sgnr = match WTHelperGetProvSignerFromChain(crypt_prov_data, 0, 0, 0) {
                sgnr if sgnr.is_null() => return Err(TRUST_E_NO_SIGNER_CERT),
                sgnr => sgnr,
            };

            let crypt_prov_cert = match WTHelperGetProvCertFromChain(crypt_prov_sgnr, 0) {
                cert if cert.is_null() => return Err(TRUST_E_NO_SIGNER_CERT),
                cert => cert,
            };

            // Every other method dereferences the leaf certificate, so it must not be null.
            ret.leaf_cert_ptr = match (*crypt_prov_cert).pCert {
                cert if cert.is_null() || (*cert).pCertInfo.is_null() => {
                    return Err(TRUST_E_NO_SIGNER_CERT);
                }
                cert => cert,
            };
        }

        Ok(ret)
    }

    fn get_oid_name(&self, issuer: bool, oid: windows_sys::core::PCSTR) -> Option<String> {
        let flag = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };

        // Determine string size:
        let len = unsafe {
            CertGetNameStringW(
                self.leaf_cert_ptr,
                CERT_NAME_ATTR_TYPE,
                flag,
                oid as *mut std::ffi::c_void,
                std::ptr::null_mut(),
                0,
            )
        };

        if len <= 1 {
            return None;
        }

        let mut buf = vec![0; len as usize];

        let len = unsafe {
            CertGetNameStringW(
                self.leaf_cert_ptr,
                CERT_NAME_ATTR_TYPE,
                flag,
                oid as *mut std::ffi::c_void,
                buf.as_mut_ptr(),
                buf.len() as _,
            )
        };

        if len <= 1 {
            return None;
        }

        // Lossy so a malformed name (e.g. unpaired surrogates) can't cause a panic.
        Some(String::from_utf16_lossy(&buf[..len as usize - 1]))
    }

    pub fn serial(&self) -> Option<String> {
        // Both pointers are checked to be non-null in `new`.
        let serial_blob = unsafe { (*(*self.leaf_cert_ptr).pCertInfo).SerialNumber };

        // An empty blob may have a null data pointer, which from_raw_parts doesn't allow.
        if serial_blob.cbData == 0 || serial_blob.pbData.is_null() {
            return None;
        }

        let blob =
            unsafe { std::slice::from_raw_parts(serial_blob.pbData, serial_blob.cbData as usize) };

        // Windows stores the serial number little-endian; flip it to the usual big-endian form.
        let big_endian: Vec<u8> = blob.iter().rev().copied().collect();
        Some(to_hex(&big_endian))
    }

    pub fn subject_name(&self) -> Name {
        Name {
            common_name: self.get_oid_name(false, szOID_COMMON_NAME),
            organization: self.get_oid_name(false, szOID_ORGANIZATION_NAME),
            organization_unit: self.get_oid_name(false, szOID_ORGANIZATIONAL_UNIT_NAME),
            country: self.get_oid_name(false, szOID_COUNTRY_NAME),
        }
    }

    pub fn issuer_name(&self) -> Name {
        Name {
            common_name: self.get_oid_name(true, szOID_COMMON_NAME),
            organization: self.get_oid_name(true, szOID_ORGANIZATION_NAME),
            organization_unit: self.get_oid_name(true, szOID_ORGANIZATIONAL_UNIT_NAME),
            country: self.get_oid_name(true, szOID_COUNTRY_NAME),
        }
    }

    fn hash_property(&self, prop_id: u32) -> String {
        let mut len: u32 = 0;

        let ok = unsafe {
            CertGetCertificateContextProperty(
                self.leaf_cert_ptr,
                prop_id,
                std::ptr::null_mut(),
                &mut len,
            )
        };
        // The hash properties are computed on demand from the encoded certificate, so this can
        // only fail on allocation failure, which Rust treats as fatal anyway.
        assert_ne!(ok, 0, "CertGetCertificateContextProperty failed to size hash property {prop_id}");

        let mut buf: Vec<u8> = vec![0; len as usize];

        let ok = unsafe {
            CertGetCertificateContextProperty(
                self.leaf_cert_ptr,
                prop_id,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len,
            )
        };
        assert_ne!(ok, 0, "CertGetCertificateContextProperty failed to read hash property {prop_id}");

        to_hex(&buf[..len as usize])
    }

    pub fn sha1_thumbprint(&self) -> String {
        self.hash_property(CERT_SHA1_HASH_PROP_ID)
    }

    pub fn sha256_thumbprint(&self) -> String {
        self.hash_property(CERT_SHA256_HASH_PROP_ID)
    }
}
