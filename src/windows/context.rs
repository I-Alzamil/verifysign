use super::wintrust_sys::*;
use crate::Name;

pub(crate) struct Context {
    data: HANDLE,
    leaf_cert_ptr: PCCERT_CONTEXT,
}

impl Drop for Context {
    fn drop(&mut self) {
        close_data(self.data);
    }
}

fn close_data(handle: HANDLE) {
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
    pub fn new(state_data: HANDLE) -> Result<Self, WIN32_ERROR> {
        let mut ret = Context {
            data: state_data,
            leaf_cert_ptr: std::ptr::null(),
        };

        unsafe {
            let crypt_prov_data = match WTHelperProvDataFromStateData(state_data) {
                data if data.is_null() => return Err(TRUST_E_NO_SIGNER_CERT as u32),
                data => data,
            };

            let crypt_prov_sgnr = match WTHelperGetProvSignerFromChain(crypt_prov_data, 0, 0, 0) {
                sgnr if sgnr.is_null() => return Err(TRUST_E_NO_SIGNER_CERT as u32),
                sgnr => sgnr,
            };

            let crypt_prov_cert = match WTHelperGetProvCertFromChain(crypt_prov_sgnr, 0) {
                cert if cert.is_null() => return Err(TRUST_E_NO_SIGNER_CERT as u32),
                cert => cert,
            };

            ret.leaf_cert_ptr = crypt_prov_cert.as_ref().unwrap().pCert as PCCERT_CONTEXT;
        }

        Ok(ret)
    }

    fn get_oid_name(&self, issuer: bool, oid: windows_sys::core::PCSTR) -> Option<String> {
        use std::os::windows::ffi::OsStringExt;
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

        if len == 1 {
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

        Some(
            std::ffi::OsString::from_wide(&buf[..len as usize - 1])
                .into_string()
                .unwrap(),
        )
    }

    pub fn serial(&self) -> Option<String> {
        let serial_blob = unsafe {
            self.leaf_cert_ptr
                .as_ref()
                .unwrap()
                .pCertInfo
                .as_ref()
                .unwrap()
                .SerialNumber
        };

        let blob =
            unsafe { std::slice::from_raw_parts(serial_blob.pbData, serial_blob.cbData as usize) };

        // For some reason windows stores the serial number in reverse order
        Some(
            blob.iter()
                .fold(String::new(), |v, s| format!("{:02x}{}", s, v)),
        )
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

    pub fn sha1_thumbprint(&self) -> String {
        let mut len: u32 = 0;
       
        unsafe { 
            CertGetCertificateContextProperty(
                self.leaf_cert_ptr,
                CERT_SHA1_HASH_PROP_ID,
                std::ptr::null_mut(),
                &mut len
            );
        }

        let mut buf: Vec<u8> = vec![0;len as usize];

        unsafe { 
            CertGetCertificateContextProperty(
                self.leaf_cert_ptr,
                CERT_SHA1_HASH_PROP_ID,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len
            );
        }

        buf.as_slice()
            .iter()
            .fold(String::new(), |full_hash, hash_chunk| full_hash + &format!("{:02x}", hash_chunk))
    }

    pub fn sha256_thumbprint(&self) -> String {
        let mut len: u32 = 0;
        
        unsafe { 
            CertGetCertificateContextProperty(
                self.leaf_cert_ptr,
                CERT_SHA256_HASH_PROP_ID,
                std::ptr::null_mut(),
                &mut len
            );
        }

        let mut buf: Vec<u8> = vec![0;len as usize];

        unsafe { 
            CertGetCertificateContextProperty(
                self.leaf_cert_ptr,
                CERT_SHA256_HASH_PROP_ID,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len
            );
        }

        buf.as_slice()
            .iter()
            .fold(String::new(), |full_hash, hash_chunk| full_hash + &format!("{:02x}", hash_chunk))
    }
}
