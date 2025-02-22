use std::ffi::{c_uchar, c_ulong};

pub use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, FALSE, GENERIC_READ, HANDLE,
    INVALID_HANDLE_VALUE, TRUST_E_NOSIGNATURE, TRUST_E_NO_SIGNER_CERT, WIN32_ERROR,
};
pub use windows_sys::Win32::Security::Cryptography::Catalog::*;
pub use windows_sys::Win32::Security::Cryptography::*;
pub use windows_sys::Win32::Security::WinTrust::*;
pub use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, OPEN_EXISTING,
};
pub use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[allow(non_camel_case_types)]
pub type PCCERT_CONTEXT = *const CERT_CONTEXT;
pub type DWORD = c_ulong;
pub type BYTE = c_uchar;