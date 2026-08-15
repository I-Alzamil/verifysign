mod context;
#[allow(non_upper_case_globals)]
mod osx;

use super::Error;
use osx::*;

pub(crate) struct Verifier(SecCodeKind);
pub(crate) use context::Context;

#[derive(Debug)]
enum SecCodeKind {
    Static(SecStaticCode), // Static code is created for files on disk
    Dynamic(SecCode),      // Regular code is created for a guest pid
}

impl Verifier {
    /// Retrieve the code object for the process with the given pid
    pub fn for_pid(pid: u32) -> Result<Self, Error> {
        let mut sec: SecCodeRef = std::ptr::null_mut();

        let attributes = unsafe {
            CFDictionary::from_CFType_pairs(&[(
                CFString::wrap_under_get_rule(kSecGuestAttributePid),
                CFNumber::from(pid as i32),
            )])
        };

        unsafe {
            match SecCodeCopyGuestWithAttributes(
                std::ptr::null_mut(),
                attributes.as_concrete_TypeRef(),
                SecCSFlags::kSecCSDefaultFlags,
                Some(&mut sec),
            ) {
                osx::errSecSuccess if !sec.is_null() => Ok(Verifier(SecCodeKind::Dynamic(
                    SecCode::wrap_under_create_rule(sec),
                ))),
                err => Err(Error::OsError(err)),
            }
        }
    }

    /// Retrieve the code object for the file at the target location
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let mut sec: SecStaticCodeRef = std::ptr::null_mut();
        let url = CFURL::from_path(path.as_ref(), false).ok_or(Error::InvalidPath)?;

        unsafe {
            match SecStaticCodeCreateWithPath(
                url.as_concrete_TypeRef(),
                SecCSFlags::kSecCSDefaultFlags,
                Some(&mut sec),
            ) {
                osx::errSecSuccess if !sec.is_null() => Ok(Verifier(SecCodeKind::Static(
                    SecStaticCode::wrap_under_create_rule(sec),
                ))),
                err => Err(Error::OsError(err)),
            }
        }
    }

    pub fn verify(&self) -> Result<Context, Error> {
        // "anchor trusted" is the most generic verification: it requires the signer's
        // certificate chain to terminate in a trust anchor the system actually trusts.
        //
        // On arm64, the linker auto-signs every binary with an ad-hoc signature (no
        // certificate at all) so the kernel will run it, so that check fails with
        // errSecCSReqFailed instead of errSecCSUnsigned. Treat that case as unsigned
        // too, so behavior matches x86_64 (where an unsigned build has no signature
        // whatsoever and fails with errSecCSUnsigned directly) — a bare ad-hoc hash
        // carries no identity to report anyway.
        if let Err(err) = self.check_validity("anchor trusted") {
            return Err(match err {
                Error::Unsigned => Error::Unsigned,
                _ if self.is_adhoc_signed() => Error::Unsigned,
                other => other,
            });
        }

        let sec_info = self.get_code_singing_info()?;
        let cert_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoCertificates) };

        let certs_ref = sec_info
            .find(cert_key.as_CFTypeRef())
            .ok_or(Error::LeafCertNotFound)?;

        let certs = unsafe { CFArray::<SecCertificate>::wrap_under_get_rule(*certs_ref as _) };
        let leaf_cert = certs.get(0).ok_or(Error::LeafCertNotFound)?;

        Ok(Context::new(leaf_cert.as_concrete_TypeRef()))
    }

    /// Retreive a dictionary of various pieces of information from a code signature.
    fn get_code_singing_info(&self) -> Result<CFDictionary, Error> {
        let mut dict: CFDictionaryRef = std::ptr::null_mut();

        let sec = match &self.0 {
            SecCodeKind::Static(sec) => sec.as_concrete_TypeRef(),
            SecCodeKind::Dynamic(sec) => sec.as_CFTypeRef() as _, // Dynamic will be implicitly converted to static
        };

        unsafe {
            match SecCodeCopySigningInformation(
                sec,
                SecCSFlags::kSecCSSigningInformation,
                Some(&mut dict),
            ) {
                osx::errSecSuccess if !dict.is_null() => {
                    Ok(CFDictionary::wrap_under_create_rule(dict))
                }
                err => Err(Error::OsError(err)),
            }
        }
    }

    /// Best-effort check for whether the code carries only an ad-hoc signature (no
    /// certificate/identity attached). Returns `false` — rather than propagating an
    /// error — if the probe itself fails, so callers fall back to the original error.
    fn is_adhoc_signed(&self) -> bool {
        let Ok(info) = self.get_code_singing_info() else {
            return false;
        };

        let flags_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) };

        let Some(flags_ref) = info.find(flags_key.as_CFTypeRef()) else {
            return false;
        };

        let flags = unsafe { CFNumber::wrap_under_get_rule(*flags_ref as CFNumberRef) };
        let flags = flags.to_i64().unwrap_or(0) as u32;

        flags & kSecCodeSignatureAdhoc != 0
    }

    fn check_validity(&self, requirement: &str) -> Result<(), Error> {
        let mut req: SecRequirementRef = std::ptr::null_mut();
        let mut err: CFErrorRef = std::ptr::null_mut();

        // Generate a new requirement object using the Apple [Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html#//apple_ref/doc/uid/TP40005929-CH5-SW1)
        let req = unsafe {
            match SecRequirementCreateWithStringAndErrors(
                CFString::new(requirement).as_concrete_TypeRef(),
                SecCSFlags::kSecCSDefaultFlags,
                Some(&mut err),
                Some(&mut req),
            ) {
                osx::errSecSuccess if !req.is_null() => {
                    SecRequirement::wrap_under_create_rule(req)
                }
                status => {
                    if !err.is_null() {
                        return Err(Error::from_cferror(err));
                    } else {
                        return Err(Error::OsError(status));
                    }
                }
            }
        };

        let status = match &self.0 {
            SecCodeKind::Static(sec) => unsafe {
                SecStaticCodeCheckValidityWithErrors(
                    sec.as_concrete_TypeRef(),
                    SecCSFlags::kSecCSDefaultFlags,
                    req.as_concrete_TypeRef(),
                    Some(&mut err),
                )
            },
            SecCodeKind::Dynamic(sec) => unsafe {
                SecCodeCheckValidityWithErrors(
                    sec.as_concrete_TypeRef(),
                    SecCSFlags::kSecCSDefaultFlags,
                    req.as_concrete_TypeRef(),
                    Some(&mut err),
                )
            },
        };

        match status {
            osx::errSecSuccess => Ok(()),
            osx::errSecCSUnsigned => {
                // errors is CF_RETURNS_RETAINED: release it even though we discard its contents.
                if !err.is_null() {
                    drop(unsafe { CFError::wrap_under_create_rule(err) });
                }
                Err(Error::Unsigned)
            }
            status => {
                if !err.is_null() {
                    Err(unsafe { Error::from_cferror(err) })
                } else {
                    Err(Error::OsError(status))
                }
            }
        }
    }
}

impl Error {
    /// Converts a non-null, owned `CFErrorRef` into an `Error`.
    ///
    /// # Safety
    ///
    /// `err` must be non-null and the caller must own the reference (e.g. it came from a
    /// `CF_RETURNS_RETAINED` out-param), since this adopts it without an extra retain.
    unsafe fn from_cferror(err: CFErrorRef) -> Self {
        debug_assert!(!err.is_null());
        unsafe {
            let err = CFError::wrap_under_create_rule(err);
            Error::CFError(format!("{:?}", err))
        }
    }
}
