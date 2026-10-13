mod context;
#[allow(non_upper_case_globals)]
mod osx;

use super::{Error, Revocation, VerifyPolicy};
use osx::*;

#[derive(Debug, Clone)]
pub(crate) struct Verifier {
    policy: VerifyPolicy,
    requirement: SecRequirement, // Compiled from policy.requirement
}
pub(crate) use context::Context;

// SAFETY: the only non-thread-safe field is the SecRequirement, an immutable CF object that
// is never mutated after creation; immutable CF objects may be shared and released from any
// thread.
unsafe impl Send for Verifier {}
unsafe impl Sync for Verifier {}

#[derive(Debug)]
enum SecCodeKind {
    Static(SecStaticCode), // Static code is created for files on disk
    Dynamic(SecCode),      // Regular code is created for a guest pid
}

impl Verifier {
    /// Compiles the policy's requirement up front, so a malformed one is reported here rather
    /// than on every verification.
    pub fn new(policy: VerifyPolicy) -> Result<Self, Error> {
        let requirement = compile_requirement(&policy.requirement)?;

        Ok(Verifier { policy, requirement })
    }

    pub fn policy(&self) -> &VerifyPolicy {
        &self.policy
    }

    pub fn verify_pid(&self, pid: u32) -> Result<Context, Error> {
        self.verify(&SecCodeKind::for_pid(pid)?)
    }

    pub fn verify_file(&self, path: &std::path::Path) -> Result<Context, Error> {
        self.verify(&SecCodeKind::for_file(path)?)
    }

    fn verify(&self, code: &SecCodeKind) -> Result<Context, Error> {
        // The default requirement, "anchor trusted", is the most generic verification: it
        // requires the signer's certificate chain to terminate in a trust anchor the system
        // actually trusts.
        //
        // On arm64, the linker auto-signs every binary with an ad-hoc signature (no
        // certificate at all) so the kernel will run it, so that check fails with
        // errSecCSReqFailed instead of errSecCSUnsigned. Treat that case as unsigned
        // too, so behavior matches x86_64 (where an unsigned build has no signature
        // whatsoever and fails with errSecCSUnsigned directly) — a bare ad-hoc hash
        // carries no identity to report anyway.
        if let Err(err) = self.check_validity(code) {
            return Err(match err {
                Error::Unsigned => Error::Unsigned,
                _ if code.is_adhoc_signed() => Error::Unsigned,
                other => other,
            });
        }

        let sec_info = code.get_code_signing_info()?;
        let cert_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoCertificates) };

        let certs_ref = sec_info
            .find(cert_key.as_CFTypeRef())
            .ok_or(Error::LeafCertNotFound)?;

        let certs = unsafe { CFArray::<SecCertificate>::wrap_under_get_rule(*certs_ref as _) };
        let leaf_cert = certs.get(0).ok_or(Error::LeafCertNotFound)?;

        Ok(Context::new(&leaf_cert))
    }

    fn check_validity(&self, code: &SecCodeKind) -> Result<(), Error> {
        let mut err: CFErrorRef = std::ptr::null_mut();

        let status = match code {
            SecCodeKind::Static(sec) => unsafe {
                SecStaticCodeCheckValidityWithErrors(
                    sec.as_concrete_TypeRef(),
                    validity_flags(&self.policy, true),
                    self.requirement.as_concrete_TypeRef(),
                    Some(&mut err),
                )
            },
            SecCodeKind::Dynamic(sec) => unsafe {
                SecCodeCheckValidityWithErrors(
                    sec.as_concrete_TypeRef(),
                    validity_flags(&self.policy, false),
                    self.requirement.as_concrete_TypeRef(),
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

/// Generate a requirement object using the Apple [Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html#//apple_ref/doc/uid/TP40005929-CH5-SW1)
fn compile_requirement(requirement: &str) -> Result<SecRequirement, Error> {
    let mut req: SecRequirementRef = std::ptr::null_mut();
    let mut err: CFErrorRef = std::ptr::null_mut();

    unsafe {
        match SecRequirementCreateWithStringAndErrors(
            CFString::new(requirement).as_concrete_TypeRef(),
            kSecCSDefaultFlags,
            Some(&mut err),
            Some(&mut req),
        ) {
            osx::errSecSuccess if !req.is_null() => Ok(SecRequirement::wrap_under_create_rule(req)),
            status => {
                if !err.is_null() {
                    Err(Error::from_cferror(err))
                } else {
                    Err(Error::OsError(status))
                }
            }
        }
    }
}

impl SecCodeKind {
    /// Retrieve the code object for the process with the given pid
    fn for_pid(pid: u32) -> Result<Self, Error> {
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
                kSecCSDefaultFlags,
                Some(&mut sec),
            ) {
                osx::errSecSuccess if !sec.is_null() => {
                    Ok(SecCodeKind::Dynamic(SecCode::wrap_under_create_rule(sec)))
                }
                err => Err(Error::OsError(err)),
            }
        }
    }

    /// Retrieve the code object for the file at the target location
    fn for_file(path: &std::path::Path) -> Result<Self, Error> {
        let mut sec: SecStaticCodeRef = std::ptr::null_mut();
        let url = CFURL::from_path(path, false).ok_or(Error::InvalidPath)?;

        unsafe {
            match SecStaticCodeCreateWithPath(
                url.as_concrete_TypeRef(),
                kSecCSDefaultFlags,
                Some(&mut sec),
            ) {
                osx::errSecSuccess if !sec.is_null() => {
                    Ok(SecCodeKind::Static(SecStaticCode::wrap_under_create_rule(sec)))
                }
                err => Err(Error::OsError(err)),
            }
        }
    }

    /// Retrieve a dictionary of various pieces of information from a code signature.
    fn get_code_signing_info(&self) -> Result<CFDictionary, Error> {
        let mut dict: CFDictionaryRef = std::ptr::null_mut();

        let sec = match self {
            SecCodeKind::Static(sec) => sec.as_concrete_TypeRef(),
            SecCodeKind::Dynamic(sec) => sec.as_CFTypeRef() as _, // Dynamic will be implicitly converted to static
        };

        unsafe {
            match SecCodeCopySigningInformation(
                sec,
                kSecCSSigningInformation,
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
        let Ok(info) = self.get_code_signing_info() else {
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
}

/// Translates a policy into the flags for a validity check of static (on-disk) code or of
/// dynamic code (a running process).
fn validity_flags(policy: &VerifyPolicy, is_static: bool) -> SecCSFlags {
    let mut flags = kSecCSDefaultFlags;
    if policy.revocation != Revocation::None {
        flags |= kSecCSEnforceRevocationChecks;
    }
    if policy.strict_expiration {
        flags |= kSecCSConsiderExpiration;
    }
    if policy.allow_network == Some(false) {
        flags |= kSecCSNoNetworkAccess;
    }
    // Without kSecCSCheckAllArchitectures only the host's slice of a universal binary is
    // validated, so a tampered slice for another architecture would go unnoticed.
    if is_static && policy.all_architectures {
        flags |= kSecCSCheckAllArchitectures;
    }
    flags
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_flags() {
        let policy = VerifyPolicy::default();

        assert_eq!(validity_flags(&policy, true), kSecCSCheckAllArchitectures);
        assert_eq!(validity_flags(&policy, false), kSecCSDefaultFlags);
    }

    #[test]
    fn test_revocation_flags() {
        // macOS has no leaf-only mode, so both levels enforce revocation checks.
        for revocation in [Revocation::EndCertificate, Revocation::Chain] {
            let policy = VerifyPolicy::new().revocation(revocation);

            for is_static in [true, false] {
                assert_ne!(validity_flags(&policy, is_static) & kSecCSEnforceRevocationChecks, 0);
            }
        }
    }

    #[test]
    fn test_network_flags() {
        let offline = VerifyPolicy::new().allow_network(false);
        let online = VerifyPolicy::new().allow_network(true);

        for is_static in [true, false] {
            assert_ne!(validity_flags(&offline, is_static) & kSecCSNoNetworkAccess, 0);
            assert_eq!(validity_flags(&online, is_static) & kSecCSNoNetworkAccess, 0);
        }
    }

    #[test]
    fn test_expiration_flags() {
        let policy = VerifyPolicy::new().strict_expiration(true);

        for is_static in [true, false] {
            assert_ne!(validity_flags(&policy, is_static) & kSecCSConsiderExpiration, 0);
        }
    }

    #[test]
    fn test_architecture_flags() {
        let policy = VerifyPolicy::new().check_all_architectures(false);

        assert_eq!(validity_flags(&policy, true) & kSecCSCheckAllArchitectures, 0);
    }
}
