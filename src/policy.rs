/// How much of the certificate chain is checked for revocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Revocation {
    /// Revocation is not checked (the default).
    #[default]
    None,
    /// Check only the signing (leaf) certificate.
    ///
    /// On macOS the Security framework doesn't offer this granularity, so this behaves like
    /// [`Revocation::Chain`].
    EndCertificate,
    /// Check every certificate in the chain except the root.
    Chain,
}

/// Settings that control how a signature is verified.
///
/// Pass it to [`CodeSignVerifier::new`](crate::CodeSignVerifier::new).
/// [`VerifyPolicy::default()`] is what [`CodeSignVerifier::default()`](crate::CodeSignVerifier::default)
/// and the [`verify_file`](crate::verify_file) / [`verify_pid`](crate::verify_pid) shorthands use:
///
/// - revocation is not checked
/// - network access is left to the platform (see [`VerifyPolicy::allow_network`])
/// - a certificate that expired after the file was signed is still accepted
/// - on Windows, catalogs are searched by SHA-256 hash only (see [`VerifyPolicy::sha1_catalogs`])
/// - on macOS, the requirement is `anchor trusted` and every architecture of a universal
///   binary is validated
///
/// ```no_run
/// use verifysign::{CodeSignVerifier, Revocation, VerifyPolicy};
///
/// let policy = VerifyPolicy::new()
///     .revocation(Revocation::Chain)
///     .allow_network(true);
///
/// let verifier = CodeSignVerifier::new(policy)?;
/// let _ctx = verifier.verify_file("C:/Windows/explorer.exe")?;
/// # Ok::<(), verifysign::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyPolicy {
    pub(crate) revocation: Revocation,
    pub(crate) allow_network: Option<bool>,
    pub(crate) strict_expiration: bool,
    #[cfg(any(windows, doc))]
    pub(crate) sha1_catalogs: bool,
    #[cfg(any(target_os = "macos", doc))]
    pub(crate) requirement: String,
    #[cfg(any(target_os = "macos", doc))]
    pub(crate) all_architectures: bool,
}

impl Default for VerifyPolicy {
    fn default() -> Self {
        VerifyPolicy {
            revocation: Revocation::None,
            allow_network: None,
            strict_expiration: false,
            #[cfg(any(windows, doc))]
            sha1_catalogs: false,
            #[cfg(any(target_os = "macos", doc))]
            requirement: "anchor trusted".to_string(),
            #[cfg(any(target_os = "macos", doc))]
            all_architectures: true,
        }
    }
}

impl VerifyPolicy {
    /// Same as [`VerifyPolicy::default()`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set which certificates are checked for revocation. A revoked certificate then fails
    /// verification. Checking usually needs network access (OCSP/CRL) and is slower.
    pub fn revocation(mut self, revocation: Revocation) -> Self {
        self.revocation = revocation;
        self
    }

    /// Allow or forbid network access during verification (e.g. fetching revocation lists or
    /// missing intermediate certificates). When forbidden, only locally cached data is used.
    ///
    /// If not set, the platform's behavior applies: on Windows the network is only used when
    /// revocation checking is enabled; on macOS the Security framework decides.
    pub fn allow_network(mut self, allow: bool) -> Self {
        self.allow_network = Some(allow);
        self
    }

    /// Reject signatures whose certificate has expired, even if the file was signed (and
    /// timestamped) while the certificate was still valid. Off by default.
    ///
    /// Uses `WTD_LIFETIME_SIGNING_FLAG` on Windows and `kSecCSConsiderExpiration` on macOS.
    /// Note that many OS-supplied Windows files are signed with certificates that have since
    /// expired, so this will reject them.
    pub fn strict_expiration(mut self, strict: bool) -> Self {
        self.strict_expiration = strict;
        self
    }

    /// Also search the system catalogs by SHA-1 hash when no catalog lists the file's SHA-256
    /// hash. Off by default.
    ///
    /// Windows itself still accepts catalogs that list their members by SHA-1 hash only; they
    /// come with driver packages signed before 2016 and are rare on current systems. A SHA-1
    /// hash is weak enough that a crafted file could be made to match a legitimately listed
    /// one, so the default does not trust such catalogs and reports their files as `Unsigned`.
    /// Turn this on to match Windows' own verdict instead. It costs an extra hash and lookup
    /// for every file that turns out to be unsigned.
    #[cfg(any(windows, doc))]
    #[cfg_attr(docsrs, doc(cfg(windows)))]
    pub fn sha1_catalogs(mut self, enabled: bool) -> Self {
        self.sha1_catalogs = enabled;
        self
    }

    /// Set the code requirement the signature must satisfy, written in Apple's
    /// [Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html).
    /// Defaults to `anchor trusted`. For example `anchor apple generic and certificate
    /// leaf[subject.OU] = "TEAMID1234"` pins a specific developer team.
    ///
    /// A requirement that fails to parse makes [`CodeSignVerifier::new`](crate::CodeSignVerifier::new)
    /// return `Error::CFError`.
    #[cfg(any(target_os = "macos", doc))]
    #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
    pub fn requirement(mut self, requirement: impl Into<String>) -> Self {
        self.requirement = requirement.into();
        self
    }

    /// Validate every architecture of a universal binary (the default), or only the host's.
    /// Only applies to files; a running process is always validated for its own architecture.
    #[cfg(any(target_os = "macos", doc))]
    #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
    pub fn check_all_architectures(mut self, all: bool) -> Self {
        self.all_architectures = all;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_preserves_existing_behavior() {
        let policy = VerifyPolicy::default();

        assert_eq!(policy, VerifyPolicy::new());
        assert_eq!(policy.revocation, Revocation::None);
        assert_eq!(policy.allow_network, None);
        assert!(!policy.strict_expiration);
        #[cfg(windows)]
        assert!(!policy.sha1_catalogs);
        #[cfg(target_os = "macos")]
        {
            assert_eq!(policy.requirement, "anchor trusted");
            assert!(policy.all_architectures);
        }
    }
}
