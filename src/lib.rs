//! Verify the digital code signature of a file or running process on Windows and macOS,
//! and read identifying details from the signing (leaf) certificate.
//!
//! On Windows verification goes through WinTrust (Authenticode, falling back to catalog
//! signatures); on macOS it goes through the Security framework's code signing services.
//!
//! ```no_run
//! use verifysign::{CodeSignVerifier, Error};
//!
//! match CodeSignVerifier::for_file("/path/to/binary").and_then(|v| v.verify()) {
//!     Ok(ctx) => println!("signed by {:?}", ctx.subject_name().common_name),
//!     Err(Error::Unsigned) => println!("not signed"),
//!     Err(e) => println!("verification failed: {e}"),
//! }
//! ```
//!
//! # Policy
//!
//! Certificate revocation is **not** checked by default, so a file signed with a since-revoked
//! certificate still verifies. Use a [`VerifyPolicy`] with [`CodeSignVerifier::policy`] to enable
//! it, control network access, reject expired certificates and more.

#[cfg(target_os = "macos")]
mod macos;
mod policy;
#[cfg(windows)]
mod windows;

pub use policy::{Revocation, VerifyPolicy};

#[cfg(target_os = "macos")]
use macos::{Context, Verifier};
#[cfg(windows)]
use windows::{Context, Verifier};

#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("verifysign only supports macOS and Windows targets");

///
/// Used to verify the validity of a code signature
///
pub struct CodeSignVerifier(Verifier);

///
/// Used to extract additional information from the signing leaf certificate
///
pub struct SignatureContext(Context);

///
/// Represents an Issuer or Subject name with the following fields:
///
/// # Fields
///
/// `common_name`: OID 2.5.4.3
///
/// `organization`: OID 2.5.4.10
///
/// `organization_unit`: OID 2.5.4.11
///
/// `country`: OID 2.5.4.6
///
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Name {
    pub common_name: Option<String>,       // 2.5.4.3
    pub organization: Option<String>,      // 2.5.4.10
    pub organization_unit: Option<String>, // 2.5.4.11
    pub country: Option<String>,           // 2.5.4.6
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Unsigned,         // The binary file didn't have any signature
    OsError(i32),     // Wraps an inner provider error code (HRESULT on Windows, OSStatus on macOS)
    InvalidPath,      // The provided path was malformed
    LeafCertNotFound, // Unable to fetch certificate information
    #[cfg(target_os = "macos")]
    CFError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unsigned => f.write_str("the file is not signed"),
            #[cfg(windows)]
            Error::OsError(code) => write!(f, "OS error {code:#010x}"),
            #[cfg(not(windows))]
            Error::OsError(code) => write!(f, "OS error {code}"),
            Error::InvalidPath => f.write_str("the provided path is invalid"),
            Error::LeafCertNotFound => f.write_str("unable to find the signing leaf certificate"),
            #[cfg(target_os = "macos")]
            Error::CFError(msg) => write!(f, "Core Foundation error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl CodeSignVerifier {
    /// Create a verifier for a binary at a given path.
    /// On macOS it can be either a binary or an application package.
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        Verifier::for_file(path).map(CodeSignVerifier)
    }

    /// Create a verifier for a running application by PID.
    ///
    /// # Security
    ///
    /// A PID is not a stable identity: the process may exit and its PID be reused by another
    /// process between the time the PID was obtained and the time this is called. On Windows
    /// the PID is also resolved to the executable's path and the *file on disk* is verified,
    /// not the image actually running in memory, so a file replaced after launch is not
    /// detected. Do not rely on this alone to authenticate a peer (e.g. the other end of a
    /// pipe) in security-sensitive contexts.
    pub fn for_pid(pid: u32) -> Result<Self, Error> {
        Verifier::for_pid(pid).map(CodeSignVerifier)
    }

    /// Set the policy used by [`verify`](Self::verify). Without this, [`VerifyPolicy::default()`]
    /// is used.
    pub fn policy(mut self, policy: VerifyPolicy) -> Self {
        self.0.set_policy(policy);
        self
    }

    /// Perform the verification itself, according to the [`VerifyPolicy`].
    /// On macOS the verification uses the Security framework with the policy's requirement
    /// (by default "anchor trusted").
    /// On Windows the verification uses WinTrust and the `WINTRUST_ACTION_GENERIC_VERIFY_V2` action.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use verifysign::CodeSignVerifier;
    ///
    /// CodeSignVerifier::for_file("C:/Windows/explorer.exe").unwrap().verify().unwrap();
    /// ```
    pub fn verify(self) -> Result<SignatureContext, Error> {
        self.0.verify().map(SignatureContext)
    }
}

impl SignatureContext {
    /// Retrieve the subject name on the leaf certificate
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use verifysign::CodeSignVerifier;
    ///
    /// let ctx = CodeSignVerifier::for_file("C:/Windows/explorer.exe").unwrap().verify().unwrap();
    /// assert_eq!(
    ///    ctx.subject_name().organization.as_deref(),
    ///    Some("Microsoft Corporation")
    /// );
    ///
    /// ```
    pub fn subject_name(&self) -> Name {
        self.0.subject_name()
    }

    /// Retrieve the issuer name on the leaf certificate
    pub fn issuer_name(&self) -> Name {
        self.0.issuer_name()
    }

    /// Compute the sha1 thumbprint of the leaf certificate, as lowercase hex
    pub fn sha1_thumbprint(&self) -> String {
        self.0.sha1_thumbprint()
    }

    /// Compute the sha256 thumbprint of the leaf certificate, as lowercase hex
    pub fn sha256_thumbprint(&self) -> String {
        self.0.sha256_thumbprint()
    }

    /// Retrieve the leaf certificate serial number, as lowercase big-endian hex of the
    /// DER-encoded integer (so it may start with `00`). The format is the same on all platforms.
    pub fn serial(&self) -> Option<String> {
        self.0.serial()
    }
}

/// Lowercase hex encoding shared by the platform backends.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use crate::{Error, SignatureContext, VerifyPolicy};

    // ------------------------------------------------------------------
    // 1. Detection: a signature is (or isn't) found on a binary
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_signature_detected() {
        // Should always be present and signed on macOS
        assert!(signed_context("/sbin/ping").is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_signature_detected() {
        // explorer.exe carries an embedded Authenticode signature
        assert!(signed_context(&explorer_path()).is_ok());
        // cmd.exe is validated via a catalog signature rather than an embedded one;
        // this exercises the WTHelperGetProvCertFromChain catalog lookup path.
        assert!(signed_context(&cmd_path()).is_ok());
    }

    #[test]
    fn test_unsigned_binary_not_detected() {
        let path = std::env::current_exe().unwrap(); // own path, always unsigned and present

        assert!(matches!(
            super::CodeSignVerifier::for_file(path).unwrap().verify(),
            Err(Error::Unsigned)
        ));
    }

    // ------------------------------------------------------------------
    // Verification policy
    // ------------------------------------------------------------------

    #[test]
    fn test_offline_policy_accepts_signed_binary() {
        // Revocation off and no network: system binaries must still verify from local data.
        let policy = VerifyPolicy::new().allow_network(false);

        for path in signed_paths() {
            let ctx = super::CodeSignVerifier::for_file(&path).unwrap().policy(policy.clone()).verify();
            assert!(ctx.is_ok(), "{path}: {:?}", ctx.err());
        }
    }

    #[test]
    fn test_policy_keeps_unsigned_binary_unsigned() {
        let policy = VerifyPolicy::new().allow_network(false).strict_expiration(true);
        let path = std::env::current_exe().unwrap();

        assert!(matches!(
            super::CodeSignVerifier::for_file(path).unwrap().policy(policy).verify(),
            Err(Error::Unsigned)
        ));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_custom_requirement() {
        let verify = |requirement: &str| {
            super::CodeSignVerifier::for_file("/sbin/ping")
                .unwrap()
                .policy(VerifyPolicy::new().requirement(requirement))
                .verify()
        };

        // Satisfied: ping is signed by Apple itself.
        assert!(verify("anchor apple").is_ok());
        // Signed, but not by the required identity: a real failure, not "unsigned".
        assert!(matches!(verify("identifier \"com.example.nope\""), Err(Error::CFError(_))));
        // Malformed requirement text.
        assert!(matches!(verify("not a requirement ("), Err(Error::CFError(_))));
    }

    #[test]
    #[cfg(windows)]
    fn test_path_with_interior_nul_rejected() {
        assert!(matches!(
            super::CodeSignVerifier::for_file("C:\\Windows\\explorer.exe\0.txt"),
            Err(Error::InvalidPath)
        ));
    }

    // ------------------------------------------------------------------
    // 2. Subject name OID properties (common name, organization, country, ...)
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_subject_name_oid_properties() {
        // Ask codesign/openssl for the leaf certificate's fields instead of relying on
        // hardcoded values, since Apple periodically rotates the signing certificate.
        let path = "/sbin/ping";
        let ctx = signed_context(path).unwrap();
        let cert = extract_leaf_certificate(path);

        assert_eq!(
            ctx.subject_name().organization,
            macos_cert_field(&cert, "-subject", "O")
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_subject_name_oid_properties() {
        // Ask Windows itself for the leaf certificate's subject fields instead of relying on
        // hardcoded values, since Microsoft periodically rotates the signing certificate.
        for path in [explorer_path(), cmd_path()] {
            let ctx = signed_context(&path).unwrap();

            assert_eq!(
                ctx.subject_name().organization,
                windows_cert_field(&path, "Subject", "O")
            );
        }
    }

    // ------------------------------------------------------------------
    // 3. Issuer name OID properties (common name, organization, country, ...)
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_issuer_name_oid_properties() {
        let path = "/sbin/ping";
        let ctx = signed_context(path).unwrap();
        let cert = extract_leaf_certificate(path);

        assert_eq!(
            ctx.issuer_name().organization_unit,
            macos_cert_field(&cert, "-issuer", "OU")
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_issuer_name_oid_properties() {
        // Ask Windows itself for the leaf certificate's issuer fields instead of relying on
        // hardcoded values, since Microsoft periodically rotates the signing certificate.
        for path in [explorer_path(), cmd_path()] {
            let ctx = signed_context(&path).unwrap();

            assert_eq!(
                ctx.issuer_name().common_name,
                windows_cert_field(&path, "Issuer", "CN")
            );
        }
    }

    // ------------------------------------------------------------------
    // 4. sha1 / sha256 thumbprints
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_thumbprints() {
        let path = "/sbin/ping";
        let ctx = signed_context(path).unwrap();
        let cert = extract_leaf_certificate(path);

        assert_eq!(ctx.sha1_thumbprint(), macos_cert_fingerprint(&cert, "-sha1"));
        assert_eq!(ctx.sha256_thumbprint(), macos_cert_fingerprint(&cert, "-sha256"));
    }

    #[test]
    #[cfg(windows)]
    fn test_thumbprints() {
        // Ask Windows itself for the signer certificate's thumbprints instead of relying on
        // hardcoded values, since Microsoft periodically rotates the signing certificate.
        for path in [explorer_path(), cmd_path()] {
            let ctx = signed_context(&path).unwrap();

            assert_eq!(
                ctx.sha1_thumbprint(),
                windows_signer_property(&path, "Thumbprint").to_lowercase()
            );
            assert_eq!(ctx.sha256_thumbprint(), windows_sha256_thumbprint(&path));
        }
    }

    // ------------------------------------------------------------------
    // 5. Serial number
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_serial_number() {
        let path = "/sbin/ping";
        let ctx = signed_context(path).unwrap();
        let cert = extract_leaf_certificate(path);

        // openssl drops the DER sign byte, so compare without leading zeros.
        assert_eq!(
            ctx.serial().map(|s| s.trim_start_matches('0').to_string()),
            Some(macos_cert_serial(&cert).trim_start_matches('0').to_string())
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_serial_number() {
        // Ask Windows itself for the signer certificate's serial number instead of relying on
        // a hardcoded value, since Microsoft periodically rotates the signing certificate.
        for path in [explorer_path(), cmd_path()] {
            let ctx = signed_context(&path).unwrap();

            assert_eq!(
                ctx.serial().unwrap_or_default(),
                windows_signer_property(&path, "SerialNumber").to_lowercase()
            );
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    // Binaries that are always present and signed on the current platform.
    fn signed_paths() -> Vec<String> {
        #[cfg(target_os = "macos")]
        return vec!["/sbin/ping".to_string()];
        #[cfg(windows)]
        return vec![explorer_path(), cmd_path()];
    }

    fn signed_context(path: &str) -> Result<SignatureContext, Error> {
        super::CodeSignVerifier::for_file(path)?.verify()
    }

    // A leaf certificate extracted into its own temporary directory, removed on drop. Each
    // extraction gets a unique directory since tests run concurrently within one process.
    #[cfg(target_os = "macos")]
    struct LeafCert(std::path::PathBuf);

    #[cfg(target_os = "macos")]
    impl LeafCert {
        fn path(&self) -> std::path::PathBuf {
            self.0.join("cert0")
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for LeafCert {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // Extracts the leaf signing certificate from a binary via `codesign` so tests can compare
    // against it instead of relying on hardcoded values, since Apple periodically rotates the
    // signing certificate.
    #[cfg(target_os = "macos")]
    fn extract_leaf_certificate(path: &str) -> LeafCert {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let dir = std::env::temp_dir().join(format!(
            "verifysign-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = LeafCert(dir);
        let prefix = cert.0.join("cert");
        let output = std::process::Command::new("codesign")
            .arg("-d")
            .arg(format!("--extract-certificates={}", prefix.display()))
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "codesign --extract-certificates failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        cert
    }

    #[cfg(target_os = "macos")]
    fn openssl_x509(cert: &LeafCert, args: &[&str]) -> String {
        let output = std::process::Command::new("openssl")
            .args(["x509", "-inform", "DER", "-in"])
            .arg(cert.path())
            .arg("-noout")
            .args(args)
            .output()
            .unwrap();

        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    // Parses a `subject= /CN=.../O=.../C=US`-style openssl name line for the given RDN key.
    #[cfg(target_os = "macos")]
    fn macos_cert_field(cert: &LeafCert, which: &str, key: &str) -> Option<String> {
        let line = openssl_x509(cert, &[which]);
        let rdns = line.split_once('/')?.1;

        rdns.split('/').find_map(|rdn| {
            let (k, v) = rdn.split_once('=')?;
            (k == key).then(|| v.to_string())
        })
    }

    #[cfg(target_os = "macos")]
    fn macos_cert_fingerprint(cert: &LeafCert, algo: &str) -> String {
        openssl_x509(cert, &["-fingerprint", algo])
            .rsplit('=')
            .next()
            .unwrap()
            .replace(':', "")
            .to_lowercase()
    }

    #[cfg(target_os = "macos")]
    fn macos_cert_serial(cert: &LeafCert) -> String {
        openssl_x509(cert, &["-serial"])
            .trim_start_matches("serial=")
            .to_lowercase()
    }

    // explorer.exe carries an embedded Authenticode signature and should always be present.
    #[cfg(windows)]
    fn explorer_path() -> String {
        format!("{}\\explorer.exe", std::env::var("windir").unwrap())
    }

    // cmd.exe is validated via a catalog signature rather than an embedded one and should
    // always be present.
    #[cfg(windows)]
    fn cmd_path() -> String {
        format!("{}\\system32\\cmd.exe", std::env::var("windir").unwrap())
    }

    // Runs Windows PowerShell (not the pwsh we may be hosted under) for a one-off `-Command`.
    // A pwsh parent leaks its PSModulePath to spawned powershell.exe children, which then
    // fails to autoload built-in modules like Microsoft.PowerShell.Security, so it's cleared.
    #[cfg(windows)]
    fn run_powershell(command: &str) -> String {
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", command])
            .env_remove("PSModulePath")
            .output()
            .unwrap();

        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    #[cfg(windows)]
    fn windows_signer_property(path: &str, property: &str) -> String {
        run_powershell(&format!(
            "(Get-AuthenticodeSignature -FilePath '{}').SignerCertificate.{}",
            path, property
        ))
    }

    // Parses a `.SignerCertificate.Subject`/`.Issuer`-style distinguished name
    // (e.g. "CN=..., O=..., C=US") for the given RDN key, mirroring the macOS
    // `macos_cert_field` helper so fields are asked of the OS rather than hardcoded.
    #[cfg(windows)]
    fn windows_cert_field(path: &str, which: &str, key: &str) -> Option<String> {
        let dn = windows_signer_property(path, which);

        dn.split(',').find_map(|rdn| {
            let (k, v) = rdn.trim().split_once('=')?;
            k.eq_ignore_ascii_case(key).then(|| v.trim().to_string())
        })
    }

    #[cfg(windows)]
    fn windows_sha256_thumbprint(path: &str) -> String {
        run_powershell(&format!(
            "$c = (Get-AuthenticodeSignature -FilePath '{}').SignerCertificate; \
             [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)) -replace '-',''",
            path
        )).to_lowercase()
    }
}
