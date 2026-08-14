#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
use macos::{Context, Verifier};
#[cfg(windows)]
use windows::{Context, Verifier};

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
#[derive(Debug, PartialEq)]
pub struct Name {
    pub common_name: Option<String>,       // 2.5.4.3
    pub organization: Option<String>,      // 2.5.4.10
    pub organization_unit: Option<String>, // 2.5.4.11
    pub country: Option<String>,           // 2.5.4.6
}

#[derive(Debug)]
pub enum Error {
    Unsigned,         // The binary file didn't have any singature
    OsError(i32),     // Warps an inner provider error code
    InvalidPath,      // The provided path was malformed
    LeafCertNotFound, // Unable to fetch certificate information
    #[cfg(target_os = "macos")]
    CFError(String),
    #[cfg(windows)]
    IoError(std::io::Error),
}

impl CodeSignVerifier {
    /// Create a verifier for a binary at a given path.
    /// On macOS it can be either a binary or an application package.
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        Verifier::for_file(path).map(CodeSignVerifier)
    }

    /// Create a verifier for a running application by PID.
    /// On Windows it will get the full path to the running application first.
    /// This can be used for e.g. verifying the app on the other end of a pipe.
    pub fn for_pid(pid: u32) -> Result<Self, Error> {
        Verifier::for_pid(pid).map(CodeSignVerifier)
    }

    /// Perform the verification itself.
    /// On macOS the verification uses the Security framework with "anchor trusted" as the requirement.
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

    /// Compute the sha1 thumbprint of the leaf certificate
    pub fn sha1_thumbprint(&self) -> String {
        self.0.sha1_thumbprint()
    }

    /// Compute the sha256 thumbprint of the leaf certificate
    pub fn sha256_thumbprint(&self) -> String {
        self.0.sha256_thumbprint()
    }

    /// Retrieve the leaf certificate serial number
    pub fn serial(&self) -> Option<String> {
        self.0.serial()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, SignatureContext};

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
    fn test_signature_detected_win_embedded() {
        // svchost.exe carries an embedded Authenticode signature
        let svchost = format!("{}\\system32\\svchost.exe", std::env::var("windir").unwrap());
        assert!(signed_context(&svchost).is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_signature_detected_win_catalog() {
        // cmd.exe is validated via a catalog signature rather than an embedded one;
        // this exercises the WTHelperGetProvCertFromChain catalog lookup path.
        let cmd = format!("{}\\system32\\cmd.exe", std::env::var("windir").unwrap());
        let ctx = signed_context(&cmd).unwrap();
        assert_eq!(
            ctx.issuer_name().organization.as_deref(),
            Some("Microsoft Corporation")
        );
    }

    #[test]
    fn test_unsigned_binary_not_detected() {
        let path = std::env::args().next().unwrap(); // own path, always unsigned and present

        assert!(matches!(
            super::CodeSignVerifier::for_file(path).unwrap().verify(),
            Err(Error::Unsigned)
        ));
    }

    // ------------------------------------------------------------------
    // 2. Subject name OID properties (common name, organization, country, ...)
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_subject_name_oid_properties() {
        let ctx = signed_context("/sbin/ping").unwrap();

        // If this begins to fail, Apple probably changed their signing certificate
        assert_eq!(
            ctx.subject_name().organization.as_deref(),
            Some("Apple Inc.")
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_subject_name_oid_properties() {
        let ctx = signed_context(&explorer_path()).unwrap();

        assert_eq!(
            ctx.subject_name().organization.as_deref(),
            Some("Microsoft Corporation")
        );
    }

    // ------------------------------------------------------------------
    // 3. Issuer name OID properties (common name, organization, country, ...)
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_issuer_name_oid_properties() {
        let ctx = signed_context("/sbin/ping").unwrap();

        assert_eq!(
            ctx.issuer_name().organization_unit.as_deref(),
            Some("Apple Certification Authority")
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_issuer_name_oid_properties() {
        let ctx = signed_context(&explorer_path()).unwrap();

        assert_eq!(
            ctx.issuer_name().common_name.as_deref(),
            Some("Microsoft Windows Production PCA 2011")
        );
    }

    // ------------------------------------------------------------------
    // 4. sha1 / sha256 thumbprints
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_thumbprints() {
        let ctx = signed_context("/sbin/ping").unwrap();

        // If this begins to fail, Apple probably rotated their signing certificate
        assert_eq!(
            ctx.sha1_thumbprint(),
            "efdbc9139dd98dbae5a9c7165a096511b15eaef9"
        );
        assert_eq!(ctx.sha256_thumbprint().len(), 64);
    }

    #[test]
    #[cfg(windows)]
    fn test_thumbprints() {
        // Ask Windows itself for the signer certificate's thumbprints instead of relying on
        // hardcoded values, since Microsoft periodically rotates the signing certificate.
        let path = explorer_path();
        let ctx = signed_context(&path).unwrap();

        assert_eq!(ctx.sha1_thumbprint(), windows_signer_property(&path, "Thumbprint"));
        assert_eq!(ctx.sha256_thumbprint(), windows_sha256_thumbprint(&path));
    }

    // ------------------------------------------------------------------
    // 5. Serial number
    // ------------------------------------------------------------------

    #[test]
    #[cfg(target_os = "macos")]
    fn test_serial_number() {
        let ctx = signed_context("/sbin/ping").unwrap();
        assert!(ctx.serial().is_some());
    }

    #[test]
    #[cfg(windows)]
    fn test_serial_number() {
        // Ask Windows itself for the signer certificate's serial number instead of relying on
        // a hardcoded value, since Microsoft periodically rotates the signing certificate.
        let path = explorer_path();
        let ctx = signed_context(&path).unwrap();

        assert_eq!(
            ctx.serial().unwrap_or_default(),
            windows_signer_property(&path, "SerialNumber")
        );
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn signed_context(path: &str) -> Result<SignatureContext, Error> {
        super::CodeSignVerifier::for_file(path)?.verify()
    }

    #[cfg(windows)]
    fn explorer_path() -> String {
        format!("{}\\explorer.exe", std::env::var("windir").unwrap()) // Should always be present on Windows
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

        String::from_utf8_lossy(&output.stdout).trim().to_lowercase()
    }

    #[cfg(windows)]
    fn windows_signer_property(path: &str, property: &str) -> String {
        run_powershell(&format!(
            "(Get-AuthenticodeSignature -FilePath '{}').SignerCertificate.{}",
            path, property
        ))
    }

    #[cfg(windows)]
    fn windows_sha256_thumbprint(path: &str) -> String {
        run_powershell(&format!(
            "$c = (Get-AuthenticodeSignature -FilePath '{}').SignerCertificate; \
             [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)) -replace '-',''",
            path
        ))
    }
}
