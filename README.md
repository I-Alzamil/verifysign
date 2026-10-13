# verifysign

[![crates.io](https://img.shields.io/crates/v/verifysign.svg)](https://crates.io/crates/verifysign)
[![docs.rs](https://docs.rs/verifysign/badge.svg)](https://docs.rs/verifysign)
[![CI](https://github.com/I-Alzamil/verifysign/actions/workflows/ci.yml/badge.svg)](https://github.com/I-Alzamil/verifysign/actions/workflows/ci.yml)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

Verify the digital code signature of files and running processes on **Windows** and **macOS**, and read who signed them.

`verifysign` asks the operating system to verify the signature (WinTrust on Windows, the Security framework on macOS), then gives you details of the signing certificate in the same format on both platforms.

## Features
- **Verify files and running processes**, including Windows files signed through system catalogs rather than an embedded signature.
- **Signer details** from the signing (leaf) certificate:
  - subject and issuer names (common name, organization, organizational unit, country)
  - serial number
  - SHA-1 and SHA-256 thumbprints
- **Configurable policy**: revocation checking, network access, strict expiration, and on macOS custom code requirements.
- **Reusable and thread-safe**: build a verifier once and share it between threads.
- **No extra dependencies** beyond the platform bindings (`windows-sys`, `core-foundation`).

## Installation
```toml
[dependencies]
verifysign = "1"
```

Supported targets are Windows and macOS. On any other target the crate fails to compile with a clear error. The minimum supported Rust version is 1.85.

## Usage

### Verify a file
```rust
use verifysign::{Error, Name};

fn print_name(label: &str, name: &Name) {
    let field = |value: &Option<String>| value.as_deref().unwrap_or("N/A").to_string();

    println!("{label}:");
    println!("  Common name:       {}", field(&name.common_name));
    println!("  Organization:      {}", field(&name.organization));
    println!("  Organization unit: {}", field(&name.organization_unit));
    println!("  Country:           {}", field(&name.country));
}

fn main() {
    #[cfg(windows)]
    let path = format!("{}\\explorer.exe", std::env::var("windir").unwrap());
    #[cfg(target_os = "macos")]
    let path = String::from("/sbin/ping");

    match verifysign::verify_file(&path) {
        Ok(signature) => {
            println!("{path} is signed");
            print_name("Signer", &signature.subject_name());
            print_name("Issuer", &signature.issuer_name());
            println!("Serial:             {}", signature.serial().unwrap_or_default());
            println!("SHA-1 thumbprint:   {}", signature.sha1_thumbprint());
            println!("SHA-256 thumbprint: {}", signature.sha256_thumbprint());
        }
        Err(Error::Unsigned) => println!("{path} is not signed"),
        Err(e) => eprintln!("could not verify {path}: {e}"),
    }
}
```

### Verify a running process
```rust
let signature = verifysign::verify_pid(std::process::id())?;
```
A PID is not a stable identity, so read the [security notes](#security-notes) before relying on this.

### Use a policy and verify many files
Build a `CodeSignVerifier` once and reuse it. It is cheap to clone and can be shared between threads.
```rust
use verifysign::{CodeSignVerifier, Revocation, VerifyPolicy};

fn main() -> Result<(), verifysign::Error> {
    let policy = VerifyPolicy::new()
        .revocation(Revocation::Chain)
        .allow_network(true);
    let verifier = CodeSignVerifier::new(policy)?;

    for path in std::env::args().skip(1) {
        match verifier.verify_file(&path) {
            Ok(signature) => println!("{path}: signed by {:?}", signature.subject_name().common_name),
            Err(e) => println!("{path}: {e}"),
        }
    }
    Ok(())
}
```

### Check who signed it
A valid signature only means *someone* with a trusted certificate signed the file. To accept only a specific publisher, compare the certificate's thumbprint with one you trust:
```rust
const TRUSTED_SHA256: &str = "…"; // Lowercase hex, as returned by sha256_thumbprint()

let signature = verifysign::verify_file("C:/Program Files/MyApp/updater.exe")?;
if signature.sha256_thumbprint() != TRUSTED_SHA256 {
    panic!("signed, but not by us");
}
```
Pinning a thumbprint breaks when the publisher renews its certificate. Comparing names, such as `subject_name().organization`, survives renewal but is weaker, because names are not unique. On macOS, a code requirement is the most robust option:
```rust
// Signed through Apple's developer program by one specific team
let policy = VerifyPolicy::new()
    .requirement(r#"anchor apple generic and certificate leaf[subject.OU] = "TEAMID1234""#);
```

## Verification policy
| Option | Default | Effect |
|---|---|---|
| `revocation(Revocation)` | `None` | Check certificates for revocation: `EndCertificate` (signing certificate only) or `Chain` (all but the root). macOS has no leaf-only mode, so `EndCertificate` behaves like `Chain`. |
| `allow_network(bool)` | platform decides | Allow or forbid network access, for example to fetch revocation lists. On Windows the network is used by default only when revocation is checked; on macOS the Security framework decides. |
| `strict_expiration(bool)` | `false` | Reject expired certificates even if the file was timestamped while they were valid. Many OS-supplied Windows files are signed with since-expired certificates, so this rejects them. |
| `requirement(&str)` (macOS) | `anchor trusted` | The [code requirement](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html) the signature must satisfy. |
| `check_all_architectures(bool)` (macOS) | `true` | Validate every architecture of a universal binary, not just the host's. |

**Revocation is not checked by default**, so a file signed with a since-revoked certificate still verifies. Enable it if that matters to you; it is slower and usually needs network access.

## Platform behavior

**Windows** uses `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`. If a file has no embedded signature, or is a type that can't embed one (such as `.inf`), it is looked up in the system catalogs by SHA-256 and then SHA-1 hash. A process is verified through the executable file it was started from.

**macOS** uses the Security framework's code signing services and works with both binaries and application bundles. On Apple Silicon the linker gives every binary an ad-hoc signature, which carries no certificate; such binaries are reported as `Unsigned`.

## Errors
| Variant | Meaning |
|---|---|
| `Unsigned` | The file or process has no signature. |
| `OsError(i32)` | The platform reported an error: an `HRESULT` on Windows, an `OSStatus` on macOS. This includes an invalid signature, for example `TRUST_E_BAD_DIGEST` for a modified file. |
| `InvalidPath` | The path is malformed. |
| `LeafCertNotFound` | The signature is valid but the signing certificate could not be read. |
| `CFError(String)` (macOS) | A Core Foundation error, for example a requirement that fails to parse or isn't satisfied. |

`Error` is `#[non_exhaustive]`, so `match` on it needs a `_` arm.

## Security notes
- **A PID is not a stable identity.** The process may exit and its PID be reused between the time you get the PID and the time you verify it. On Windows, the executable *file on disk* is verified, not the image running in memory, so a file replaced after launch is not detected. Don't rely on `verify_pid` alone to authenticate a peer, such as the other end of a pipe.
- **Files are verified by path.** Anyone who can write to the file can replace it between verifying it and using it, so only rely on verifying files in locations that untrusted users can't write to.

## Migrating from 0.2
In 1.0, `CodeSignVerifier` holds the verification policy and is built once and reused, rather than being created for each file. The file or PID now goes to the verify call:

| 0.2 | 1.0 |
|---|---|
| `CodeSignVerifier::for_file(path)?.verify()?` | `verifysign::verify_file(path)?` |
| `CodeSignVerifier::for_pid(pid)?.verify()?` | `verifysign::verify_pid(pid)?` |

To use a [policy](#verification-policy), which is new in 1.0, build a verifier with `CodeSignVerifier::new(policy)?` and call `verify_file` or `verify_pid` on it.

Other changes that can affect existing code:
- **`Error`:**
  - The `IoError` variant was removed.
  - `CFError` exists only on macOS.
  - The enum is now `#[non_exhaustive]`, so a `match` on it needs a `_` arm.
  - It now implements `Display` and `std::error::Error`.
- **Windows error codes:** `OsError` always holds an `HRESULT`. Win32 errors are converted to their `0x8007xxxx` form; for example, an invalid PID gives `E_INVALIDARG` instead of `87`.
- **`serial()` on macOS** returns lowercase big-endian hex of the DER-encoded serial number, the same format as on Windows. It may start with `00`. In 0.2 it returned the Security framework's display string, so compare carefully against serial numbers you stored with 0.2.
- **Verification results:**
  - On macOS, ad-hoc signed binaries (every unsigned build on Apple Silicon) are reported as `Unsigned` instead of an error.
  - On macOS, every architecture of a universal binary is validated by default, so a binary with one bad architecture now fails. Use `check_all_architectures(false)` to validate only the host's.
  - On Windows, the catalogs are also searched by SHA-1 hash and across every catalog that lists the file, so some files that failed in 0.2 now verify.
  - On Windows, files of a type that can't embed a signature are checked against the catalogs. If no catalog lists them, they return `Unsigned` instead of `OsError`.

## License
Licensed under the [BSD 3-Clause License](LICENSE). You may use, modify and redistribute it, including in commercial and closed-source projects, provided you keep the copyright notice and license text, and do not use the authors' names to endorse derived products. It is provided "as is", without warranty of any kind.

### Credit
This project was forked on 22 February 2025 from [codesign-verify-rs](https://github.com/vkrasnov/codesign-verify-rs) by Vlad Krasnov, which is also licensed under BSD 3-Clause.
