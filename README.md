# verifysign
A Rust library providing a verifier for code signing in Windows and macOS.

## Description
The `verifysign` crate is an easy-to-use Rust library designed to verify the presence and authenticity of digital signatures on files. It provides developers with the tools to inspect and extract detailed signer information from digitally signed files, making it ideal for applications that require secure file validation, integrity checks, and certificate-based authentication.

## Key Features
- **Signature Verification:** Verify whether a file has a valid digital signature.
- **Signer Information Extraction:** Query and retrieve detailed information about the signer, including:
  - **Signer Name:** The name of the individual or organization that signed the file.
  - **Issuer Name:** The entity that issued the signer's certificate.
  - **Serial Number:** The unique identifier of the signer's certificate.
  - **Thumbprint:** The cryptographic hash of the certificate in both SHA1 and SHA256.
- **Cross-Platform Support:** Works seamlessly in both Windows and macOS, with the same output format on both.
- **Configurable Policy:** Revocation checking, network access, strict expiration and (on macOS) custom code requirements via `VerifyPolicy`. Revocation is not checked by default.

## Use Cases
- Verify the authenticity of downloaded files or software packages.
- Ensure the integrity of critical documents in secure workflows.
- Implement certificate-based authentication in enterprise applications.
- Audit and log signer information for compliance purposes.

## Example Usage
```rust
fn main() {
    #[cfg(target_os = "windows")]
    let path = format!("{}\\explorer.exe", std::env::var("windir").unwrap());
    #[cfg(target_os = "macos")]
    let path = format!("/sbin/ping");
    
    match verifysign::verify_file(&path) {
        Ok(signature) => {
            println!("File {} is signed",&path);
            println!("Signer:");
            println!("- Common Name: {}",signature.subject_name().common_name.unwrap_or(format!("N/A")));
            println!("- Country: {}",signature.subject_name().country.unwrap_or(format!("N/A")));
            println!("- Organization: {}",signature.subject_name().organization.unwrap_or(format!("N/A")));
            println!("- Organization Unit: {}",signature.subject_name().organization_unit.unwrap_or(format!("N/A")));
            println!("Issuer:");
            println!("- Common Name: {}",signature.issuer_name().common_name.unwrap_or(format!("N/A")));
            println!("- Country: {}",signature.issuer_name().country.unwrap_or(format!("N/A")));
            println!("- Organization: {}",signature.issuer_name().organization.unwrap_or(format!("N/A")));
            println!("- Organization Unit: {}",signature.issuer_name().organization_unit.unwrap_or(format!("N/A")));
            println!("Serial: {}",signature.serial().unwrap_or(format!("N/A")));
            println!("SHA1 Thumbprint: {}",signature.sha1_thumbprint());
            println!("SHA256 Thumbprint: {}",signature.sha256_thumbprint());
        }
        Err(verifysign::Error::Unsigned) => {
            eprintln!("File {} is unsigned",&path)
        }
        Err(e) => eprintln!("Error: {}",e),
    }
}
```

### Custom policy, many files
Build a `CodeSignVerifier` once and reuse it; it can be shared between threads.
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

## Migrating to 1.0
In 1.0, `CodeSignVerifier` holds the verification policy and is built once and reused, rather than being created for each file. The target now goes to the verify call:

| Before 1.0 | 1.0 |
|---|---|
| `CodeSignVerifier::for_file(path)?.verify()?` | `verifysign::verify_file(path)?` |
| `CodeSignVerifier::for_pid(pid)?.verify()?` | `verifysign::verify_pid(pid)?` |
| `CodeSignVerifier::for_file(path)?.policy(policy).verify()?` | `CodeSignVerifier::new(policy)?.verify_file(path)?` |
| `CodeSignVerifier::for_pid(pid)?.policy(policy).verify()?` | `CodeSignVerifier::new(policy)?.verify_pid(pid)?` |

When verifying several files, create the verifier once outside the loop and call `verify_file` on it for each file. On macOS, an invalid `requirement` in the policy is now reported by `CodeSignVerifier::new` instead of by each verification. `SignatureContext` and its methods are unchanged.

## Installation
Add the crate to your `Cargo.toml`:
```toml
[dependencies]
verifysign = "1"
```

## License
Licensed under the [BSD 3-Clause License](LICENSE). You may use, modify and redistribute it, including in commercial and closed-source projects, provided you keep the copyright notice and license text, and do not use the authors' names to endorse derived products. It is provided "as is", without warranty of any kind.

### Credit
This project was forked on 22 February 2025 from [codesign-verify-rs](https://github.com/vkrasnov/codesign-verify-rs) by Vlad Krasnov, which is also licensed under BSD 3-Clause.
