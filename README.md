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
- **Cross-Platform Support:** Works seamlessly in both Windows and macOS.

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
    
    match verifysign::CodeSignVerifier::for_file(&path) {
        Ok(valid_file) => {
            match valid_file.verify() {
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
                Err(e) => eprintln!("Error: {:?}",e),
            }
        }
        Err(e) => eprintln!("Fatal Error: {:?}",e),
    }
}
```

## Installation
Add the crate to your `Cargo.toml`:
```toml
[dependencies]
verifysign = "*"
```

## License
This crate is distributed under the BSD 3-Clause License, making it free to use, modify, and distribute in both open-source and commercial projects. Whether you're building secure software, auditing tools, or compliance systems, `verifysign` provides the functionality you need to ensure file integrity and authenticity with ease.

### Credit
This project was forked from [codesign-verify-rs](https://github.com/vkrasnov/codesign-verify-rs) in 22/02/2025 credit to Vlad Krasnov.
