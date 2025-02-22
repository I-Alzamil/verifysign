# verifysign

A rust cargo used to verify digital code signature on files.

This cargo aims to provide a way for developers to check if a file is signed or not. As well as give them the ability to query the signer information.

## How to use

The following code demonstrate how you could use this crate to help with verifying the signature:

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

## Credit

This project was forked from (codesign-verify-rs)[https://github.com/vkrasnov/codesign-verify-rs] in 22/02/2025 credit to Vlad Krasnov.
