use super::osx::*;
use crate::{Name, to_hex};

pub(crate) struct Context {
    cert: SecCertificate,
    // The certificate's decoded values, keyed by OID. `None` if the Security framework
    // couldn't decode them, in which case name lookups come back empty.
    values: Option<CFDictionary>,
}

// SAFETY: both fields are immutable CF objects that are never mutated after creation;
// immutable CF objects may be shared, read and released from any thread.
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

/// Wraps one of the Security framework's constant `CFStringRef` keys.
fn key(key: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(key) }
}

/// Looks up `key` in an untyped dictionary as a `T`, or `None` if it's absent or isn't a `T`.
/// The type check matters: the values come from parsing an arbitrary certificate.
fn lookup<T: ConcreteCFType>(dict: &CFDictionary, key: &CFString) -> Option<T> {
    let value = dict.find(key.as_CFTypeRef())?;
    unsafe { CFType::wrap_under_get_rule(*value as CFTypeRef) }.downcast_into()
}

impl Context {
    pub fn new(cert: &SecCertificate) -> Self {
        let values = unsafe {
            SecCertificateCopyValues(cert.as_concrete_TypeRef(), std::ptr::null(), None)
        };

        Context {
            cert: cert.clone(),
            values: (!values.is_null())
                .then(|| unsafe { CFDictionary::wrap_under_create_rule(values) }),
        }
    }

    /// Returns the value array of a "section" property such as the subject or issuer name.
    fn section(&self, oid: CFStringRef) -> Option<CFArray> {
        let property: CFDictionary = lookup(self.values.as_ref()?, &key(oid))?;
        lookup(&property, &key(unsafe { kSecPropertyKeyValue }))
    }

    /// Finds the string value labelled with `oid` among a section's entries.
    fn section_string(section: &CFArray, oid: CFStringRef) -> Option<String> {
        let (label_key, value_key) = unsafe {
            (key(kSecPropertyKeyLabel), key(kSecPropertyKeyValue))
        };
        let wanted = key(oid);

        section.iter().find_map(|entry| {
            let entry = unsafe { CFType::wrap_under_get_rule(*entry as CFTypeRef) }
                .downcast_into::<CFDictionary>()?;
            let label: CFString = lookup(&entry, &label_key)?;

            if label != wanted {
                return None;
            }
            lookup::<CFString>(&entry, &value_key).map(|v| v.to_string())
        })
    }

    fn name_for_field(&self, field: CFStringRef) -> Name {
        let Some(section) = self.section(field) else {
            return Name::default();
        };
        let get = |oid| Self::section_string(&section, oid);

        unsafe {
            Name {
                common_name: get(kSecOIDCommonName),
                country: get(kSecOIDCountryName),
                organization: get(kSecOIDOrganizationName),
                organization_unit: get(kSecOIDOrganizationalUnitName),
            }
        }
    }

    pub fn serial(&self) -> Option<String> {
        let data = unsafe { SecCertificateCopySerialNumberData(self.cert.as_concrete_TypeRef(), None) };
        if data.is_null() {
            return None;
        }

        let data = unsafe { CFData::wrap_under_create_rule(data) };
        Some(to_hex(data.bytes()))
    }

    pub fn subject_name(&self) -> Name {
        self.name_for_field(unsafe { kSecOIDX509V1SubjectName })
    }

    pub fn issuer_name(&self) -> Name {
        self.name_for_field(unsafe { kSecOIDX509V1IssuerName })
    }

    fn cert_data(&self) -> CFData {
        unsafe { CFData::wrap_under_create_rule(SecCertificateCopyData(self.cert.as_concrete_TypeRef())) }
    }

    pub fn sha1_thumbprint(&self) -> String {
        let data = self.cert_data();
        let bytes = data.bytes();
        let mut hash = [0u8; CC_SHA1_DIGEST_LENGTH];
        unsafe { CC_SHA1(bytes.as_ptr() as *const _, bytes.len() as CC_LONG, hash.as_mut_ptr()) };

        to_hex(&hash)
    }

    pub fn sha256_thumbprint(&self) -> String {
        let data = self.cert_data();
        let bytes = data.bytes();
        let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
        unsafe { CC_SHA256(bytes.as_ptr() as *const _, bytes.len() as CC_LONG, hash.as_mut_ptr()) };

        to_hex(&hash)
    }
}
