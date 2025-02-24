pub use core_foundation::array::{CFArray, CFArrayRef};
pub use core_foundation::base::{CFType, CFTypeID, OSStatus, TCFType};
pub use core_foundation::data::{CFData, CFDataRef};
pub use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
pub use core_foundation::error::{CFError, CFErrorRef};
pub use core_foundation::number::CFNumber;
pub use core_foundation::string::{CFString, CFStringRef};
pub use core_foundation::url::{CFURLRef, CFURL};
pub use core_foundation::{declare_TCFType, impl_CFTypeDescription, impl_TCFType};

pub const errSecSuccess: OSStatus = 0;
pub const errSecCSUnsigned: OSStatus = -67062;

pub struct __SecCode {}
pub struct __SecStaticCode {}
pub struct __SecCertificate {}
pub struct __SecRequirement {}

pub type SecCertificateRef = *const __SecCertificate;
pub type SecCodeRef = *const __SecCode;
pub type SecStaticCodeRef = *const __SecStaticCode;
pub type SecRequirementRef = *const __SecRequirement;

unsafe extern "C" {
    pub unsafe fn SecCertificateGetTypeID() -> CFTypeID;
    pub unsafe fn SecCodeGetTypeID() -> CFTypeID;
    pub unsafe fn SecStaticCodeGetTypeID() -> CFTypeID;
    pub unsafe fn SecRequirementGetTypeID() -> CFTypeID;
}

declare_TCFType!(SecCertificate, SecCertificateRef);
impl_TCFType!(SecCertificate, SecCertificateRef, SecCertificateGetTypeID);
impl_CFTypeDescription!(SecCertificate);

declare_TCFType!(SecCode, SecCodeRef);
impl_TCFType!(SecCode, SecCodeRef, SecCodeGetTypeID);
impl_CFTypeDescription!(SecCode);

declare_TCFType!(SecStaticCode, SecStaticCodeRef);
impl_TCFType!(SecStaticCode, SecStaticCodeRef, SecStaticCodeGetTypeID);
impl_CFTypeDescription!(SecStaticCode);

declare_TCFType!(SecRequirement, SecRequirementRef);
impl_TCFType!(SecRequirement, SecRequirementRef, SecRequirementGetTypeID);
impl_CFTypeDescription!(SecRequirement);

#[repr(u32)]
#[allow(dead_code, non_camel_case_types)]
pub enum SecCSFlags {
    kSecCSDefaultFlags = 0,
    kSecCSSigningInformation = 1 << 1,
    kSecCSConsiderExpiration = 1 << 31,
    kSecCSEnforceRevocationChecks = 1 << 30,
    kSecCSCheckTrustedAnchors = 1 << 27,
    kSecCSNoNetworkAccess = 1 << 29,
    kSecCSReportProgress = 1 << 28,
    kSecCSQuickCheck = 1 << 26,
}

#[allow(improper_ctypes)]
#[cfg_attr(
    any(target_os = "macos", target_os = "ios"),
    link(name = "Security", kind = "framework")
)]
unsafe extern "C" {
    pub unsafe fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: SecCSFlags,
        guest: Option<&mut SecCodeRef>,
    ) -> OSStatus;

    pub unsafe fn SecStaticCodeCreateWithPath(
        path: CFURLRef,
        flags: SecCSFlags,
        static_code: Option<&mut SecStaticCodeRef>,
    ) -> OSStatus;

    pub unsafe fn SecCodeCheckValidityWithErrors(
        code: SecCodeRef,
        flags: SecCSFlags,
        requirement: SecRequirementRef,
        errors: Option<&mut CFErrorRef>,
    ) -> OSStatus;

    pub unsafe fn SecStaticCodeCheckValidityWithErrors(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        requirement: SecRequirementRef,
        errors: Option<&mut CFErrorRef>,
    ) -> OSStatus;

    pub unsafe fn SecRequirementCreateWithStringAndErrors(
        text: CFStringRef,
        flags: SecCSFlags,
        errors: Option<&mut CFErrorRef>,
        requirement: Option<&mut SecRequirementRef>,
    ) -> OSStatus;

    pub unsafe fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: Option<&mut CFDictionaryRef>,
    ) -> OSStatus;

    pub unsafe fn SecCertificateCopyData(certificate: SecCertificateRef) -> CFDataRef;

    pub unsafe fn SecCertificateCopyValues(
        certificate: SecCertificateRef,
        keys: CFArrayRef,
        errors: Option<&mut CFErrorRef>,
    ) -> CFDictionaryRef;

    pub unsafe static kSecGuestAttributePid: CFStringRef;
    pub unsafe static kSecCodeInfoCertificates: CFStringRef;

    pub unsafe static kSecPropertyKeyValue: CFStringRef;
    pub unsafe static kSecPropertyKeyLabel: CFStringRef;
    pub unsafe static kSecPropertyKeyType: CFStringRef;

    pub unsafe static kSecOIDX509V1SubjectName: CFStringRef;
    pub unsafe static kSecOIDX509V1IssuerName: CFStringRef;
    pub unsafe static kSecOIDX509V1SerialNumber: CFStringRef;

    pub unsafe static kSecOIDCountryName: CFStringRef;
    pub unsafe static kSecOIDCommonName: CFStringRef;
    pub unsafe static kSecOIDOrganizationalUnitName: CFStringRef;
    pub unsafe static kSecOIDOrganizationName: CFStringRef;
}
