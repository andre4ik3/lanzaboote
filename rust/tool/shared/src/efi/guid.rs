//! EFI GUIDs: `uguid`'s, which stores them in their on-disk (mixed-endian) byte order.

pub use uguid::{Guid, guid};

/// `EFI_GLOBAL_VARIABLE`: vendor GUID of `PK`, `KEK` and `SecureBoot`.
pub const GLOBAL_VARIABLE: Guid = guid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");

/// `EFI_IMAGE_SECURITY_DATABASE_GUID`: vendor GUID of `db` and `dbx`.
pub const IMAGE_SECURITY_DATABASE: Guid = guid!("d719b2cb-3d3a-4596-a3bc-dad00e67656f");

/// `EFI_CERT_X509_GUID`: signature type of an X.509 certificate entry.
pub const CERT_X509: Guid = guid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");

/// `EFI_CERT_TYPE_PKCS7_GUID`: certificate type of an authenticated variable update.
pub const CERT_TYPE_PKCS7: Guid = guid!("4aafd29d-68df-49ee-8aa9-347d375665a7");

/// A random (version 4) GUID, e.g. a signature owner.
pub fn random() -> Guid {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).expect("Failed to get random bytes from the OS");
    Guid::from_random_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_the_first_fields_little_endian() {
        // As it appears in an efivarfs file name and in the first 16 bytes of a signature list.
        assert_eq!(
            GLOBAL_VARIABLE.to_bytes(),
            [
                0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03,
                0x2b, 0x8c
            ]
        );
        assert_eq!(
            GLOBAL_VARIABLE.to_string(),
            "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
    }

    #[test]
    fn random_guids_are_version_4() {
        let guid = random();
        assert_ne!(guid, random());
        assert_eq!(guid.version(), 4);
    }
}
