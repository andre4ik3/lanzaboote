use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result};
use uuid::Uuid;

/// An EFI GUID, stored in its on-disk (mixed-endian) byte order.
///
/// The first three fields are little-endian, the last eight bytes are stored as written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// `EFI_GLOBAL_VARIABLE`: vendor GUID of `PK`, `KEK` and `SecureBoot`.
    pub const GLOBAL_VARIABLE: Guid =
        Guid::from_uuid(uuid::uuid!("8be4df61-93ca-11d2-aa0d-00e098032b8c"));

    /// `EFI_IMAGE_SECURITY_DATABASE_GUID`: vendor GUID of `db` and `dbx`.
    pub const IMAGE_SECURITY_DATABASE: Guid =
        Guid::from_uuid(uuid::uuid!("d719b2cb-3d3a-4596-a3bc-dad00e67656f"));

    /// `EFI_CERT_X509_GUID`: signature type of an X.509 certificate entry.
    pub const CERT_X509: Guid =
        Guid::from_uuid(uuid::uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072"));

    /// `EFI_CERT_TYPE_PKCS7_GUID`: certificate type of an authenticated variable update.
    pub const CERT_TYPE_PKCS7: Guid =
        Guid::from_uuid(uuid::uuid!("4aafd29d-68df-49ee-8aa9-347d375665a7"));

    const fn from_uuid(uuid: Uuid) -> Self {
        Guid(uuid.to_bytes_le())
    }

    /// A random (version 4) GUID, e.g. a signature owner.
    pub fn new_random() -> Self {
        Self::from_uuid(Uuid::new_v4())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Guid(bytes.try_into().context("A GUID is 16 bytes")?))
    }
}

impl FromStr for Guid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let uuid = Uuid::try_parse(s).with_context(|| format!("Invalid GUID {s:?}"))?;
        Ok(Self::from_uuid(uuid))
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Uuid::from_bytes_le(self.0).hyphenated().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_string_form() {
        let s = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
        let guid: Guid = s.parse().unwrap();
        assert_eq!(guid, Guid::GLOBAL_VARIABLE);
        assert_eq!(guid.to_string(), s);
    }

    #[test]
    fn stores_the_first_fields_little_endian() {
        // As it appears in an efivarfs file name and in the first 16 bytes of a signature list.
        assert_eq!(
            Guid::GLOBAL_VARIABLE.0,
            [
                0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03,
                0x2b, 0x8c
            ]
        );
    }

    #[test]
    fn random_guids_are_version_4() {
        let guid = Guid::new_random();
        assert_ne!(guid, Guid::new_random());
        assert_eq!(Uuid::from_bytes_le(guid.0).get_version_num(), 4);
    }

    #[test]
    fn rejects_malformed_strings() {
        assert!("8be4df61-93ca-11d2-aa0d".parse::<Guid>().is_err());
        assert!(
            "zzzzzzzz-93ca-11d2-aa0d-00e098032b8c"
                .parse::<Guid>()
                .is_err()
        );
    }
}
