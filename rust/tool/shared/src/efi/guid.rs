use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};

/// An EFI GUID, stored in its on-disk (mixed-endian) byte order.
///
/// The first three fields are little-endian, the last eight bytes are stored as written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// `EFI_GLOBAL_VARIABLE`: vendor GUID of `PK`, `KEK` and `SecureBoot`.
    pub const GLOBAL_VARIABLE: Guid = Guid::from_fields(
        0x8be4df61,
        0x93ca,
        0x11d2,
        [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    );

    /// `EFI_IMAGE_SECURITY_DATABASE_GUID`: vendor GUID of `db` and `dbx`.
    pub const IMAGE_SECURITY_DATABASE: Guid = Guid::from_fields(
        0xd719b2cb,
        0x3d3a,
        0x4596,
        [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    );

    /// `EFI_CERT_X509_GUID`: signature type of an X.509 certificate entry.
    pub const CERT_X509: Guid = Guid::from_fields(
        0xa5c059a1,
        0x94e4,
        0x4aa7,
        [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
    );

    /// `EFI_CERT_TYPE_PKCS7_GUID`: certificate type of an authenticated variable update.
    pub const CERT_TYPE_PKCS7: Guid = Guid::from_fields(
        0x4aafd29d,
        0x68df,
        0x49ee,
        [0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7],
    );

    pub const fn from_fields(a: u32, b: u16, c: u16, d: [u8; 8]) -> Self {
        let a = a.to_le_bytes();
        let b = b.to_le_bytes();
        let c = c.to_le_bytes();
        Guid([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5],
            d[6], d[7],
        ])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Guid(bytes.try_into().context("A GUID is 16 bytes")?))
    }
}

impl FromStr for Guid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        let [a, b, c, d, e] = parts[..] else {
            bail!("Invalid GUID {s:?}: expected 5 groups");
        };
        if [a.len(), b.len(), c.len(), d.len(), e.len()] != [8, 4, 4, 4, 12] {
            bail!("Invalid GUID {s:?}: wrong group lengths");
        }
        let hex = |group: &str| -> Result<Vec<u8>> {
            (0..group.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&group[i..i + 2], 16))
                .collect::<Result<_, _>>()
                .with_context(|| format!("Invalid GUID {s:?}: not hexadecimal"))
        };
        let tail: [u8; 8] = [hex(d)?, hex(e)?].concat().try_into().expect("8 bytes");
        Ok(Guid::from_fields(
            u32::from_str_radix(a, 16)?,
            u16::from_str_radix(b, 16)?,
            u16::from_str_radix(c, 16)?,
            tail,
        ))
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
            u16::from_le_bytes([g[4], g[5]]),
            u16::from_le_bytes([g[6], g[7]]),
            g[8],
            g[9],
            g[10],
            g[11],
            g[12],
            g[13],
            g[14],
            g[15]
        )
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
    fn rejects_malformed_strings() {
        assert!("8be4df61-93ca-11d2-aa0d".parse::<Guid>().is_err());
        assert!(
            "8be4df6-193ca-11d2-aa0d-00e098032b8c"
                .parse::<Guid>()
                .is_err()
        );
        assert!(
            "zzzzzzzz-93ca-11d2-aa0d-00e098032b8c"
                .parse::<Guid>()
                .is_err()
        );
    }
}
