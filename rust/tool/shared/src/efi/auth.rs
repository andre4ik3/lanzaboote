//! Time-based authenticated variable updates (`EFI_VARIABLE_AUTHENTICATION_2`), the `.auth`
//! files systemd-boot enrolls from `loader/keys/<name>/`.
//!
//! ```text
//! EFI_TIME         TimeStamp                 (16 bytes)
//! WIN_CERTIFICATE_UEFI_GUID AuthInfo {
//!     u32  dwLength                          (header + CertType + CertData)
//!     u16  wRevision        = 0x0200
//!     u16  wCertificateType = WIN_CERT_TYPE_EFI_GUID (0x0ef1)
//!     GUID CertType         = EFI_CERT_TYPE_PKCS7_GUID
//!     u8   CertData[]       = PKCS#7 SignedData (DER, detached, no signed attributes)
//! }
//! u8 Data[]                                  (the new variable contents)
//! ```
//!
//! The signature covers `VariableName (UTF-16LE, no terminator) || VendorGuid || Attributes ||
//! TimeStamp || Data`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use tempfile::tempdir;

use super::Guid;
use crate::der;

/// `EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS |
/// TIME_BASED_AUTHENTICATED_WRITE_ACCESS`
pub const SECURE_BOOT_VARIABLE_ATTRIBUTES: u32 = 0x27;

const WIN_CERT_REVISION: u16 = 0x0200;
const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0ef1;

/// A Secure Boot variable an authenticated update can be built for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecureBootVariable {
    Pk,
    Kek,
    Db,
    Dbx,
}

impl SecureBootVariable {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pk => "PK",
            Self::Kek => "KEK",
            Self::Db => "db",
            Self::Dbx => "dbx",
        }
    }

    pub fn vendor(self) -> Guid {
        match self {
            Self::Pk | Self::Kek => Guid::GLOBAL_VARIABLE,
            Self::Db | Self::Dbx => Guid::IMAGE_SECURITY_DATABASE,
        }
    }
}

/// `EFI_TIME` for a UTC time, with the fields firmware compares (nanoseconds, time zone and
/// daylight are zero).
pub fn efi_time(time: time::OffsetDateTime) -> [u8; 16] {
    let time = time.to_offset(time::UtcOffset::UTC);
    let mut out = [0u8; 16];
    out[0..2].copy_from_slice(&(time.year() as u16).to_le_bytes());
    out[2] = u8::from(time.month());
    out[3] = time.day();
    out[4] = time.hour();
    out[5] = time.minute();
    out[6] = time.second();
    out
}

/// `EFI_TIME` of the current time, for a new authenticated update.
pub fn efi_time_now() -> [u8; 16] {
    efi_time(time::OffsetDateTime::now_utc())
}

/// The bytes the PKCS#7 signature of an authenticated update covers.
pub fn signed_payload(variable: SecureBootVariable, timestamp: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let name: Vec<u8> = variable
        .name()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    [
        &name[..],
        &variable.vendor().0,
        &SECURE_BOOT_VARIABLE_ATTRIBUTES.to_le_bytes(),
        timestamp,
        data,
    ]
    .concat()
}

/// Assemble an authenticated update from its timestamp, the DER SignedData and the new data.
pub fn assemble(timestamp: &[u8; 16], signed_data: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(8 + 16 + signed_data.len())?;
    let mut out = Vec::with_capacity(16 + length as usize + data.len());
    out.extend_from_slice(timestamp);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&WIN_CERT_REVISION.to_le_bytes());
    out.extend_from_slice(&WIN_CERT_TYPE_EFI_GUID.to_le_bytes());
    out.extend_from_slice(&Guid::CERT_TYPE_PKCS7.0);
    out.extend_from_slice(signed_data);
    out.extend_from_slice(data);
    Ok(out)
}

/// The `Data` part of an authenticated update (what the variable is set to).
pub fn data_of(update: &[u8]) -> Result<&[u8]> {
    ensure!(update.len() >= 16 + 8, "Truncated authenticated update");
    let length = u32::from_le_bytes(update[16..20].try_into().expect("4 bytes")) as usize;
    ensure!(
        length >= 24 && 16 + length <= update.len(),
        "Invalid authenticated update length {length}"
    );
    Ok(&update[16 + length..])
}

/// Build and sign an authenticated update of `variable` to `data`.
///
/// Signs with `openssl cms`, so `key` is anything OpenSSL can load: a PEM file, or a URI for a
/// provider configured through `OPENSSL_CONF` (e.g. `pkcs11:...` for a hardware token).
pub fn sign(
    variable: SecureBootVariable,
    data: &[u8],
    timestamp: &[u8; 16],
    key: &str,
    certificate: &Path,
) -> Result<Vec<u8>> {
    let dir = tempdir()?;
    let payload = dir.path().join("payload");
    let signature = dir.path().join("signature");
    std::fs::write(&payload, signed_payload(variable, timestamp, data))?;

    let output = Command::new("openssl")
        .args([
            "cms",
            "-sign",
            "-binary",
            "-noattr",
            "-nosmimecap",
            "-md",
            "sha256",
        ])
        .args(["-outform", "DER", "-inkey", key])
        .arg("-signer")
        .arg(certificate)
        .arg("-in")
        .arg(&payload)
        .arg("-out")
        .arg(&signature)
        .output()
        .context("Failed to run openssl. Most likely, the binary is not on PATH.")?;
    if !output.status.success() {
        bail!(
            "Failed to sign the {} update: {}",
            variable.name(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let content_info = std::fs::read(&signature)?;
    assemble(timestamp, signed_data_of(&content_info)?, data)
}

/// The SignedData inside a DER CMS `ContentInfo { contentType, [0] EXPLICIT SignedData }`.
///
/// `EFI_VARIABLE_AUTHENTICATION_2` carries the bare SignedData, while `openssl cms` emits the
/// ContentInfo around it.
fn signed_data_of(content_info: &[u8]) -> Result<&[u8]> {
    let outer = der::expect(content_info, 0x30).context("ContentInfo")?;
    let oid = der::expect(outer.contents, 0x06).context("contentType")?;
    let explicit = der::expect(&outer.contents[oid.len..], 0xa0).context("[0] content")?;
    let signed_data = der::expect(explicit.contents, 0x30).context("SignedData")?;
    Ok(&explicit.contents[..signed_data.len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn efi_time_matches_the_uefi_layout() {
        // 2026-09-23 12:34:56 UTC
        let t = time::OffsetDateTime::from_unix_timestamp(1_790_166_896).unwrap();
        assert_eq!(
            efi_time(t),
            [0xea, 0x07, 9, 23, 12, 34, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn payload_covers_name_vendor_attributes_time_and_data() {
        let ts = [7u8; 16];
        let payload = signed_payload(SecureBootVariable::Db, &ts, b"DATA");
        // "db" as UTF-16LE, no terminator
        assert_eq!(&payload[..4], b"d\0b\0");
        assert_eq!(&payload[4..20], &Guid::IMAGE_SECURITY_DATABASE.0);
        assert_eq!(&payload[20..24], &[0x27, 0, 0, 0]);
        assert_eq!(&payload[24..40], &ts);
        assert_eq!(&payload[40..], b"DATA");
    }

    #[test]
    fn assembled_update_round_trips_its_data() {
        let update = assemble(&[1; 16], &[0x30, 0x00], b"payload").unwrap();
        assert_eq!(u32::from_le_bytes(update[16..20].try_into().unwrap()), 26);
        assert_eq!(&update[20..22], &[0x00, 0x02]);
        assert_eq!(&update[22..24], &[0xf1, 0x0e]);
        assert_eq!(&update[24..40], &Guid::CERT_TYPE_PKCS7.0);
        assert_eq!(data_of(&update).unwrap(), b"payload");
    }

    #[test]
    fn unwraps_signed_data_from_content_info() {
        // ContentInfo { OID 1.2.840.113549.1.7.2, [0] { SEQUENCE { INTEGER 1 } } }
        let signed_data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ];
        let explicit = [&[0xa0, signed_data.len() as u8][..], &signed_data].concat();
        let body = [&oid[..], &explicit].concat();
        let content_info = [&[0x30, body.len() as u8][..], &body].concat();
        assert_eq!(signed_data_of(&content_info).unwrap(), &signed_data);
    }
}
