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

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use x509_cert::der::{Decode, Encode};

use super::Guid;

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
/// Signs with `openssl smime`, so `key` is anything OpenSSL can load: a PEM file, or a URI for a
/// provider configured through `OPENSSL_CONF` (e.g. `pkcs11:...` for a hardware token).
///
/// `smime` rather than `cms`: `cms` leaves the digest algorithm parameters out, and some AMI
/// firmware rejects such updates with a security violation. `smime` writes them as NULL, like
/// efitools' `sign-efi-sig-list`.
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
            "smime",
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
    assemble(timestamp, &signed_data_of(&content_info)?, data)
}

/// The SignedData inside a DER CMS `ContentInfo`, as the bytes `openssl cms` wrote.
///
/// `EFI_VARIABLE_AUTHENTICATION_2` carries the bare SignedData, while `openssl cms` emits the
/// ContentInfo around it.
fn signed_data_of(content_info: &[u8]) -> Result<Vec<u8>> {
    let content_info = ContentInfo::from_der(content_info).context("Invalid CMS ContentInfo")?;
    ensure!(
        content_info.content_type == const_oid::db::rfc5911::ID_SIGNED_DATA,
        "The CMS ContentInfo does not hold SignedData"
    );
    // Validate, but pass on the original encoding: `Any` keeps the value's bytes as they were.
    let _: SignedData = content_info.content.decode_as()?;
    Ok(content_info.content.to_der()?)
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

    /// Signs a db update with the test fixture key through `openssl smime`, like `authorize`.
    #[test]
    fn signs_an_update_openssl_can_verify() {
        let fixtures = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../systemd/tests/fixtures/uefi-keys"
        );
        let (key, cert) = (format!("{fixtures}/db.key"), format!("{fixtures}/db.pem"));
        let timestamp = efi_time(time::OffsetDateTime::from_unix_timestamp(1_790_166_896).unwrap());
        let update = sign(
            SecureBootVariable::Db,
            b"DATA",
            &timestamp,
            &key,
            Path::new(&cert),
        )
        .unwrap();
        assert_eq!(data_of(&update).unwrap(), b"DATA");

        // The certificate data is a bare SignedData that verifies against the payload.
        let length = u32::from_le_bytes(update[16..20].try_into().unwrap()) as usize;
        let signed_data = SignedData::from_der(&update[40..16 + length]).unwrap();
        // Digest algorithms carry NULL parameters: firmware that wants them rejects the update.
        let null = Some(x509_cert::der::Any::null());
        assert!(
            signed_data
                .digest_algorithms
                .iter()
                .chain(signed_data.signer_infos.0.iter().map(|s| &s.digest_alg))
                .all(|alg| alg.parameters == null)
        );
        let wrapped = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: x509_cert::der::Any::encode_from(&signed_data).unwrap(),
        };
        let dir = tempdir().unwrap();
        let (p7, payload) = (dir.path().join("p7"), dir.path().join("payload"));
        std::fs::write(&p7, wrapped.to_der().unwrap()).unwrap();
        std::fs::write(
            &payload,
            signed_payload(SecureBootVariable::Db, &timestamp, b"DATA"),
        )
        .unwrap();
        let status = Command::new("openssl")
            .args([
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-noverify",
                "-in",
            ])
            .arg(&p7)
            .arg("-content")
            .arg(&payload)
            .args(["-out", "/dev/null"])
            .status()
            .unwrap();
        assert!(status.success());
    }
}
