//! Keys held by a TPM, in the TSS2 key file format of openssl_tpm2_engine
//! (`-----BEGIN TSS2 PRIVATE KEY-----`).
//!
//! A key file is a wrapped blob only the TPM that created it can load. Keys are created with a
//! signed policy: they are usable only in a state (e.g. a PCR 7 value) that an approver key has
//! signed an approval for. Approvals are stored in the key file itself.
//!
//! Creating keys and adding approvals shells out to the engine's tools, the same way signing
//! goes through its OpenSSL provider; only reading the public half is done here, because it
//! needs no TPM.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use sha2::Digest;
use tss_esapi::structures::Public;
use tss_esapi::traits::UnMarshall;
use x509_cert::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::der::{Any, Decode, EncodePem, Reader, SliceReader, Tag, Tagged, pem};
use x509_cert::spki::SubjectPublicKeyInfoOwned;

const TPM_CC_POLICY_PCR: u32 = 0x0000_017f;
const TPM_CC_POLICY_COUNTER_TIMER: u32 = 0x0000_016d;
const TPM_ALG_SHA256: u16 = 0x000b;
/// `id-loadablekey`: the `type` of a TSS2 key file for a key loaded under a parent.
const TSS2_LOADABLE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.10.1.3");
const TPM_EO_UNSIGNED_LE: u16 = 0x0009;
/// Offset of `clockInfo.clock` in `TPMS_TIME_INFO` (after `time`, a UINT64).
const CLOCK_OFFSET: u16 = 8;

/// Create an RSA 2048 key in the TPM, usable only under policies signed by `approver`
/// (a PEM public key).
pub fn create(key_file: &Path, approver: &Path) -> Result<()> {
    run(Command::new("create_tpm2_key")
        .args(["--rsa", "--key-size", "2048", "--signed-policy"])
        .arg(approver)
        .arg(key_file))
}

/// Add an approval to a key: `policy` is a policy file (see [`Policy`]), signed with `approver`
/// (anything OpenSSL can load: a PEM file, or e.g. a `pkcs11:` URI through `OPENSSL_CONF`).
pub fn approve(key_file: &Path, name: &str, policy: &Path, approver: &str) -> Result<()> {
    run(Command::new("signed_tpm2_policy")
        .args(["add", "-n", name, "-c"])
        .arg(policy)
        .arg(key_file)
        .arg(approver))
}

fn run(command: &mut Command) -> Result<()> {
    let program = command.get_program().to_string_lossy().into_owned();
    let output = command.output().with_context(|| {
        format!("Failed to run {program}. Most likely, the binary is not on PATH.")
    })?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// A policy an approver signs, as a sequence of TPM policy commands. Serializes to the
/// engine's policy file format: one hex-encoded command (code + parameters) per line.
#[derive(Default)]
pub struct Policy(Vec<Vec<u8>>);

impl Policy {
    /// `TPM2_PolicyPCR`: the given SHA-256 PCRs have exactly these values.
    pub fn pcrs(mut self, pcrs: &[(u8, [u8; 32])]) -> Self {
        let mut sorted = pcrs.to_vec();
        sorted.sort_by_key(|(index, _)| *index);
        let mut bitmap = [0u8; 3];
        for (index, _) in &sorted {
            bitmap[*index as usize / 8] |= 1 << (index % 8);
        }
        let digest = sha2::Sha256::digest(sorted.iter().flat_map(|(_, v)| *v).collect::<Vec<_>>());
        let mut command = TPM_CC_POLICY_PCR.to_be_bytes().to_vec();
        command.extend_from_slice(&1u32.to_be_bytes()); // TPML_PCR_SELECTION.count
        command.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        command.push(bitmap.len() as u8);
        command.extend_from_slice(&bitmap);
        command.extend_from_slice(&digest);
        self.0.push(command);
        self
    }

    /// `TPM2_PolicyCounterTimer`: the TPM clock (milliseconds, only moves forward) is at most
    /// `clock`.
    pub fn until_clock(mut self, clock: u64) -> Self {
        let mut command = TPM_CC_POLICY_COUNTER_TIMER.to_be_bytes().to_vec();
        command.extend_from_slice(&clock.to_be_bytes());
        command.extend_from_slice(&CLOCK_OFFSET.to_be_bytes());
        command.extend_from_slice(&TPM_EO_UNSIGNED_LE.to_be_bytes());
        self.0.push(command);
        self
    }

    pub fn to_file_contents(&self) -> String {
        self.0
            .iter()
            .map(|command| {
                command
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    + "\n"
            })
            .collect()
    }
}

/// The public half of a TSS2 key file, read from the `TPM2B_PUBLIC` it stores in the clear, so
/// it works for a key no approval covers yet.
pub struct KeyFile(Public);

impl KeyFile {
    pub fn parse(pem_contents: &str) -> Result<Self> {
        let (label, der) = pem::decode_vec(pem_contents.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid PEM: {e}"))?;
        ensure!(label == "TSS2 PRIVATE KEY", "Not a TSS2 key file ({label})");
        Self::from_der(&der)
    }

    /// `TPMKey ::= SEQUENCE { type OID, emptyAuth [0] EXPLICIT BOOLEAN OPTIONAL, ... [5]
    /// OPTIONAL, parent INTEGER, pubkey OCTET STRING, privkey OCTET STRING }`: the first OCTET
    /// STRING after the tagged options.
    fn from_der(der: &[u8]) -> Result<Self> {
        let mut reader = SliceReader::new(der)?;
        let public = reader.sequence(|seq| {
            let key_type = ObjectIdentifier::decode(seq)?;
            if key_type != TSS2_LOADABLE_KEY {
                return Err(Tag::ObjectIdentifier.value_error());
            }
            loop {
                let any = Any::decode(seq)?;
                if any.tag() == Tag::OctetString {
                    let public: OctetString = any.decode_as()?;
                    Any::decode(seq)?; // privkey
                    return Ok(public.into_bytes());
                }
            }
        })?;
        reader.finish(())?;
        // TPM2B_PUBLIC: a big-endian size, then the TPMT_PUBLIC.
        ensure!(
            public.len() >= 2
                && public.len() - 2 == u16::from_be_bytes([public[0], public[1]]) as usize,
            "Invalid TPM2B_PUBLIC in the TSS2 key file"
        );
        Ok(Self(
            Public::unmarshall(&public[2..]).context("Invalid TPMT_PUBLIC")?,
        ))
    }

    /// The SubjectPublicKeyInfo of a PEM `PUBLIC KEY`, e.g. the approver (`PK.pub`), to compare
    /// with a certificate's.
    pub fn approver_spki(pem_contents: &str) -> Result<SubjectPublicKeyInfoOwned> {
        use x509_cert::der::DecodePem;
        SubjectPublicKeyInfoOwned::from_pem(pem_contents).context("Invalid PEM public key")
    }

    /// The key as a PEM `PUBLIC KEY` (SubjectPublicKeyInfo).
    pub fn public_key_pem(&self) -> Result<String> {
        let spki =
            SubjectPublicKeyInfoOwned::try_from(&self.0).context("Only RSA keys are supported")?;
        Ok(spki.to_pem(pem::LineEnding::LF)?)
    }

    /// Fail unless only a policy session can use the key: a plain password session with the
    /// (empty) auth value would skip the approvals entirely. The engine clears `userWithAuth`
    /// whenever a key is created with a policy.
    pub fn ensure_policy_only(&self) -> Result<()> {
        ensure!(
            !self.0.object_attributes().user_with_auth(),
            "The key is usable with plain password authorization (userWithAuth is set)"
        );
        ensure!(!self.0.auth_policy().is_empty(), "The key has no policy");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_policy_matches_the_engine_encoding() {
        // Produced by openssl_tpm2_engine's `signed_tpm2_policy add --pcr-lock sha256:7` with
        // PCR 7 at all zeroes: CC_PolicyPCR, one sha256 selection of PCR 7, sha256(zeroes).
        let policy = Policy::default().pcrs(&[(7, [0; 32])]);
        assert_eq!(
            policy.to_file_contents(),
            "0000017f00000001000b0380000066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\n"
        );
    }

    #[test]
    fn counter_timer_policy_encodes_clock_limit() {
        assert_eq!(
            Policy::default().until_clock(1000).to_file_contents(),
            "0000016d00000000000003e800080009\n"
        );
    }

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tss2");

    fn key_file(name: &str) -> KeyFile {
        KeyFile::parse(&std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()).unwrap()
    }

    /// Key files made with `create_tpm2_key` on a throwaway software TPM: they are only
    /// loadable there, so their private parts are useless.
    #[test]
    fn signed_policy_keys_are_policy_only() {
        key_file("signed-policy.key").ensure_policy_only().unwrap();
        let err = key_file("plain.key").ensure_policy_only().unwrap_err();
        assert!(err.to_string().contains("userWithAuth"), "{err}");
    }

    #[test]
    fn exports_the_public_key() {
        let pem = key_file("signed-policy.key").public_key_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"), "{pem}");
        let (_, der) = pem::decode_vec(pem.as_bytes()).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(&der).unwrap();
        assert_eq!(spki.algorithm.oid.to_string(), "1.2.840.113549.1.1.1"); // rsaEncryption
    }

    #[test]
    fn rejects_other_pem_files() {
        let approver = std::fs::read_to_string(format!("{FIXTURES}/approver.pub")).unwrap();
        assert!(KeyFile::parse(&approver).is_err());
    }
}
