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

use crate::der;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_CC_POLICY_PCR: u32 = 0x0000_017f;
const TPM_CC_POLICY_COUNTER_TIMER: u32 = 0x0000_016d;
const TPM_ALG_SHA256: u16 = 0x000b;
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

/// The RSA public key of a TSS2 key file, as (modulus, exponent). Reads the `TPM2B_PUBLIC`
/// stored in the clear in the file, so it works for a key no approval covers yet.
pub fn rsa_public_key(key_file_pem: &str) -> Result<(Vec<u8>, u32)> {
    let der = der::pem_decode(key_file_pem, "TSS2 PRIVATE KEY")?;
    let public = tpm2b_public(&der)?;
    parse_rsa_public(public)
}

/// The pubkey field of `TPMKey ::= SEQUENCE { type OID, emptyAuth [0] OPTIONAL, policy [1]
/// OPTIONAL, secret [2] OPTIONAL, authPolicy [3] OPTIONAL, description [4] OPTIONAL,
/// rsaParent [5] OPTIONAL, parent INTEGER, pubkey OCTET STRING, privkey OCTET STRING }`:
/// the first OCTET STRING at the top level.
fn tpm2b_public(key: &[u8]) -> Result<&[u8]> {
    let key = der::expect(key, 0x30).context("A TSS2 key file is a DER SEQUENCE")?;
    let mut rest = key.contents;
    while !rest.is_empty() {
        let field = der::element(rest)?;
        if field.tag == 0x04 {
            return Ok(field.contents);
        }
        rest = &rest[field.len..];
    }
    bail!("No public area in the TSS2 key file")
}

fn parse_rsa_public(public: &[u8]) -> Result<(Vec<u8>, u32)> {
    let mut reader = Reader(public);
    let size = reader.u16()? as usize;
    ensure!(size == reader.0.len(), "Invalid TPM2B_PUBLIC size");
    let key_type = reader.u16()?;
    ensure!(key_type == TPM_ALG_RSA, "Only RSA keys are supported");
    reader.u16()?; // nameAlg
    reader.u32()?; // objectAttributes
    let policy = reader.u16()? as usize;
    reader.skip(policy)?; // authPolicy
    // TPMS_RSA_PARMS: symmetric (alg[, keyBits, mode]), scheme (alg[, hash]), keyBits, exponent
    if reader.u16()? != TPM_ALG_NULL {
        reader.skip(4)?;
    }
    if reader.u16()? != TPM_ALG_NULL {
        reader.skip(2)?;
    }
    reader.u16()?; // keyBits
    let exponent = match reader.u32()? {
        0 => 65537,
        e => e,
    };
    let modulus_len = reader.u16()? as usize;
    let modulus = reader.take(modulus_len)?.to_vec();
    Ok((modulus, exponent))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "Truncated TPM2B_PUBLIC");
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
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

    #[test]
    fn reads_the_rsa_public_area() {
        // TPM2B_PUBLIC: type RSA, nameAlg sha256, attributes, empty policy, NULL symmetric,
        // NULL scheme, 2048 bits, exponent 0 (65537), 4-byte modulus.
        let mut public = Vec::new();
        public.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        public.extend_from_slice(&0x0004_0072u32.to_be_bytes());
        public.extend_from_slice(&0u16.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        public.extend_from_slice(&2048u16.to_be_bytes());
        public.extend_from_slice(&0u32.to_be_bytes());
        public.extend_from_slice(&4u16.to_be_bytes());
        public.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let tpm2b = [&(public.len() as u16).to_be_bytes()[..], &public].concat();

        // TPMKey with an OID, a parent INTEGER, then pubkey and privkey OCTET STRINGs.
        let oid = der::encode(0x06, &[0x67, 0x81, 0x05, 0x0a, 0x01, 0x03]);
        let parent = der::encode(0x02, &[0x40, 0x00, 0x00, 0x01]);
        let body = [
            oid,
            parent,
            der::encode(0x04, &tpm2b),
            der::encode(0x04, &[1, 2]),
        ]
        .concat();
        let pem = der::pem_encode("TSS2 PRIVATE KEY", &der::encode(0x30, &body));

        let (modulus, exponent) = rsa_public_key(&pem).unwrap();
        assert_eq!(modulus, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(exponent, 65537);
    }
}
