//! Predict PCR 7 (the Secure Boot policy PCR) for a Secure Boot state, from the contents of its
//! variables rather than from a TPM event log. This works for a state that is not enrolled yet,
//! so a key can be bound to the PCR 7 value a machine will have after enrollment.
//!
//! Firmware extends PCR 7, in order, with the `SecureBoot`, `PK`, `KEK`, `db` and `dbx` variables,
//! a separator, and the `db` entry that authorized the boot loader. Every variable event is an
//! `EFI_VARIABLE_DATA`:
//!
//! ```text
//! VariableName (GUID) | UnicodeNameLength (u64) | VariableDataLength (u64)
//! | UnicodeName (UTF-16LE, unterminated) | VariableData
//! ```
//!
//! and extends the register by `PCR = SHA256(PCR || SHA256(event))`.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::efi::{Guid, SignatureList, signature_list::find_certificate};

/// The contents of the Secure Boot variables, as enrolled (without efivarfs attribute bytes).
pub struct SecureBootState<'a> {
    pub pk: &'a [u8],
    pub kek: &'a [u8],
    pub db: &'a [u8],
    /// Empty when dbx is not set.
    pub dbx: &'a [u8],
}

fn variable_event(name: &str, vendor: Guid, data: &[u8]) -> Vec<u8> {
    let name_len = name.encode_utf16().count() as u64;
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    [
        &vendor.0[..],
        &name_len.to_le_bytes(),
        &(data.len() as u64).to_le_bytes(),
        &name,
        data,
    ]
    .concat()
}

/// Predict PCR 7 (SHA-256 bank) with Secure Boot enabled, `state` enrolled, and the boot loader
/// authorized by the `db` entry holding `authority` (a DER certificate).
pub fn predict(state: &SecureBootState, authority: &[u8]) -> Result<[u8; 32]> {
    let db = SignatureList::parse_all(state.db).context("Failed to parse db")?;
    let authority = find_certificate(&db, authority)
        .context("The authorizing certificate is not in db")?
        .to_bytes();

    let events = [
        variable_event("SecureBoot", Guid::GLOBAL_VARIABLE, &[1]),
        variable_event("PK", Guid::GLOBAL_VARIABLE, state.pk),
        variable_event("KEK", Guid::GLOBAL_VARIABLE, state.kek),
        variable_event("db", Guid::IMAGE_SECURITY_DATABASE, state.db),
        variable_event("dbx", Guid::IMAGE_SECURITY_DATABASE, state.dbx),
        // EV_SEPARATOR for a successful boot.
        0u32.to_le_bytes().to_vec(),
        variable_event("db", Guid::IMAGE_SECURITY_DATABASE, &authority),
    ];

    let mut pcr = [0u8; 32];
    for event in events {
        let digest = Sha256::digest(&event);
        pcr = Sha256::new()
            .chain_update(pcr)
            .chain_update(digest)
            .finalize()
            .into();
    }
    Ok(pcr)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pcr7");

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The certificate of our own key, which authorized the boot on every fixture host. The
    /// multi-certificate hosts also trust five Microsoft certificates; the prediction must pick
    /// the entry by certificate, not by position.
    fn our_certificate(db: &[u8]) -> Vec<u8> {
        let lists = SignatureList::parse_all(db).unwrap();
        // sbctl puts our key first, but pick by content to not rely on that.
        let entries: Vec<_> = lists.iter().flat_map(|l| &l.entries).collect();
        entries
            .iter()
            .find(|e| e.data.windows(12).any(|w| w == b"Database Key"))
            .expect("fixture db has our certificate")
            .data
            .clone()
    }

    /// Recorded from real machines: PK, KEK, db as enrolled, and the live PCR 7 they booted
    /// with (dbx absent on all of them). All public data.
    #[test]
    fn matches_live_pcr7_on_real_firmware() {
        for host in ["heatseeker", "wavelight", "endless", "pineapple"] {
            let dir = std::path::Path::new(FIXTURES).join(host);
            let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
            let (pk, kek, db) = (read("PK.esl"), read("KEK.esl"), read("db.esl"));
            let state = SecureBootState {
                pk: &pk,
                kek: &kek,
                db: &db,
                dbx: &[],
            };
            let expected = String::from_utf8(read("pcr7.hex")).unwrap();
            let predicted = predict(&state, &our_certificate(&db)).unwrap();
            assert_eq!(hex(&predicted), expected.trim(), "PCR 7 on {host}");
        }
    }

    #[test]
    fn requires_the_authority_to_be_in_db() {
        let db = SignatureList::x509(Guid::GLOBAL_VARIABLE, vec![1; 8])
            .to_bytes()
            .unwrap();
        let state = SecureBootState {
            pk: &[],
            kek: &[],
            db: &db,
            dbx: &[],
        };
        assert!(predict(&state, &[2; 8]).is_err());
        assert!(predict(&state, &[1; 8]).is_ok());
    }
}
