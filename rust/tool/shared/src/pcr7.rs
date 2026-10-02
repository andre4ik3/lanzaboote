//! Predict PCR 7 (the Secure Boot policy PCR) for a Secure Boot state, from the contents of its
//! variables rather than from a TPM event log. This works for a state that is not enrolled yet,
//! so a key can be bound to the PCR 7 value a machine will have after enrollment.
//!
//! Firmware extends PCR 7, in order, with the `SecureBoot`, `PK`, `KEK`, `db` and `dbx` variables,
//! a separator, and then each `db` entry that authorized an image (option ROMs, the boot loader),
//! the first time it does so in that boot. Every variable event is an `EFI_VARIABLE_DATA`:
//!
//! ```text
//! VariableName (GUID) | UnicodeNameLength (u64) | VariableDataLength (u64)
//! | UnicodeName (UTF-16LE, unterminated) | VariableData
//! ```
//!
//! and extends the register by `PCR = SHA256(PCR || SHA256(event))`.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::efi::{Guid, SignatureList, guid, signature_list::find_certificate};

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
        &vendor.to_bytes()[..],
        &name_len.to_le_bytes(),
        &(data.len() as u64).to_le_bytes(),
        &name,
        data,
    ]
    .concat()
}

/// Predict PCR 7 (SHA-256 bank) with Secure Boot enabled and `state` enrolled.
///
/// `authorities` are the `db` certificates (DER) that authorize images in this boot, in the order
/// firmware first uses them: e.g. the CA of a graphics card's option ROM, then the boot loader's.
/// Firmware measures each authority once per boot (EDK2: `DxeImageVerificationLib`), so repeats
/// add nothing. An authority in db that nothing uses is not measured, which is why the caller,
/// not db, says which ones apply.
pub fn predict(state: &SecureBootState, authorities: &[&[u8]]) -> Result<[u8; 32]> {
    let db = SignatureList::parse_all(state.db).context("Failed to parse db")?;
    let mut measured: Vec<&[u8]> = Vec::new();
    let mut authority_events = Vec::new();
    for authority in authorities {
        if measured.contains(authority) {
            continue;
        }
        measured.push(authority);
        let entry =
            find_certificate(&db, authority).context("An authorizing certificate is not in db")?;
        authority_events.push(variable_event(
            "db",
            guid::IMAGE_SECURITY_DATABASE,
            &entry.to_bytes(),
        ));
    }

    let events = [
        variable_event("SecureBoot", guid::GLOBAL_VARIABLE, &[1]),
        variable_event("PK", guid::GLOBAL_VARIABLE, state.pk),
        variable_event("KEK", guid::GLOBAL_VARIABLE, state.kek),
        variable_event("db", guid::IMAGE_SECURITY_DATABASE, state.db),
        variable_event("dbx", guid::IMAGE_SECURITY_DATABASE, state.dbx),
        // EV_SEPARATOR for a successful boot.
        0u32.to_le_bytes().to_vec(),
    ]
    .into_iter()
    .chain(authority_events);

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
    use crate::efi::SignatureData;

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
    /// with (dbx absent on all of them). All public data. One machine trusts only its own keys,
    /// the others also trust Microsoft's certificates.
    #[test]
    fn matches_live_pcr7_on_real_firmware() {
        let mut machines: Vec<_> = std::fs::read_dir(FIXTURES)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        machines.sort();
        assert!(!machines.is_empty(), "no fixtures in {FIXTURES}");
        for dir in machines {
            let machine = dir.file_name().unwrap().to_string_lossy().into_owned();
            let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
            let (pk, kek, db) = (read("PK.esl"), read("KEK.esl"), read("db.esl"));
            let state = SecureBootState {
                pk: &pk,
                kek: &kek,
                db: &db,
                dbx: &[],
            };
            let expected = String::from_utf8(read("pcr7.hex")).unwrap();
            let predicted = predict(&state, &[&our_certificate(&db)]).unwrap();
            assert_eq!(hex(&predicted), expected.trim(), "PCR 7 of {machine}");
        }
    }

    #[test]
    fn requires_the_authority_to_be_in_db() {
        let db = SignatureList::x509(guid::GLOBAL_VARIABLE, vec![1; 8])
            .to_bytes()
            .unwrap();
        let state = SecureBootState {
            pk: &[],
            kek: &[],
            db: &db,
            dbx: &[],
        };
        assert!(predict(&state, &[&[2; 8]]).is_err());
        assert!(predict(&state, &[&[1; 8]]).is_ok());
    }

    /// One authority event per distinct certificate after the separator, in first-use order.
    #[test]
    fn measures_each_authority_once_in_order() {
        let owner = guid::GLOBAL_VARIABLE;
        let (rom_ca, ours) = (vec![1; 8], vec![2; 8]);
        let db = [
            SignatureList::x509(owner, ours.clone()).to_bytes().unwrap(),
            SignatureList::x509(owner, rom_ca.clone())
                .to_bytes()
                .unwrap(),
        ]
        .concat();
        let state = SecureBootState {
            pk: &[],
            kek: &[],
            db: &db,
            dbx: &[],
        };
        let extend = |pcr: [u8; 32], cert: &[u8]| -> [u8; 32] {
            let entry = SignatureData {
                owner,
                data: cert.to_vec(),
            };
            let event = variable_event("db", guid::IMAGE_SECURITY_DATABASE, &entry.to_bytes());
            Sha256::new()
                .chain_update(pcr)
                .chain_update(Sha256::digest(event))
                .finalize()
                .into()
        };

        let separator = predict(&state, &[]).unwrap();
        let with_rom = predict(&state, &[&rom_ca, &ours]).unwrap();
        assert_eq!(predict(&state, &[&ours]).unwrap(), extend(separator, &ours));
        assert_eq!(with_rom, extend(extend(separator, &rom_ca), &ours));
        assert_eq!(
            with_rom,
            predict(&state, &[&rom_ca, &ours, &rom_ca, &ours]).unwrap()
        );
        assert_ne!(with_rom, predict(&state, &[&ours, &rom_ca]).unwrap());
    }
}
