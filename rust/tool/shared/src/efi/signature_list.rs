//! `EFI_SIGNATURE_LIST`: the contents of the `PK`, `KEK`, `db` and `dbx` variables.
//!
//! A variable is a concatenation of lists. Each list holds entries of one signature type and
//! one size:
//!
//! ```text
//! EFI_SIGNATURE_LIST {
//!     SignatureType       GUID
//!     SignatureListSize   u32   (whole list, header included)
//!     SignatureHeaderSize u32   (always 0 for the types used here)
//!     SignatureSize       u32   (one EFI_SIGNATURE_DATA)
//!     SignatureHeader     [u8; SignatureHeaderSize]
//!     Signatures          [EFI_SIGNATURE_DATA { SignatureOwner GUID, SignatureData }]
//! }
//! ```

use anyhow::{Context, Result, bail, ensure};

use super::Guid;

const LIST_HEADER_SIZE: usize = 28;
const OWNER_SIZE: usize = 16;

/// One `EFI_SIGNATURE_DATA`: an owner GUID and the signature itself (e.g. a DER certificate).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureData {
    pub owner: Guid,
    pub data: Vec<u8>,
}

impl SignatureData {
    /// The entry as it is laid out in a list, and as firmware measures it into PCR 7 when it
    /// authorizes a boot binary (`EV_EFI_VARIABLE_AUTHORITY`).
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.owner.0[..], &self.data].concat()
    }
}

/// One `EFI_SIGNATURE_LIST`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureList {
    pub signature_type: Guid,
    pub entries: Vec<SignatureData>,
}

impl SignatureList {
    /// A list with a single X.509 certificate (DER), as used for `PK`, `KEK` and `db` entries.
    pub fn x509(owner: Guid, certificate_der: Vec<u8>) -> Self {
        SignatureList {
            signature_type: Guid::CERT_X509,
            entries: vec![SignatureData {
                owner,
                data: certificate_der,
            }],
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let Some(first) = self.entries.first() else {
            bail!("A signature list needs at least one entry");
        };
        let entry_size = OWNER_SIZE + first.data.len();
        ensure!(
            self.entries
                .iter()
                .all(|e| OWNER_SIZE + e.data.len() == entry_size),
            "All entries of a signature list must have the same size"
        );
        let list_size = LIST_HEADER_SIZE + entry_size * self.entries.len();
        let mut out = Vec::with_capacity(list_size);
        out.extend_from_slice(&self.signature_type.0);
        out.extend_from_slice(&u32::try_from(list_size)?.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&u32::try_from(entry_size)?.to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.to_bytes());
        }
        Ok(out)
    }

    /// Parse the contents of a Secure Boot variable (zero or more concatenated lists).
    pub fn parse_all(mut data: &[u8]) -> Result<Vec<SignatureList>> {
        let mut lists = Vec::new();
        while !data.is_empty() {
            ensure!(
                data.len() >= LIST_HEADER_SIZE,
                "Truncated signature list header"
            );
            let signature_type = Guid::from_bytes(&data[..16])?;
            let u32_at = |offset: usize| {
                u32::from_le_bytes(data[offset..offset + 4].try_into().expect("4 bytes")) as usize
            };
            let (list_size, header_size, entry_size) = (u32_at(16), u32_at(20), u32_at(24));
            ensure!(
                list_size >= LIST_HEADER_SIZE + header_size && list_size <= data.len(),
                "Invalid signature list size {list_size}"
            );
            ensure!(
                entry_size > OWNER_SIZE,
                "Invalid signature entry size {entry_size}"
            );
            let body = &data[LIST_HEADER_SIZE + header_size..list_size];
            ensure!(
                body.len().is_multiple_of(entry_size),
                "Signature list size is not a multiple of its entry size"
            );
            let entries = body
                .chunks(entry_size)
                .map(|entry| {
                    Ok(SignatureData {
                        owner: Guid::from_bytes(&entry[..OWNER_SIZE])?,
                        data: entry[OWNER_SIZE..].to_vec(),
                    })
                })
                .collect::<Result<_>>()
                .context("Failed to parse signature entries")?;
            lists.push(SignatureList {
                signature_type,
                entries,
            });
            data = &data[list_size..];
        }
        Ok(lists)
    }
}

/// Find the X.509 entry holding `certificate_der` in the contents of a `db` variable.
pub fn find_certificate<'a>(
    lists: &'a [SignatureList],
    certificate_der: &[u8],
) -> Option<&'a SignatureData> {
    lists
        .iter()
        .filter(|list| list.signature_type == Guid::CERT_X509)
        .flat_map(|list| &list.entries)
        .find(|entry| entry.data == certificate_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Guid {
        "11111111-2222-3333-4444-555555555555".parse().unwrap()
    }

    #[test]
    fn serializes_a_single_certificate_list() {
        let list = SignatureList::x509(owner(), vec![0xaa; 5]);
        let bytes = list.to_bytes().unwrap();
        assert_eq!(bytes.len(), 28 + 16 + 5);
        assert_eq!(&bytes[..16], &Guid::CERT_X509.0);
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 49);
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 21);
        assert_eq!(&bytes[28..44], &owner().0);
        assert_eq!(&bytes[44..], &[0xaa; 5]);
    }

    #[test]
    fn parses_concatenated_lists_of_different_sizes() {
        let a = SignatureList::x509(owner(), vec![1; 3]);
        let b = SignatureList::x509(Guid::GLOBAL_VARIABLE, vec![2; 7]);
        let bytes = [a.to_bytes().unwrap(), b.to_bytes().unwrap()].concat();
        assert_eq!(SignatureList::parse_all(&bytes).unwrap(), vec![a, b]);
        assert!(SignatureList::parse_all(&[]).unwrap().is_empty());
    }

    #[test]
    fn finds_a_certificate_among_several() {
        let ours = vec![9; 4];
        let lists = vec![
            SignatureList::x509(Guid::GLOBAL_VARIABLE, vec![1; 4]),
            SignatureList::x509(owner(), ours.clone()),
        ];
        let entry = find_certificate(&lists, &ours).unwrap();
        assert_eq!(entry.owner, owner());
        assert!(find_certificate(&lists, &[7; 4]).is_none());
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = SignatureList::x509(owner(), vec![1; 3]).to_bytes().unwrap();
        assert!(SignatureList::parse_all(&bytes[..bytes.len() - 1]).is_err());
        assert!(SignatureList::parse_all(&bytes[..20]).is_err());
    }
}
