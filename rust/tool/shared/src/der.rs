//! The little DER and PEM handling the EFI and TPM key code needs: walking known structures
//! and encoding a public key. Not a general ASN.1 implementation.

use anyhow::{Context, Result, ensure};

/// A DER element: its tag, its contents, and its total encoded length.
pub struct Element<'a> {
    pub tag: u8,
    pub contents: &'a [u8],
    pub len: usize,
}

/// Parse the DER element at the start of `input`.
pub fn element(input: &[u8]) -> Result<Element<'_>> {
    ensure!(input.len() >= 2, "Truncated DER element");
    let (length, header) = match input[1] {
        n if n < 0x80 => (n as usize, 2),
        n => {
            let count = (n & 0x7f) as usize;
            ensure!(
                (1..=4).contains(&count) && input.len() >= 2 + count,
                "Invalid DER length"
            );
            let length = input[2..2 + count]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (length, 2 + count)
        }
    };
    ensure!(input.len() >= header + length, "Truncated DER element");
    Ok(Element {
        tag: input[0],
        contents: &input[header..header + length],
        len: header + length,
    })
}

/// Parse the DER element at the start of `input`, requiring `tag`.
pub fn expect(input: &[u8], tag: u8) -> Result<Element<'_>> {
    let element = element(input)?;
    ensure!(
        element.tag == tag,
        "Unexpected DER tag {:#04x}, expected {tag:#04x}",
        element.tag
    );
    Ok(element)
}

/// Encode a DER element.
pub fn encode(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(contents);
    out
}

/// Encode a non-negative big-endian integer as a DER INTEGER.
pub fn encode_unsigned(bytes: &[u8]) -> Vec<u8> {
    let bytes = match bytes.iter().position(|b| *b != 0) {
        Some(first) => &bytes[first..],
        None => &[0][..],
    };
    let mut contents = Vec::with_capacity(bytes.len() + 1);
    if bytes[0] & 0x80 != 0 {
        contents.push(0);
    }
    contents.extend_from_slice(bytes);
    encode(0x02, &contents)
}

/// An RSA public key as a PEM `SubjectPublicKeyInfo`.
pub fn rsa_public_key_pem(modulus: &[u8], exponent: u32) -> String {
    let rsa_public_key = encode(
        0x30,
        &[
            encode_unsigned(modulus),
            encode_unsigned(&exponent.to_be_bytes()),
        ]
        .concat(),
    );
    // AlgorithmIdentifier { rsaEncryption, NULL }
    let algorithm = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let bit_string = encode(0x03, &[&[0u8][..], &rsa_public_key].concat());
    pem_encode(
        "PUBLIC KEY",
        &encode(0x30, &[&algorithm[..], &bit_string].concat()),
    )
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The DER contents of the first PEM block with the given label.
pub fn pem_decode(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .with_context(|| format!("No {label} PEM block"))?
        + begin.len();
    let stop = pem[start..].find(&end).context("Unterminated PEM block")? + start;
    let body: Vec<u8> = pem[start..stop]
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let value = |c: u8| {
        BASE64
            .iter()
            .position(|b| *b == c)
            .map(|v| v as u32)
            .with_context(|| format!("Invalid base64 character {:?}", c as char))
    };
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let mut acc = 0u32;
        for c in chunk {
            acc = (acc << 6) | value(*c)?;
        }
        acc <<= 6 * (4 - chunk.len() as u32);
        out.extend_from_slice(&acc.to_be_bytes()[1..chunk.len()]);
    }
    Ok(out)
}

/// A PEM block with the given label.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let mut encoded = String::with_capacity(der.len() * 4 / 3 + 4);
    for chunk in der.chunks(3) {
        let acc = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            encoded.push(if i <= chunk.len() {
                BASE64[((acc >> (18 - 6 * i)) & 0x3f) as usize] as char
            } else {
                '='
            });
        }
    }
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trips_all_lengths() {
        for len in 0..10 {
            let data: Vec<u8> = (0..len).collect();
            let pem = pem_encode("TEST", &data);
            assert_eq!(pem_decode(&pem, "TEST").unwrap(), data);
        }
    }

    #[test]
    fn parses_long_form_lengths() {
        let encoded = encode(0x30, &[0u8; 0x100]);
        assert_eq!(&encoded[..4], &[0x30, 0x82, 0x01, 0x00]);
        let element = expect(&encoded, 0x30).unwrap();
        assert_eq!(element.len, 4 + 0x100);
        assert_eq!(element.contents.len(), 0x100);
    }

    #[test]
    fn rejects_truncated_and_mismatched_elements() {
        assert!(element(&[0x30, 0x05, 0x00]).is_err());
        assert!(expect(&[0x04, 0x00], 0x30).is_err());
    }

    #[test]
    fn encodes_integers_without_sign_confusion() {
        assert_eq!(encode_unsigned(&[0x00, 0x7f]), [0x02, 0x01, 0x7f]);
        assert_eq!(encode_unsigned(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_unsigned(&[0, 0]), [0x02, 0x01, 0x00]);
    }
}
