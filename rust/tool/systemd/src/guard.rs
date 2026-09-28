//! Checks that a generation lzbt is about to install can unlock this machine's disks the way
//! they are enrolled, so a bad configuration fails the install instead of the next boot.
//!
//! What a generation's initrd does comes from lanzaboote's bootspec extension; how the disks are
//! enrolled comes from their LUKS2 headers and from the TPM measurement log of this boot.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use x509_cert::der::Decode;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use lanzaboote_tool::generation::{Generation, InitrdLuksDevice};
use lanzaboote_tool::pcr_signature::signed_pcr11_policies;
use lanzaboote_tool::pe;

/// Set (non-empty, not `0`) to install anyway, for a boot that is expected to need the recovery
/// key (e.g. before a firmware update, or after the TPM was cleared).
pub const ALLOW_RECOVERY_ENV: &str = "LZBT_ALLOW_RECOVERY";

pub fn allow_recovery() -> bool {
    std::env::var_os(ALLOW_RECOVERY_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// The inputs of a generation's UKI that its PCR 11 depends on.
pub struct UkiInputs<'a> {
    pub image: &'a Path,
    pub kernel: &'a Path,
    pub initrd: &'a Path,
    pub cmdline: &'a str,
    pub os_release: &'a str,
}

/// Problems that make the next boot of `generation` fail to unlock one of its volumes with the
/// TPM. Volumes whose LUKS header can't be read here (e.g. another machine's disk) are skipped.
pub fn check_generation(generation: &Generation, uki: &UkiInputs) -> Result<Vec<String>> {
    let Some(initrd) = &generation.spec.lanzaboote_extension.initrd else {
        return Ok(Vec::new());
    };
    let mut devices = Vec::new();
    for device in &initrd.luks {
        match tpm2_tokens(&device.device)? {
            Some(tokens) if !tokens.is_empty() => devices.push((device, tokens)),
            Some(_) => {}
            None => log::warn!(
                "Can't read the LUKS header of {} ({}), not checking it.",
                device.name,
                device.device.display()
            ),
        }
    }
    // Only compute PCR 11 when a token depends on it: it runs systemd-measure.
    let needs_pcr11 = devices
        .iter()
        .flat_map(|(_, tokens)| tokens)
        .any(|token| token.signed_pcr11.is_some());
    let boot = if needs_pcr11 {
        BootState::of(uki, initrd.pcrphases)?
    } else {
        BootState {
            pcrphases: initrd.pcrphases,
            initrd_policy: String::new(),
            signed: Vec::new(),
        }
    };
    let mut problems = Vec::new();
    for (device, tokens) in devices {
        let measured = measured_volume_key(&device.name)?;
        if device.option("fixate-volume-key").is_some() && measured.is_none() {
            log::warn!(
                "{}: this boot didn't measure its volume key, so fixate-volume-key= can't be checked.",
                device.name
            );
        }
        problems.extend(device_problems(device, &tokens, &boot, measured.as_deref()));
    }
    Ok(problems)
}

/// A TPM2 token in a LUKS2 header, as systemd-cryptenroll writes it.
#[derive(Debug)]
struct Tpm2Token {
    keyslot: String,
    /// PCRs with literal values (e.g. 7, or 15 = 0).
    pcrs: Vec<u64>,
    /// Whether PCR 11 is bound to a signed policy, and the `pkfp` of the key that must sign it.
    signed_pcr11: Option<String>,
}

/// What the TPM sees when the initrd of a generation unlocks its volumes.
struct BootState {
    pcrphases: bool,
    /// The PCR 11 policy digest (hex) while the initrd unlocks: at `enter-initrd` if it
    /// measures its boot phases, before any phase otherwise.
    initrd_policy: String,
    /// `(pkfp, pol)` pairs the UKI carries signatures for.
    signed: Vec<(String, String)>,
}

impl BootState {
    fn of(uki: &UkiInputs, pcrphases: bool) -> Result<Self> {
        let image = fs::read(uki.image)?;
        let signed = pe::read_section_data(&image, ".pcrsig")
            .map(signed_pcr11_policies)
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            pcrphases,
            initrd_policy: pcr11_policy(&expected_pcr11(
                uki,
                if pcrphases { "enter-initrd" } else { "" },
            )?),
            signed,
        })
    }
}

fn device_problems(
    device: &InitrdLuksDevice,
    tokens: &[Tpm2Token],
    boot: &BootState,
    measured_volume_key: Option<&str>,
) -> Vec<String> {
    let name = &device.name;
    let mut problems = Vec::new();
    // Without tpm2-device=, systemd-cryptsetup tries every token through libcryptsetup's
    // plugins, but not when it needs the volume key itself: to measure it, or to check it.
    let needs_volume_key = [
        "tpm2-measure-pcr",
        "tpm2-measure-keyslot-nvpcr",
        "fixate-volume-key",
    ]
    .iter()
    .any(|option| device.option(option).is_some());
    if needs_volume_key && device.option("tpm2-device").is_none() {
        problems.push(format!(
            "{name}: has a TPM2 token, but its crypttab lacks tpm2-device= next to options that \
             turn off automatic token unlock, so the TPM is never tried"
        ));
    }
    for token in tokens {
        let slot = &token.keyslot;
        if token.pcrs.contains(&15) && device.option("tpm2-measure-pcr").is_none() {
            // It still unlocks, but nothing closes the gate behind it.
            log::warn!(
                "{name}: the token in keyslot {slot} needs PCR 15 unused, but the crypttab lacks \
                 tpm2-measure-pcr=yes, so the TPM would unlock it again in the same boot"
            );
        }
        let Some(key) = &token.signed_pcr11 else {
            continue;
        };
        if !boot
            .signed
            .iter()
            .any(|(pkfp, pol)| pkfp == key && *pol == boot.initrd_policy)
        {
            let phase = if boot.pcrphases {
                "at enter-initrd"
            } else {
                "before any boot phase (boot.initrd.systemd.tpm2.pcrphases.enable is off)"
            };
            problems.push(format!(
                "{name}: the token in keyslot {slot} needs PCR 11 {phase} signed by the key with \
                 fingerprint {}, and this generation carries no such signature \
                 (boot.lanzaboote.measuredBoot.pcrSignatures)",
                &key[..16.min(key.len())]
            ));
        }
    }
    if let (Some(expected), Some(measured)) =
        (device.option("fixate-volume-key"), measured_volume_key)
        && expected != measured
    {
        problems.push(format!(
            "{name}: fixate-volume-key={expected} is not this volume's key ({measured}), so it \
             won't open at all, not even with the recovery key"
        ));
    }
    problems
}

/// The TPM2 tokens of a LUKS2 volume, or `None` if it isn't one here (e.g. another machine's
/// disk, when installing onto it).
fn tpm2_tokens(device: &Path) -> Result<Option<Vec<Tpm2Token>>> {
    if !device.exists() {
        return Ok(None);
    }
    let output = Command::new("cryptsetup")
        .args(["luksDump", "--dump-json-metadata"])
        .arg(device)
        .output()
        .context("Failed to run cryptsetup. Most likely, the binary is not on PATH")?;
    if !output.status.success() {
        return Ok(None);
    }
    let metadata: Value =
        serde_json::from_slice(&output.stdout).context("Invalid LUKS2 metadata")?;
    let Some(tokens) = metadata["tokens"].as_object() else {
        return Ok(Some(Vec::new()));
    };
    Ok(tokens
        .values()
        .filter(|token| token["type"] == "systemd-tpm2")
        .map(|token| {
            let pcrs = |key: &str| -> Vec<u64> {
                token[key]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_u64).collect())
                    .unwrap_or_default()
            };
            let signed_pcr11 = match token["tpm2_pubkey"].as_str() {
                Some(pem) if pcrs("tpm2_pubkey_pcrs").contains(&11) => {
                    Some(pkcs1_fingerprint(pem).ok()?)
                }
                _ => None,
            };
            Some(Tpm2Token {
                keyslot: token["keyslots"][0].as_str().unwrap_or("?").to_owned(),
                pcrs: pcrs("tpm2-pcrs"),
                signed_pcr11,
            })
        })
        .collect::<Option<Vec<_>>>()
        .context("Unreadable public key in a TPM2 token")?
        .into())
}

/// SHA-256 of the PKCS#1 DER of a PEM `PUBLIC KEY` (base64-encoded, as in a LUKS2 token):
/// what systemd-measure calls `pkfp`.
fn pkcs1_fingerprint(pem_base64: &str) -> Result<String> {
    use base64ct::{Base64, Encoding};
    let pem = Base64::decode_vec(pem_base64).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (_, der) = x509_cert::der::pem::decode_vec(&pem).map_err(|e| anyhow::anyhow!("{e}"))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&der)?;
    // For RSA, the SubjectPublicKeyInfo's key bits are the PKCS#1 RSAPublicKey.
    Ok(hex(&Sha256::digest(spki.subject_public_key.raw_bytes())))
}

/// PCR 11 of a UKI at `phase`, from `systemd-measure calculate`.
fn expected_pcr11(uki: &UkiInputs, phase: &str) -> Result<[u8; 32]> {
    let dir = tempfile::tempdir()?;
    let cmdline = dir.path().join("cmdline");
    let os_release = dir.path().join("osrel");
    fs::write(&cmdline, uki.cmdline)?;
    fs::write(&os_release, uki.os_release)?;
    let output = Command::new("systemd-measure")
        .args(["calculate", "--json=short", "--bank=sha256"])
        .arg(format!("--phase={phase}"))
        .arg("--linux")
        .arg(uki.kernel)
        .arg("--initrd")
        .arg(uki.initrd)
        .arg("--cmdline")
        .arg(&cmdline)
        .arg("--osrel")
        .arg(&os_release)
        .output()
        .context("Failed to run systemd-measure. Maybe, the binary is not in PATH")?;
    ensure!(
        output.status.success(),
        "systemd-measure failed to calculate PCR 11: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let result: Value = serde_json::from_slice(&output.stdout)?;
    let hash = result["sha256"][0]["hash"]
        .as_str()
        .context("No sha256 PCR 11 value in the systemd-measure output")?;
    let bytes = (0..hash.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hash[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid PCR 11 value {hash}"))
}

/// The `TPM2_PolicyPCR` digest of PCR 11 (SHA-256 bank) having `value`, from an empty policy:
/// what systemd-measure signs (`pol`).
fn pcr11_policy(value: &[u8; 32]) -> String {
    const TPM_CC_POLICY_PCR: u32 = 0x0000_017f;
    const TPM_ALG_SHA256: u16 = 0x000b;
    let mut digest = Sha256::new();
    digest.update([0u8; 32]);
    digest.update(TPM_CC_POLICY_PCR.to_be_bytes());
    digest.update(1u32.to_be_bytes()); // one PCR selection
    digest.update(TPM_ALG_SHA256.to_be_bytes());
    digest.update([3, 0x00, 0x08, 0x00]); // 3-byte bitmap, PCR 11
    digest.update(Sha256::digest(value));
    hex(&digest.finalize())
}

/// The digest `tpm2-measure-pcr=` recorded for volume `name` in this boot, if any.
fn measured_volume_key(name: &str) -> Result<Option<String>> {
    let log = match fs::read_to_string("/run/log/systemd/tpm2-measure.log") {
        Ok(log) => log,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("Failed to read the TPM measurement log"),
    };
    Ok(measured_volume_key_in(&log, name))
}

/// Records in the measurement log are JSON objects, each after an ASCII record separator.
fn measured_volume_key_in(log: &str, name: &str) -> Option<String> {
    let prefix = format!("cryptsetup:{name}:");
    log.split('\u{1e}')
        .filter_map(|record| serde_json::from_str::<Value>(record.trim()).ok())
        .filter(|record| record["pcr"] == 15)
        .filter(|record| {
            record["content"]["string"]
                .as_str()
                .is_some_and(|s| s.starts_with(&prefix))
        })
        .find_map(|record| {
            // One digest per active PCR bank; fixate-volume-key= is the SHA-256 one.
            record["digests"]
                .as_array()?
                .iter()
                .find(|digest| digest["hashAlg"] == "sha256")?["digest"]
                .as_str()
                .map(str::to_owned)
        })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(options: &[&str]) -> InitrdLuksDevice {
        InitrdLuksDevice {
            name: "system".into(),
            device: "/dev/disk/by-partlabel/NixOS".into(),
            options: options.iter().map(|o| o.to_string()).collect(),
        }
    }

    fn final_token() -> Tpm2Token {
        Tpm2Token {
            keyslot: "1".into(),
            pcrs: vec![15],
            signed_pcr11: Some("initrd-key".into()),
        }
    }

    fn boot(signed: &[(&str, &str)]) -> BootState {
        BootState {
            pcrphases: true,
            initrd_policy: "at-enter-initrd".into(),
            signed: signed
                .iter()
                .map(|(k, p)| (k.to_string(), p.to_string()))
                .collect(),
        }
    }

    const GOOD: &[&str] = &[
        "fixate-volume-key=abc",
        "tpm2-device=auto",
        "tpm2-measure-pcr=yes",
    ];

    #[test]
    fn a_generation_that_unlocks_has_no_problems() {
        let boot = boot(&[("initrd-key", "at-enter-initrd"), ("host-key", "at-ready")]);
        assert_eq!(
            device_problems(&device(GOOD), &[final_token()], &boot, Some("abc")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn crypttab_without_tpm2_device() {
        let options = ["fixate-volume-key=abc", "tpm2-measure-pcr=yes"];
        let boot = boot(&[("initrd-key", "at-enter-initrd")]);
        let problems = device_problems(&device(&options), &[final_token()], &boot, Some("abc"));
        assert!(problems[0].contains("tpm2-device"), "{problems:?}");
    }

    #[test]
    fn crypttab_without_any_options_tries_tokens() {
        // What hosts without TPM-specific crypttab options have: tokens are tried automatically.
        let token = Tpm2Token {
            keyslot: "2".into(),
            pcrs: vec![7],
            signed_pcr11: None,
        };
        let problems = device_problems(&device(&["discard"]), &[token], &boot(&[]), None);
        assert_eq!(problems, Vec::<String>::new());
    }

    #[test]
    fn token_bound_to_a_key_that_signs_another_phase() {
        // The host key's signature covers the booted system, not the initrd.
        let token = Tpm2Token {
            signed_pcr11: Some("host-key".into()),
            ..final_token()
        };
        let boot = boot(&[("initrd-key", "at-enter-initrd"), ("host-key", "at-ready")]);
        let problems = device_problems(&device(GOOD), &[token], &boot, Some("abc"));
        assert!(problems[0].contains("no such signature"), "{problems:?}");
    }

    #[test]
    fn signed_pcr11_without_phase_measurements() {
        // The signature for enter-initrd doesn't cover an initrd that measures no phases.
        let mut boot = boot(&[("initrd-key", "at-enter-initrd")]);
        boot.pcrphases = false;
        boot.initrd_policy = "before-any-phase".into();
        let problems = device_problems(&device(GOOD), &[final_token()], &boot, Some("abc"));
        assert!(problems[0].contains("pcrphases"), "{problems:?}");
    }

    #[test]
    fn wrong_fixate_volume_key() {
        let boot = boot(&[("initrd-key", "at-enter-initrd")]);
        let problems = device_problems(&device(GOOD), &[final_token()], &boot, Some("def"));
        assert!(
            problems[0].contains("not this volume's key"),
            "{problems:?}"
        );
    }

    #[test]
    fn plain_pcr7_token_needs_only_tpm2_device() {
        let token = Tpm2Token {
            keyslot: "2".into(),
            pcrs: vec![7],
            signed_pcr11: None,
        };
        let boot = boot(&[]);
        let problems = device_problems(&device(&["tpm2-device=auto"]), &[token], &boot, None);
        assert_eq!(problems, Vec::<String>::new());
    }

    #[test]
    fn policy_digest_matches_systemd_measure() {
        // A real UKI: its PCR 11 at enter-initrd (systemd-measure calculate) and the `pol` that
        // systemd-measure sign wrote into its .pcrsig for that phase.
        let value = "468bfa8e2d16390528e3ef3ac50d2786d41e706514cc98156d94b690dc9c3921";
        let value: [u8; 32] = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        assert_eq!(
            pcr11_policy(&value),
            "79577a12b40e2827bde28571ee177838cabbab8528ec0dd16323c0f181e514c9"
        );
    }

    #[test]
    fn finds_the_volume_key_measurement() {
        let log = concat!(
            "\u{1e}{\"pcr\":11,\"digests\":[{\"hashAlg\":\"sha256\",\"digest\":\"11\"}],\"content\":{\"string\":\"enter-initrd\"}}\n",
            "\u{1e}{\"pcr\":15,\"digests\":[{\"hashAlg\":\"sha1\",\"digest\":\"5a1\"},{\"hashAlg\":\"sha256\",\"digest\":\"e863\"}],",
            "\"content\":{\"string\":\"cryptsetup:system:1932a6f0-ad52-49fb-98cd-13ef06be2d89\"}}\n"
        );
        assert_eq!(
            measured_volume_key_in(log, "system").as_deref(),
            Some("e863")
        );
        assert_eq!(measured_volume_key_in(log, "other"), None);
    }
}
