//! `lzbt tpm`: provision Secure Boot keys held in the TPM.
//!
//! The flow moves a machine to a KEK and db generated inside its TPM, usable only in PCR 7
//! states an approver (normally the PK, on a hardware token) has signed:
//!
//! 1. `init` (on the machine): create the keys and record the current Secure Boot state.
//! 2. `authorize` (where the approver key is): issue certificates and the PK/KEK/db enrollment
//!    updates, predict PCR 7 after enrollment, and approve it, plus the current state until a
//!    TPM clock deadline so the machine can re-sign its ESP before enrolling.
//! 3. `lzbt install --transition-dir` (on the machine): sign boot files with both the old and
//!    the new db key, and stage the enrollment updates for systemd-boot.
//!
//! All files live in one directory ("state directory") that is carried between machines. Only
//! the TPM key files are specific to the machine, and they are useless without its TPM.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};

use lanzaboote_tool::der;
use lanzaboote_tool::efi::auth::{self, SecureBootVariable};
use lanzaboote_tool::efi::{Guid, SignatureList};
use lanzaboote_tool::pcr7::{self, SecureBootState};
use lanzaboote_tool::signature::LocalKeyPair;
use lanzaboote_tool::tpm_key::{self, Policy};

const EFIVARS: &str = "/sys/firmware/efi/efivars";

/// Files in the state directory.
struct State(PathBuf);

impl State {
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        fs::read(self.path(name)).with_context(|| format!("Failed to read {name}"))
    }

    fn read_string(&self, name: &str) -> Result<String> {
        Ok(String::from_utf8(self.read(name)?)?.trim().to_owned())
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> Result<()> {
        fs::write(self.path(name), contents).with_context(|| format!("Failed to write {name}"))
    }
}

#[derive(Subcommand)]
pub enum TpmCommand {
    /// Create the KEK and db in the TPM and record the current Secure Boot state
    Init(InitCommand),
    /// Issue certificates, enrollment updates and PCR 7 approvals (run where the approver is)
    Authorize(AuthorizeCommand),
    /// Approve an additional PCR 7 value for the keys (e.g. after a firmware update)
    Approve(ApproveCommand),
}

#[derive(Parser)]
pub struct InitCommand {
    /// State directory; must contain `PK.pub`, the approver's public key
    dir: PathBuf,
}

#[derive(Parser)]
pub struct AuthorizeCommand {
    /// State directory, as written by `init`
    dir: PathBuf,
    /// The PK private key: anything OpenSSL can load (a PEM file, or e.g. a `pkcs11:` URI)
    #[arg(long)]
    pk: String,
    /// The PK certificate (PEM)
    #[arg(long)]
    pk_certificate: PathBuf,
    /// Signature owner GUID for the enrolled certificates (random by default)
    #[arg(long)]
    owner: Option<Guid>,
    /// How long the current Secure Boot state stays approved, counted from `init`
    #[arg(long, default_value_t = 60)]
    transition_minutes: u64,
}

#[derive(Parser)]
pub struct ApproveCommand {
    /// State directory
    dir: PathBuf,
    /// The approver private key (anything OpenSSL can load)
    #[arg(long)]
    pk: String,
    /// The PCR 7 value to approve (hex)
    #[arg(long)]
    pcr7: String,
    /// A name for the approval
    #[arg(long)]
    name: String,
    /// Only approve until the TPM clock (milliseconds, see `tpm2_readclock`) passes this value
    #[arg(long)]
    until_clock: Option<u64>,
    /// Keys to approve for (default: all of them)
    #[arg(long = "key", value_name = "KEY")]
    keys: Vec<String>,
}

impl TpmCommand {
    pub fn call(self) -> Result<()> {
        match self {
            Self::Init(args) => init(&State(args.dir)),
            Self::Authorize(args) => authorize(args),
            Self::Approve(args) => {
                let state = State(args.dir);
                let mut policy = Policy::default().pcrs(&[(7, parse_pcr(&args.pcr7)?)]);
                if let Some(clock) = args.until_clock {
                    policy = policy.until_clock(clock);
                }
                let keys: Vec<&str> = if args.keys.is_empty() {
                    KEYS.to_vec()
                } else {
                    args.keys.iter().map(String::as_str).collect()
                };
                approve(&state, &keys, &args.name, &policy, &args.pk)
            }
        }
    }
}

const KEYS: [&str; 2] = ["KEK", "db"];

fn init(state: &State) -> Result<()> {
    ensure!(
        state.path("PK.pub").exists(),
        "{} must contain PK.pub, the approver's public key",
        state.0.display()
    );
    for key in KEYS {
        let key_file = state.path(&format!("{key}.key"));
        if key_file.exists() {
            log::info!("{key}.key exists, keeping it.");
        } else {
            tpm_key::create(&key_file, &state.path("PK.pub"))
                .with_context(|| format!("Failed to create the {key} key"))?;
            log::info!("Created {key}.key in the TPM.");
        }
        let (modulus, exponent) = tpm_key::rsa_public_key(&fs::read_to_string(&key_file)?)?;
        state.write(
            &format!("{key}.pub"),
            der::rsa_public_key_pem(&modulus, exponent),
        )?;
    }

    // dbx is not replaced by enrollment, so it stays part of the PCR 7 state.
    let dbx = read_efivar("dbx", Guid::IMAGE_SECURITY_DATABASE)?.unwrap_or_default();
    state.write("dbx.esl", dbx)?;
    state.write("pcr7.current", hex(&read_pcr7()?))?;
    state.write("clock.current", read_tpm_clock()?.to_string())?;
    log::info!(
        "Done. Copy {} to the machine with the approver key and run `lzbt tpm authorize`.",
        state.0.display()
    );
    Ok(())
}

fn authorize(args: AuthorizeCommand) -> Result<()> {
    let state = State(args.dir);
    let owner = match args.owner {
        Some(owner) => owner,
        None => random_guid()?,
    };

    // Certificates for the TPM keys, issued by the PK from their public halves: nothing here
    // uses the TPM keys themselves, which cannot sign before an approval exists.
    for key in KEYS {
        issue_certificate(&state, key, &args.pk, &args.pk_certificate)?;
    }

    let pk = SignatureList::x509(owner, pem_certificate_der(&args.pk_certificate)?).to_bytes()?;
    let kek =
        SignatureList::x509(owner, pem_certificate_der(&state.path("KEK.crt"))?).to_bytes()?;
    let db_cert = pem_certificate_der(&state.path("db.crt"))?;
    let db = SignatureList::x509(owner, db_cert.clone()).to_bytes()?;

    // All three signed by the PK: firmware accepts them in setup mode, and they can re-enroll
    // the same state after a firmware reset.
    let timestamp = auth::efi_time_now();
    for (variable, data) in [
        (SecureBootVariable::Pk, &pk),
        (SecureBootVariable::Kek, &kek),
        (SecureBootVariable::Db, &db),
    ] {
        let update = auth::sign(variable, data, &timestamp, &args.pk, &args.pk_certificate)?;
        state.write(&format!("{}.auth", variable.name()), update)?;
    }

    let dbx = state.read("dbx.esl")?;
    let enrolled = pcr7::predict(
        &SecureBootState {
            pk: &pk,
            kek: &kek,
            db: &db,
            dbx: &dbx,
        },
        &db_cert,
    )?;
    state.write("pcr7.enrolled", hex(&enrolled))?;

    let current = parse_pcr(&state.read_string("pcr7.current")?)?;
    let deadline =
        state.read_string("clock.current")?.parse::<u64>()? + args.transition_minutes * 60_000;

    approve(
        &state,
        &KEYS,
        "enrolled",
        &Policy::default().pcrs(&[(7, enrolled)]),
        &args.pk,
    )?;
    approve(
        &state,
        &KEYS,
        "transition",
        &Policy::default()
            .pcrs(&[(7, current)])
            .until_clock(deadline),
        &args.pk,
    )?;
    log::info!(
        "Approved PCR 7 {} after enrollment; the current state stays approved for {} minutes after init.",
        hex(&enrolled),
        args.transition_minutes
    );
    Ok(())
}

/// The provider module that loads TPM key files, from `LZBT_TPM2_PROVIDER` (set by the
/// package). Given to systemd-sbsign by path, so no OpenSSL configuration is needed.
fn tpm2_provider() -> Result<String> {
    std::env::var("LZBT_TPM2_PROVIDER")
        .context("LZBT_TPM2_PROVIDER is not set: it must point at openssl_tpm2_engine's tpm2.so")
}

/// A signer for the TPM db key of a state directory.
pub fn db_signer(dir: &Path) -> Result<LocalKeyPair> {
    let state = State(dir.to_owned());
    ensure!(
        state.path("db.crt").exists(),
        "{} has no db.crt: run `lzbt tpm authorize` first",
        dir.display()
    );
    Ok(LocalKeyPair::new(
        &state.path("db.crt"),
        &state.path("db.key"),
        Some(format!("provider:{}", tpm2_provider()?)),
    ))
}

/// Stage the enrollment updates for systemd-boot, and optionally delete the current PK so the
/// next boot is in setup mode.
pub fn stage(dir: &Path, esp: &Path, clear_pk: Option<(&Path, &Path)>) -> Result<()> {
    let state = State(dir.to_owned());
    let keys = esp.join("loader/keys/auto");
    fs::create_dir_all(&keys)?;
    for variable in ["PK", "KEK", "db"] {
        let name = format!("{variable}.auth");
        fs::write(keys.join(&name), state.read(&name)?)?;
    }
    log::info!("Staged the enrollment updates in {}.", keys.display());

    if let Some((key, certificate)) = clear_pk {
        // An empty PK update signed by the current PK deletes it: setup mode.
        let timestamp = auth::efi_time_now();
        let key = key
            .to_str()
            .context("The PK key path must be valid UTF-8")?;
        let update = auth::sign(SecureBootVariable::Pk, &[], &timestamp, key, certificate)?;
        write_efivar("PK", Guid::GLOBAL_VARIABLE, &update)?;
        log::info!("Deleted the PK: the next boot is in setup mode and enrolls the new keys.");
    }
    Ok(())
}

/// Write an authenticated update to an EFI variable through efivarfs.
fn write_efivar(name: &str, vendor: Guid, update: &[u8]) -> Result<()> {
    let path = Path::new(EFIVARS).join(format!("{name}-{vendor}"));
    // efivarfs marks existing variables immutable; lift that for this write only.
    let _ = Command::new("chattr").arg("-i").arg(&path).status();
    let contents = [
        &auth::SECURE_BOOT_VARIABLE_ATTRIBUTES.to_le_bytes()[..],
        update,
    ]
    .concat();
    // One write(2): efivarfs rejects updates split across several.
    fs::write(&path, contents).with_context(|| format!("Failed to write {}", path.display()))
}

fn approve(
    state: &State,
    keys: &[&str],
    name: &str,
    policy: &Policy,
    approver: &str,
) -> Result<()> {
    let policy_file = state.path(&format!("policy.{name}"));
    fs::write(&policy_file, policy.to_file_contents())?;
    for key in keys {
        tpm_key::approve(
            &state.path(&format!("{key}.key")),
            name,
            &policy_file,
            approver,
        )
        .with_context(|| format!("Failed to approve {name} for the {key} key"))?;
    }
    Ok(())
}

fn issue_certificate(state: &State, key: &str, pk: &str, pk_certificate: &Path) -> Result<()> {
    let subject = match key {
        "KEK" => "/CN=Key Exchange Key (TPM)/",
        _ => "/CN=Database Key (TPM)/",
    };
    let output = Command::new("openssl")
        .args([
            "x509",
            "-new",
            "-days",
            "36500",
            "-subj",
            subject,
            "-force_pubkey",
        ])
        .arg(state.path(&format!("{key}.pub")))
        .arg("-CA")
        .arg(pk_certificate)
        .args(["-CAkey", pk, "-out"])
        .arg(state.path(&format!("{key}.crt")))
        .output()
        .context("Failed to run openssl. Most likely, the binary is not on PATH.")?;
    if !output.status.success() {
        bail!(
            "Failed to issue the {key} certificate: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn pem_certificate_der(path: &Path) -> Result<Vec<u8>> {
    der::pem_decode(&fs::read_to_string(path)?, "CERTIFICATE")
        .with_context(|| format!("Failed to read the certificate {}", path.display()))
}

/// The contents of an EFI variable (without efivarfs' attribute prefix), if it exists.
fn read_efivar(name: &str, vendor: Guid) -> Result<Option<Vec<u8>>> {
    let path = Path::new(EFIVARS).join(format!("{name}-{vendor}"));
    match fs::read(&path) {
        Ok(data) if data.len() >= 4 => Ok(Some(data[4..].to_vec())),
        Ok(_) => Ok(Some(Vec::new())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

fn read_pcr7() -> Result<[u8; 32]> {
    let output = tpm2_tools(&["tpm2_pcrread", "sha256:7"])?;
    // "  sha256:\n    7 : 0x<hex>"
    let value = output
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("7") && fields.next() == Some(":"))
                .then(|| fields.next())
                .flatten()
        })
        .context("No PCR 7 in tpm2_pcrread output")?;
    parse_pcr(value.trim_start_matches("0x"))
}

fn read_tpm_clock() -> Result<u64> {
    let output = tpm2_tools(&["tpm2_readclock"])?;
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("clock:"))
        .context("No clock in tpm2_readclock output")?
        .trim()
        .parse()
        .context("Invalid TPM clock")
}

fn tpm2_tools(args: &[&str]) -> Result<String> {
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| {
            format!(
                "Failed to run {}. Most likely, tpm2-tools is not on PATH.",
                args[0]
            )
        })?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn random_guid() -> Result<Guid> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .context("Failed to read /dev/urandom")?;
    // RFC 4122 version 4, variant 1.
    bytes[7] = (bytes[7] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Guid(bytes))
}

fn parse_pcr(hex: &str) -> Result<[u8; 32]> {
    ensure!(
        hex.len() == 64,
        "A SHA-256 PCR value is 64 hex digits: {hex:?}"
    );
    let bytes = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .with_context(|| format!("Invalid PCR value {hex:?}"))?;
    Ok(bytes.try_into().expect("32 bytes"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
