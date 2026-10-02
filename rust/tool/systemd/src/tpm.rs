//! `lzbt tpm`: provision Secure Boot keys held in the TPM.
//!
//! The flow moves a machine to a KEK and db generated inside its TPM, usable only in states an
//! approver (normally the PK, on a hardware token) has signed. A state is PCR 7 (the Secure Boot
//! policy) and PCR 15, which holds the measurement of the root volume's key once it is open
//! (crypttab `tpm2-measure-pcr=yes`): the keys only work in a boot that opened this machine's
//! disk, with nothing else measured into PCR 15.
//!
//! 1. `init` (on the machine): create the keys and record the current Secure Boot state and PCR 15.
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

use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};

use lanzaboote_tool::efi::auth::{self, SecureBootVariable};
use lanzaboote_tool::efi::{Guid, SignatureList, guid};
use lanzaboote_tool::pcr7::{self, SecureBootState};
use lanzaboote_tool::signature::LocalKeyPair;
use lanzaboote_tool::tpm_key::{self, KeyFile, Policy};
use tss_esapi::Context as TpmContext;
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use x509_cert::Certificate;
use x509_cert::der::{Decode, DecodePem};

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

    /// The certificates (DER) kept in the directory `name`, in order. A non-empty `replace`
    /// first replaces them with those files.
    fn certificates(&self, name: &str, replace: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
        let dir = self.path(name);
        if !replace.is_empty() {
            let certs = replace
                .iter()
                .map(|path| certificate_der(path))
                .collect::<Result<Vec<_>>>()?;
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
            fs::create_dir(&dir)?;
            for (i, cert) in certs.iter().enumerate() {
                self.write(&format!("{name}/{i:02}.der"), cert)?;
            }
        }
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut files: Vec<_> = fs::read_dir(&dir)?
            .map(|entry| Ok(entry?.path()))
            .collect::<Result<_>>()?;
        files.sort();
        files.iter().map(|path| certificate_der(path)).collect()
    }

    /// An approval of `pcr7`, together with the PCR 15 `init` recorded.
    fn policy(&self, pcr7: [u8; 32]) -> Result<Policy> {
        let pcr15 = parse_pcr(&self.read_string("pcr15.current")?)?;
        Ok(Policy::default().pcrs(&[(7, pcr7), (15, pcr15)]))
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
    /// Delete PK, KEK and db from firmware with updates the current PK signs: setup mode. The
    /// next boot enrolls the updates in `loader/keys/auto`, if any
    ClearKeys(ClearKeysCommand),
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
    /// Issue new certificates and enrollment updates even if the state directory has them.
    /// After enrollment this breaks booting until the new ones are enrolled too. Without it,
    /// existing ones are kept and only the approvals are renewed (e.g. after `init` again,
    /// for a new transition window).
    #[arg(long)]
    force: bool,
    /// Another certificate (PEM or DER) to trust in db next to the TPM db key, e.g. Microsoft's
    /// option ROM CAs for a graphics card. Repeat for several. Kept in the state directory
    /// (`db.extra/`): later runs without the flag keep the same db; to drop them, delete it.
    #[arg(long = "extra-db", value_name = "CERTIFICATE")]
    extra_db: Vec<PathBuf>,
    /// A certificate from db (PEM or DER) that authorizes an installed card's option ROM, so it
    /// is measured into PCR 7 before the boot loader's. Repeat in the order firmware loads them;
    /// only the CA that actually signed the ROM counts. The keys are approved for PCR 7 both with
    /// and without the cards (`pcr7.enrolled-option-roms`, `pcr7.enrolled`). Kept in the state
    /// directory (`option-rom-authorities/`) like `--extra-db`.
    #[arg(long = "option-rom-authority", value_name = "CERTIFICATE")]
    option_rom_authorities: Vec<PathBuf>,
}

#[derive(Parser)]
pub struct ApproveCommand {
    /// State directory
    dir: PathBuf,
    /// The approver private key (anything OpenSSL can load)
    #[arg(long)]
    pk: String,
    /// The PCR 7 value to approve (hex). PCR 15 is the value `init` recorded.
    #[arg(long)]
    pcr7: String,
    /// A name for the approval
    #[arg(long)]
    name: String,
    /// Only approve until the TPM clock (milliseconds since the TPM was manufactured) passes
    /// this value
    #[arg(long)]
    until_clock: Option<u64>,
    /// Keys to approve for (default: db; the KEK only signs db/dbx updates)
    #[arg(long = "key", value_name = "KEY")]
    keys: Vec<String>,
}

#[derive(Parser)]
#[command(group = clap::ArgGroup::new("source").required(true).args(["pk", "from"]))]
pub struct ClearKeysCommand {
    /// The current PK's private key (anything OpenSSL can load)
    #[arg(long, requires = "pk_certificate")]
    pk: Option<String>,
    /// The current PK's certificate (PEM)
    #[arg(long, requires = "pk")]
    pk_certificate: Option<PathBuf>,
    /// Only sign the deletions, into this directory, for `--from` on the machine. Works on any
    /// machine with the PK: nothing is read from or written to firmware.
    #[arg(long, requires = "pk", value_name = "DIR")]
    sign_to: Option<PathBuf>,
    /// Apply deletions signed earlier with `--sign-to`, without the PK. They stay valid until
    /// the variables are written with a newer timestamp (e.g. by the next enrollment).
    #[arg(long, value_name = "DIR")]
    from: Option<PathBuf>,
}

impl TpmCommand {
    pub fn call(self) -> Result<()> {
        match self {
            Self::Init(args) => init(&State(args.dir)),
            Self::Authorize(args) => authorize(args),
            Self::Approve(args) => {
                let state = State(args.dir);
                let mut policy = state.policy(parse_pcr(&args.pcr7)?)?;
                if let Some(clock) = args.until_clock {
                    policy = policy.until_clock(clock);
                }
                let keys: Vec<&str> = if args.keys.is_empty() {
                    vec!["db"]
                } else {
                    args.keys.iter().map(String::as_str).collect()
                };
                approve(&state, &keys, &args.name, &policy, &args.pk)
            }
            Self::ClearKeys(args) => match (args.pk, args.pk_certificate, args.from) {
                (Some(pk), Some(certificate), None) => {
                    let updates = sign_deletions(&pk, &certificate)?;
                    match args.sign_to {
                        Some(dir) => write_deletions(&dir, &updates),
                        None => apply_deletions(&updates),
                    }
                }
                (None, None, Some(dir)) => apply_deletions(&read_deletions(&dir)?),
                _ => unreachable!("clap requires --pk with --pk-certificate, or --from"),
            },
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
        let key_file = KeyFile::parse(&fs::read_to_string(&key_file)?)
            .with_context(|| format!("Failed to read {key}.key"))?;
        key_file
            .ensure_policy_only()
            .with_context(|| format!("{key}.key is not bound to its approvals"))?;
        state.write(&format!("{key}.pub"), key_file.public_key_pem()?)?;
    }

    // dbx is not replaced by enrollment, so it stays part of the PCR 7 state.
    let dbx = read_efivar("dbx", guid::IMAGE_SECURITY_DATABASE)?.unwrap_or_default();
    state.write("dbx.esl", dbx)?;
    state.write("pcr7.current", hex(&read_pcr(7)?))?;
    let pcr15 = read_pcr(15)?;
    ensure!(
        pcr15 != [0; 32],
        "PCR 15 is zero: nothing measured a volume key in this boot. Open the root volume with \
         `tpm2-measure-pcr=yes` in crypttab, then run init again."
    );
    state.write("pcr15.current", hex(&pcr15))?;
    state.write("clock.current", read_tpm_clock()?.to_string())?;
    log::info!(
        "Done. Copy {} to the machine with the approver key and run `lzbt tpm authorize`.",
        state.0.display()
    );
    Ok(())
}

fn authorize(args: AuthorizeCommand) -> Result<()> {
    let state = State(args.dir);
    // Certificates and enrollment updates are what firmware trusts once enrolled: reissuing
    // them breaks booting until the new ones are enrolled too, so keep existing ones.
    const ISSUED: [&str; 5] = ["KEK.crt", "db.crt", "PK.auth", "KEK.auth", "db.auth"];
    let issued = ISSUED
        .iter()
        .filter(|name| state.path(name).exists())
        .count();
    ensure!(
        args.force || issued == 0 || issued == ISSUED.len(),
        "The state directory has some of {ISSUED:?} but not all: use --force to issue new ones"
    );
    let reissue = args.force || issued == 0;

    // The keys only accept approvals from the PK they were created for.
    let pk_certificate = Certificate::from_pem(fs::read(&args.pk_certificate)?)
        .context("Failed to read the PK certificate")?;
    let approver = KeyFile::approver_spki(&state.read_string("PK.pub")?)?;
    ensure!(
        pk_certificate.tbs_certificate.subject_public_key_info == approver,
        "{} is not the certificate of PK.pub, the approver the keys were created for",
        args.pk_certificate.display()
    );

    // One owner GUID for all entries; kept so a forced re-run keeps the same owner.
    let owner = match args.owner {
        Some(owner) => owner,
        None if state.path("owner.guid").exists() => state.read_string("owner.guid")?.parse()?,
        None => guid::random(),
    };
    state.write("owner.guid", owner.to_string())?;

    if reissue {
        // Certificates for the TPM keys, issued by the PK from their public halves: nothing
        // here uses the TPM keys themselves, which cannot sign before an approval exists.
        for key in KEYS {
            issue_certificate(&state, key, &args.pk, &args.pk_certificate)?;
        }
    } else {
        log::info!("Keeping the existing certificates and enrollment updates; renewing approvals.");
    }

    let extra_db = state.certificates("db.extra", &args.extra_db)?;
    let option_rom_authorities =
        state.certificates("option-rom-authorities", &args.option_rom_authorities)?;

    let pk = SignatureList::x509(owner, pem_certificate_der(&args.pk_certificate)?).to_bytes()?;
    let kek =
        SignatureList::x509(owner, pem_certificate_der(&state.path("KEK.crt"))?).to_bytes()?;
    let db_cert = pem_certificate_der(&state.path("db.crt"))?;
    // Our key first, then the extra certificates, one list each (they differ in size).
    let db = std::iter::once(&db_cert)
        .chain(&extra_db)
        .map(|cert| SignatureList::x509(owner, cert.clone()).to_bytes())
        .collect::<Result<Vec<_>>>()?
        .concat();

    // All three signed by the PK: firmware accepts them in setup mode, and they can re-enroll
    // the same state after a firmware reset.
    if reissue {
        let timestamp = auth::efi_time_now();
        for (variable, data) in [
            (SecureBootVariable::Pk, &pk),
            (SecureBootVariable::Kek, &kek),
            (SecureBootVariable::Db, &db),
        ] {
            let update = auth::sign(variable, data, &timestamp, &args.pk, &args.pk_certificate)?;
            state.write(&format!("{}.auth", variable.name()), update)?;
        }
    } else if auth::data_of(&state.read("db.auth")?)? != db.as_slice() {
        // Only db changed (extra certificates): re-sign its update alone. KEK and the
        // certificates stay, so nothing else needs to be enrolled again.
        let update = auth::sign(
            SecureBootVariable::Db,
            &db,
            &auth::efi_time_now(),
            &args.pk,
            &args.pk_certificate,
        )?;
        state.write("db.auth", update)?;
        log::info!("db changed: issued a new db.auth. Stage and enroll it to take effect.");
    }

    let dbx = state.read("dbx.esl")?;
    let enrolled_state = SecureBootState {
        pk: &pk,
        kek: &kek,
        db: &db,
        dbx: &dbx,
    };
    let enrolled = pcr7::predict(&enrolled_state, &[&db_cert])?;
    state.write("pcr7.enrolled", hex(&enrolled))?;
    // With the option ROM cards installed, their CAs are measured before the boot loader's.
    // Without them, PCR 7 is `enrolled`, which stays approved: the machine boots either way.
    let with_option_roms = if option_rom_authorities.is_empty() {
        None
    } else {
        let authorities: Vec<&[u8]> = option_rom_authorities
            .iter()
            .chain(std::iter::once(&db_cert))
            .map(Vec::as_slice)
            .collect();
        let pcr7 = pcr7::predict(&enrolled_state, &authorities)?;
        state.write("pcr7.enrolled-option-roms", hex(&pcr7))?;
        Some(pcr7)
    };

    let current = parse_pcr(&state.read_string("pcr7.current")?)?;
    let deadline =
        state.read_string("clock.current")?.parse::<u64>()? + args.transition_minutes * 60_000;

    // Only db: the KEK signs db/dbx updates, so a KEK usable in the running system would let
    // root trust any key without the PK. Approve it per rotation instead.
    approve(
        &state,
        &["db"],
        "enrolled",
        &state.policy(enrolled)?,
        &args.pk,
    )?;
    if let Some(pcr7) = with_option_roms {
        approve(
            &state,
            &["db"],
            "enrolled-option-roms",
            &state.policy(pcr7)?,
            &args.pk,
        )?;
    }
    approve(
        &state,
        &["db"],
        "transition",
        &state.policy(current)?.until_clock(deadline),
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

/// Stage the enrollment updates in `loader/keys/auto` on the ESP, flushed to the device.
///
/// Called before the install signs anything with the TPM key, so a failure here leaves the ESP
/// as it was.
pub fn stage(dir: &Path, esp: &Path) -> Result<()> {
    let state = State(dir.to_owned());
    let keys = esp.join("loader/keys/auto");
    fs::create_dir_all(&keys)?;
    for variable in ["PK", "KEK", "db"] {
        let name = format!("{variable}.auth");
        let mut file = fs::File::create(keys.join(&name))?;
        std::io::Write::write_all(&mut file, &state.read(&name)?)?;
        // vfat has no sync_fs, but fsync flushes the file and the device cache.
        file.sync_all()
            .with_context(|| format!("Failed to flush {}", keys.join(&name).display()))?;
    }
    for dir in [&keys, &esp.join("loader"), &esp.to_path_buf()] {
        fs::File::open(dir)?.sync_all()?;
    }
    log::info!("Staged the enrollment updates in {}.", keys.display());
    Ok(())
}

/// The variables `clear-keys` deletes, in order.
///
/// Deleting KEK and db too means enrollment doesn't depend on the staged updates being newer
/// than what firmware stored: some firmware rejects older ones even in setup mode, leaving the
/// old KEK and db enrolled. The PK authorizes KEK updates, so the KEK goes first, while the
/// firmware still verifies. db updates need a KEK signature, so db goes last, once deleting the
/// PK has put the firmware in setup mode. dbx stays: enrollment does not replace it, and the
/// PCR 7 prediction counts on it.
const DELETED: [SecureBootVariable; 3] = [
    SecureBootVariable::Kek,
    SecureBootVariable::Pk,
    SecureBootVariable::Db,
];

/// Empty updates for [`DELETED`], signed by the current PK (`key`: anything OpenSSL can load).
fn sign_deletions(key: &str, certificate: &Path) -> Result<Vec<(SecureBootVariable, Vec<u8>)>> {
    let timestamp = auth::efi_time_now();
    DELETED
        .iter()
        .map(|&variable| {
            Ok((
                variable,
                auth::sign(variable, &[], &timestamp, key, certificate)?,
            ))
        })
        .collect()
}

fn deletion_file(dir: &Path, variable: SecureBootVariable) -> PathBuf {
    dir.join(format!("{}.delete.auth", variable.name()))
}

fn write_deletions(dir: &Path, updates: &[(SecureBootVariable, Vec<u8>)]) -> Result<()> {
    fs::create_dir_all(dir)?;
    for (variable, update) in updates {
        let path = deletion_file(dir, *variable);
        fs::write(&path, update).with_context(|| format!("Failed to write {}", path.display()))?;
    }
    log::info!(
        "Signed the deletions into {}. On the machine: `lzbt tpm clear-keys --from` that directory.",
        dir.display()
    );
    Ok(())
}

fn read_deletions(dir: &Path) -> Result<Vec<(SecureBootVariable, Vec<u8>)>> {
    DELETED
        .iter()
        .map(|&variable| {
            let path = deletion_file(dir, variable);
            let update =
                fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))?;
            ensure!(
                auth::data_of(&update)?.is_empty(),
                "{} is not a deletion",
                path.display()
            );
            Ok((variable, update))
        })
        .collect()
}

/// Delete KEK, PK and db with the signed `updates` (see [`DELETED`]), so the next boot is in
/// setup mode and enrolls `loader/keys/auto`. Safe to repeat: deleted variables are skipped.
fn apply_deletions(updates: &[(SecureBootVariable, Vec<u8>)]) -> Result<()> {
    for (variable, update) in updates {
        let name = variable.name();
        if read_efivar(name, variable.vendor())?.is_none() {
            log::info!("{name} is already deleted.");
            continue;
        }
        let result = write_efivar(name, variable.vendor(), update);
        if *variable == SecureBootVariable::Db {
            result.context(
                "Failed to delete db (the firmware may only enter setup mode on the next boot). \
                 KEK and PK are deleted: the next boot is in setup mode and replaces db with the \
                 staged update, if that is newer than the enrolled db",
            )?;
        } else {
            result.with_context(|| format!("Failed to delete {name}"))?;
        }
        log::info!("Deleted {name}.");
    }
    log::info!("The firmware is in setup mode: the next boot enrolls loader/keys/auto, if staged.");
    Ok(())
}

/// Delete KEK, PK and db with updates signed by the current PK (`key`: anything OpenSSL can
/// load). See [`apply_deletions`].
pub fn clear_keys(key: &str, certificate: &Path) -> Result<()> {
    apply_deletions(&sign_deletions(key, certificate)?)
}

/// Write an authenticated update to an existing EFI variable through efivarfs.
fn write_efivar(name: &str, vendor: Guid, update: &[u8]) -> Result<()> {
    let path = Path::new(EFIVARS).join(format!("{name}-{vendor}"));
    // efivarfs marks existing variables immutable; lift that for this write only.
    clear_immutable(&path)
        .with_context(|| format!("Failed to make {} writable", path.display()))?;
    let contents = [
        &auth::SECURE_BOOT_VARIABLE_ATTRIBUTES.to_le_bytes()[..],
        update,
    ]
    .concat();
    // One write(2): efivarfs rejects updates split across several.
    fs::write(&path, contents).with_context(|| format!("Failed to write {}", path.display()))
}

/// Clear `FS_IMMUTABLE_FL` (`chattr -i`).
fn clear_immutable(path: &Path) -> Result<()> {
    const FS_IMMUTABLE_FL: libc::c_int = 0x10;
    // The kernel reads and writes an int through these, despite the request number's `long`.
    nix::ioctl_read_bad!(get_flags, libc::FS_IOC_GETFLAGS, libc::c_int);
    nix::ioctl_write_ptr_bad!(set_flags, libc::FS_IOC_SETFLAGS, libc::c_int);

    let file = fs::File::open(path)?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
    let mut flags: libc::c_int = 0;
    // SAFETY: FS_IOC_GETFLAGS and FS_IOC_SETFLAGS access one int through the pointer.
    unsafe { get_flags(fd, &mut flags) }?;
    if flags & FS_IMMUTABLE_FL != 0 {
        flags &= !FS_IMMUTABLE_FL;
        unsafe { set_flags(fd, &flags) }?;
    }
    Ok(())
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

/// The DER bytes of a PEM certificate, exactly as issued (only validated, not re-encoded, so
/// the issuer's signature over them stays valid).
fn pem_certificate_der(path: &Path) -> Result<Vec<u8>> {
    let pem = fs::read(path)?;
    let (label, der) = x509_cert::der::pem::decode_vec(&pem)
        .map_err(|e| anyhow::anyhow!("Failed to read the certificate {}: {e}", path.display()))?;
    ensure!(
        label == "CERTIFICATE",
        "{} is not a certificate",
        path.display()
    );
    Certificate::from_der(&der)
        .with_context(|| format!("Invalid certificate {}", path.display()))?;
    Ok(der)
}

/// The DER bytes of a certificate file, PEM or DER.
fn certificate_der(path: &Path) -> Result<Vec<u8>> {
    let data = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    if data.starts_with(b"-----BEGIN") {
        return pem_certificate_der(path);
    }
    Certificate::from_der(&data)
        .with_context(|| format!("Invalid certificate {}", path.display()))?;
    Ok(data)
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

/// The TPM the keys live in: the kernel's resource manager, like the engine uses.
const TPM_DEVICE: &str = "/dev/tpmrm0";

/// A PCR of the SHA-256 bank, from the kernel (`/sys/class/tpm/tpm0/pcr-sha256/<index>`, a
/// single hex line).
fn read_pcr(index: u8) -> Result<[u8; 32]> {
    let path = format!("/sys/class/tpm/tpm0/pcr-sha256/{index}");
    let value = fs::read_to_string(&path).with_context(|| format!("Failed to read {path}"))?;
    parse_pcr(&value.trim().to_ascii_lowercase())
}

/// The TPM clock (milliseconds the TPM has been powered, only moves forward).
fn read_tpm_clock() -> Result<u64> {
    let device = DeviceConfig::from_str(TPM_DEVICE)?;
    let mut tpm = TpmContext::new(TctiNameConf::Device(device))
        .with_context(|| format!("Failed to open the TPM at {TPM_DEVICE}"))?;
    let time = tpm.read_clock().context("Failed to read the TPM clock")?;
    Ok(time.clock_info().clock())
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
