use crate::pe::lanzaboote_image;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use tempfile::tempdir;

use super::Signer;

/// A local keypair is a signer that reuses private key material
/// on the disk.
///
/// The security of the private key is the responsibility of the user.
///
/// Signing happens via `systemd-sbsign`. `private_key_source` is passed on as
/// `--private-key-source=` (e.g. `provider:tpm2`), so the private key can also
/// be a reference to a key held by an OpenSSL provider rather than a PEM file.
///
/// Signatures are made with a fixed signing time, so signing the same input
/// with the same RSA key yields identical bytes. That lets callers re-sign
/// unconditionally and only write the result when it differs.
#[derive(Debug, Clone)]
pub struct LocalKeyPair {
    pub private_key: PathBuf,
    pub private_key_source: Option<String>,
    pub public_key: PathBuf,
}

impl LocalKeyPair {
    pub fn new(public_key: &Path, private_key: &Path, private_key_source: Option<String>) -> Self {
        Self {
            public_key: public_key.into(),
            private_key: private_key.into(),
            private_key_source,
        }
    }
}

impl Signer for LocalKeyPair {
    fn get_public_key(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.public_key).with_context(|| {
            format!(
                "Failed to read public key from {}",
                self.public_key.display()
            )
        })
    }

    fn sign_and_copy(&self, from: &Path, to: &Path) -> Result<()> {
        let mut args: Vec<OsString> = vec![
            OsString::from("sign"),
            OsString::from("--private-key"),
            self.private_key.clone().into(),
            OsString::from("--certificate"),
            self.public_key.clone().into(),
            OsString::from("--output"),
            to.as_os_str().to_owned(),
        ];
        if let Some(source) = &self.private_key_source {
            args.push(OsString::from("--private-key-source"));
            args.push(source.into());
        }
        args.push(from.as_os_str().to_owned());

        let output = Command::new("systemd-sbsign")
            // The signing time is part of the signature. Pinning it makes the
            // output reproducible; the value carries no meaning for Secure Boot.
            .env("SOURCE_DATE_EPOCH", "1")
            .args(&args)
            .output()
            .context("Failed to run systemd-sbsign. Most likely, the binary is not on PATH.")?;

        if !output.status.success() {
            std::io::stderr()
                .write_all(&output.stderr)
                .context("Failed to write output of systemd-sbsign to stderr.")?;
            log::debug!("systemd-sbsign failed with args: `{args:?}`.");
            return Err(anyhow::anyhow!("Failed to sign {to:?}."));
        }

        Ok(())
    }

    fn sign_store_path(&self, store_path: &Path) -> Result<Vec<u8>> {
        let working_tree = tempdir()?;
        let to = &working_tree.path().join("signed.efi");
        self.sign_and_copy(store_path, to)?;

        Ok(std::fs::read(to)?)
    }

    fn build_and_sign_stub(&self, stub: &crate::pe::StubParameters) -> Result<Vec<u8>> {
        let working_tree = tempdir()?;
        let lzbt_image_path =
            lanzaboote_image(&working_tree, stub).context("Failed to build a lanzaboote image")?;
        let to = working_tree.path().join("signed-stub.efi");
        self.sign_and_copy(&lzbt_image_path, &to)?;

        std::fs::read(&to).context("Failed to read a lanzaboote image")
    }
}
