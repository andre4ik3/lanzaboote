use std::path::Path;

use anyhow::{Context, Result};
use tempfile::tempdir;

use super::Signer;
use crate::pe::StubParameters;

/// Signs with two keys: every binary carries a signature from each.
///
/// This is for moving between Secure Boot keys: a binary signed by both the old and the new db
/// key boots whichever of them firmware trusts, so the ESP stays bootable across the switch.
/// PE binaries hold any number of signatures and `systemd-sbsign` appends rather than replaces,
/// so the second signature is simply added on top of the first.
pub struct DualSigner<A, B> {
    pub first: A,
    pub second: B,
}

impl<A: Signer, B: Signer> Signer for DualSigner<A, B> {
    fn sign_store_path(&self, store_path: &Path) -> Result<Vec<u8>> {
        let dir = tempdir()?;
        let once = dir.path().join("once.efi");
        std::fs::write(&once, self.first.sign_store_path(store_path)?)?;
        self.second
            .sign_store_path(&once)
            .context("Failed to add the second signature")
    }

    fn build_and_sign_stub(&self, stub: &StubParameters) -> Result<Vec<u8>> {
        let dir = tempdir()?;
        let once = dir.path().join("once.efi");
        std::fs::write(&once, self.first.build_and_sign_stub(stub)?)?;
        self.second
            .sign_store_path(&once)
            .context("Failed to add the second signature")
    }

    /// Both keys, so stubs are named (and rebuilt) differently from those signed by either key
    /// alone: installing with a single key again replaces the dual-signed ones.
    fn get_public_key(&self) -> Result<Vec<u8>> {
        Ok([self.first.get_public_key()?, self.second.get_public_key()?].concat())
    }
}
