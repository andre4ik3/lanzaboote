//! Pass a random seed to the kernel, like systemd-stub and systemd-boot do.
//!
//! A port of systemd's `src/boot/random-seed.c`: the seed file on the ESP
//! (`\loader\random-seed`), the firmware RNG, the system token (`LoaderSystemToken`), the UEFI
//! monotonic counter and the time are hashed into a new seed file and a seed for the kernel,
//! handed over as the `LINUX_EFI_RANDOM_SEED_TABLE_GUID` configuration table. The kernel credits
//! it before its own RNG is initialised; `systemd-boot-random-seed.service` refreshes the file
//! from the booted system.

use core::ptr::NonNull;

use sha2::{Digest, Sha256};
use uefi::boot::{self, MemoryType};
use uefi::fs::{FileSystem, Path};
use uefi::proto::rng::Rng;
use uefi::runtime;
use uefi::system;
use uefi::table::cfg::ConfigTableEntry;
use uefi::{Guid, Result, Status, StatusExt, cstr16, guid};

use crate::efivars::BOOT_LOADER_VENDOR_UUID;

/// `LINUX_EFI_RANDOM_SEED_TABLE_GUID`.
static LINUX_EFI_RANDOM_SEED_TABLE: Guid = guid!("1ce1e5bc-7ceb-42f2-81e5-8aadf180f57b");

/// Linux's RNG is 256 bits.
const SEED_SIZE: usize = 32;
const FILE_SIZE_MIN: usize = 32;
const FILE_SIZE_MAX: usize = 32 * 1024;
/// Domain separation, as systemd uses it: the file is shared with systemd-boot.
const HASH_LABEL: &[u8] = b"systemd-boot random seed label v1";

/// The `linux_efi_random_seed` table: a u32 size, then that many bytes of seed.
#[repr(C)]
struct SeedTable {
    size: u32,
    seed: [u8; SEED_SIZE],
}

/// Hashes `size || data` pairs like systemd's (sizes as native `size_t`).
struct SeedHash(Sha256);

impl SeedHash {
    fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(HASH_LABEL);
        Self(hash)
    }

    fn input(&mut self, data: &[u8]) {
        self.0.update(data.len().to_ne_bytes());
        self.0.update(data);
    }
}

/// The current seed table, if the firmware or a boot loader installed one.
fn previous_seed() -> Option<&'static [u8]> {
    system::with_config_table(|entries: &[ConfigTableEntry]| {
        let entry = entries
            .iter()
            .find(|entry| entry.guid == LINUX_EFI_RANDOM_SEED_TABLE)?;
        let table = entry.address.cast::<u32>();
        // SAFETY: the table is a u32 size followed by that many bytes, and stays allocated.
        unsafe {
            let size = table.read_unaligned() as usize;
            Some(core::slice::from_raw_parts(table.add(1).cast::<u8>(), size))
        }
    })
}

fn firmware_rng(buffer: &mut [u8]) -> Result {
    let handle = boot::get_handle_for_protocol::<Rng>()?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle)?;
    rng.get_rng(None, buffer)
}

fn system_token() -> Option<alloc::boxed::Box<[u8]>> {
    runtime::get_variable_boxed(cstr16!("LoaderSystemToken"), &BOOT_LOADER_VENDOR_UUID)
        .ok()
        .map(|(data, _)| data)
        .filter(|data| !data.is_empty())
}

fn monotonic_count() -> Option<u64> {
    let bs = uefi::table::system_table_raw()?;
    // SAFETY: the system table and its boot services are valid while boot services run.
    unsafe {
        let bs = bs.as_ref().boot_services.as_ref()?;
        let mut count = 0u64;
        (bs.get_next_monotonic_count)(&mut count).to_result().ok()?;
        Some(count)
    }
}

/// Refresh the seed file on the ESP `fs` and install a new seed table for the kernel.
///
/// Like systemd, it only proceeds with enough entropy: the firmware RNG, a previous seed table,
/// or (without Secure Boot) a system token together with a seed file.
pub fn process(fs: &mut FileSystem, secure_boot: bool) -> Result {
    let mut hash = SeedHash::new();

    let previous = previous_seed();
    let mut seeded_by_efi = previous.is_some_and(|seed| seed.len() >= SEED_SIZE);
    hash.input(previous.unwrap_or_default());

    // The firmware RNG protects against a seed file copied between machines.
    let mut random = [0u8; SEED_SIZE];
    if firmware_rng(&mut random).is_ok() {
        seeded_by_efi = true;
        hash.input(&random);
    } else {
        hash.input(&[]);
        // Without it, the only entropy is the mutable ESP: not with Secure Boot.
        if !seeded_by_efi && secure_boot {
            return Err(Status::NOT_FOUND.into());
        }
    }
    random.fill(0);

    // Set once per installation: protects against sloppy golden images.
    let token = system_token();
    if !seeded_by_efi && token.as_ref().is_none_or(|t| t.len() < SEED_SIZE) {
        return Err(Status::NOT_FOUND.into());
    }
    hash.input(token.as_deref().unwrap_or_default());

    let path = Path::new(cstr16!("\\loader\\random-seed"));
    let file = match fs.read(path) {
        Ok(file) if file.len() > FILE_SIZE_MAX => return Err(Status::INVALID_PARAMETER.into()),
        Ok(file) if file.len() >= FILE_SIZE_MIN => Some(file),
        // A short file counts as a new one, like a file created just before a power loss.
        Ok(_) => None,
        Err(_) if seeded_by_efi => None,
        Err(_) => return Err(Status::NOT_FOUND.into()),
    };
    hash.input(file.as_deref().unwrap_or_default());

    // Differs on every boot, even if the ESP write below is lost.
    hash.input(&monotonic_count().unwrap_or_default().to_ne_bytes());
    match runtime::get_time() {
        Ok(time) => hash.input(
            &[
                &time.year().to_le_bytes()[..],
                &[
                    time.month(),
                    time.day(),
                    time.hour(),
                    time.minute(),
                    time.second(),
                ],
                &time.nanosecond().to_le_bytes(),
            ]
            .concat(),
        ),
        Err(_) => hash.input(&[]),
    }

    let key = hash.0.finalize();
    let derive = |n: u8| -> [u8; SEED_SIZE] {
        let mut hash = Sha256::new();
        hash.update(key);
        hash.update([n]);
        hash.finalize().into()
    };

    // Update the file before using the seed, zeroing any extra length.
    let mut new_file = derive(0).to_vec();
    new_file.resize(
        file.as_ref().map_or(SEED_SIZE, |f| f.len().max(SEED_SIZE)),
        0,
    );
    fs.write(path, &new_file)
        .map_err(|_| Status::DEVICE_ERROR)?;
    new_file.fill(0);

    let table = boot::allocate_pool(MemoryType::ACPI_RECLAIM, size_of::<SeedTable>())?;
    let table = table.cast::<SeedTable>();
    // SAFETY: freshly allocated, suitably sized and aligned for SeedTable.
    unsafe {
        table.write(SeedTable {
            size: SEED_SIZE as u32,
            seed: derive(1),
        });
        if let Err(e) =
            boot::install_configuration_table(&LINUX_EFI_RANDOM_SEED_TABLE, table.as_ptr().cast())
        {
            let _ = boot::free_pool(table.cast());
            return Err(e);
        }
    }

    // The previous table was replaced: wipe it.
    if let Some(previous) = previous {
        // SAFETY: the old table is no longer referenced by the configuration table.
        unsafe {
            core::ptr::write_bytes(previous.as_ptr().cast_mut(), 0, previous.len());
            let _ = boot::free_pool(NonNull::new_unchecked(
                previous
                    .as_ptr()
                    .cast_mut()
                    .sub(size_of::<u32>())
                    .cast::<u8>(),
            ));
        }
    }
    Ok(())
}
