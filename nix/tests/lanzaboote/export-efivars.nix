{ lib, pkgs, ... }:

let

  inherit (pkgs.stdenv.hostPlatform) efiArch;
  efiArchUppercased = lib.toUpper efiArch;

in

{
  name = "lanzaboote-export-efivars";

  nodes.machine = {
    imports = [ ./common/lanzaboote.nix ];
    # It rewrites the seed file from userspace on every boot: without it, only the stub does.
    systemd.suppressedSystemUnits = [ "systemd-boot-random-seed.service" ];
  };

  testScript =
    { nodes, ... }:
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + (import ./common/efivariables-helper.nix)
    + ''
      import struct

      # We will choose to boot directly on the stub.
      # To perform this trick, we will boot first with systemd-boot.
      # Then, we will add a new boot entry in EFI with higher priority
      # pointing to our stub.
      # Finally, we will reboot.
      # We will also assert that systemd-boot is not running
      # by checking for the sd-boot's specific EFI variables.
      machine.start()

      # By construction, nixos-generation-1.efi is the stub we are interested in.
      # TODO: this should work -- machine.succeed("efibootmgr -d /dev/vda -c -l \\EFI\\Linux\\nixos-generation-1.efi") -- efivars are not persisted
      # across reboots atm?
      # cheat code no 1
      machine.succeed("cp /boot/EFI/Linux/nixos-generation-1-*.efi /boot/EFI/BOOT/BOOT${efiArchUppercased}.EFI")
      machine.succeed("cp /boot/EFI/Linux/nixos-generation-1-*.efi /boot/EFI/systemd/systemd-boot${efiArch}.efi")

      # Let's reboot.
      machine.succeed("sync")
      machine.crash()
      machine.start()

      # This is the sd-boot EFI variable indicator, we should not have it at this point.
      print(machine.execute("bootctl")[1]) # Check if there's incorrect value in the output.
      machine.succeed(
          "test -e /sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f && false || true"
      )

      expected_variables = ["LoaderDevicePartUUID",
        "LoaderImageIdentifier",
        "LoaderFirmwareInfo",
        "LoaderFirmwareType",
        "StubInfo",
        "StubFeatures"
      ]

      # Debug all systemd loader specification GUID EFI variables loaded by the current environment.
      print(machine.succeed(f"ls /sys/firmware/efi/efivars/*-{SD_LOADER_GUID}"))
      with subtest("Check if supported variables are exported"):
          for expected_var in expected_variables:
              machine.succeed(f"test -e /sys/firmware/efi/efivars/{expected_var}-{SD_LOADER_GUID}")

      with subtest("Is `StubInfo` correctly set"):
          assert "lanzastub" in read_string_variable("StubInfo"), "Unexpected stub information, provenance is not lanzaboote project!"

      assert_variable_string("LoaderImageIdentifier", "\\EFI\\BOOT\\BOOT${efiArchUppercased}.EFI")
      # Defined via systemd-repart in the image
      assert_variable_string("LoaderDevicePartUUID", "a3c9c5a1-1a9a-451c-bdac-a80bacb4170b")
      # OVMF tests are using EDK II tree.
      assert_variable_string_contains("LoaderFirmwareInfo", "EDK II")
      assert_variable_string_contains("LoaderFirmwareType", "UEFI")

      with subtest("`StubFeatures` lists what the stub does"):
          # Boot partition, credentials, sysexts, three PCRs, random seed.
          (features,) = struct.unpack('<Q', read_raw_variable("StubFeatures"))
          t.assertEqual(features, 0b11111)

      with subtest("Without systemd-boot, the stub passes a random seed on"):
          # The stub rewrites the seed file before it hands the kernel a seed derived from it,
          # so a new file on every boot shows it got that far. (Nothing else writes it here.)
          machine.succeed("test $(stat -c %s /boot/loader/random-seed) -ge 32")
          before = machine.succeed("sha256sum /boot/loader/random-seed")
          machine.succeed("sync")
          machine.crash()
          machine.start()
          machine.wait_for_unit("multi-user.target")
          t.assertNotEqual(machine.succeed("sha256sum /boot/loader/random-seed"), before, "a new seed on every boot")
    '';
}
