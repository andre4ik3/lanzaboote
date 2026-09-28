# lzbt refuses to install a new generation that would not unlock the machine's disk the way it is
# enrolled, and leaves the ESP booting the generations it had before.
#
# The cases are configurations that broke real machines: a token bound to a PCR 11 key the
# initrd isn't signed with, a crypttab without tpm2-device=, and a wrong fixate-volume-key=.
{ lib, ... }:

let
  base =
    { pkgs, ... }:
    let
      mkKeyPair =
        name:
        pkgs.runCommand name { } ''
          mkdir $out
          ${lib.getExe pkgs.openssl} genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $out/private.pem
          ${lib.getExe pkgs.openssl} rsa -pubout -in $out/private.pem -out $out/public.pem
        '';
      initrdKey = mkKeyPair "tpm2-pcr-initrd-key";
      hostKey = mkKeyPair "tpm2-pcr-host-key";
    in
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest.persistentRoot = true;
      # Room for the variants' UKIs (one per specialisation) next to the generation's own.
      image.repart.partitions.esp.repartConfig.SizeMinBytes = lib.mkForce "256M";
      # Small, so a refused generation would push a good one out if it counted.
      boot.lanzaboote.configurationLimit = 2;
      virtualisation.tpm.enable = true;
      virtualisation.emptyDiskImages = [
        {
          driveConfig.name = "crypt";
          size = 32;
        }
      ];

      boot.initrd.systemd.enable = true;
      boot.initrd.systemd.tpm2.pcrphases.enable = true;
      systemd.tpm2.pcrphases.enable = true;
      # nofail volumes aren't waited for: open it in the initrd, where its token applies.
      boot.initrd.systemd.services."systemd-cryptsetup@".before = [
        "cryptsetup.target"
        "initrd-switch-root.target"
      ];
      boot.initrd.luks.devices.crypt = {
        device = "/dev/disk/by-label/crypt";
        crypttabExtraOpts = [
          "tpm2-device=auto"
          "tpm2-measure-pcr=yes"
          "nofail"
          "headless=true"
        ];
      };

      boot.lanzaboote.measuredBoot.pcrSignatures = lib.mkDefault [
        {
          privateKeyFile = "${initrdKey}/private.pem";
          phases = [ "enter-initrd" ];
          banks = [ "sha256" ];
        }
        {
          privateKeyFile = "${hostKey}/private.pem";
          phases = [ "enter-initrd:leave-initrd:sysinit:ready" ];
          banks = [ "sha256" ];
        }
      ];

      environment.systemPackages = [
        pkgs.cryptsetup
        pkgs.jq
      ];
      environment.etc."keys/initrd.pem".source = "${initrdKey}/public.pem";

      _module.args = { inherit hostKey; };
    };

  # New generations to install, each a whole system like a deploy would add.
  variants = {
    good = { };
    no-tpm2-device = {
      boot.initrd.luks.devices.crypt.crypttabExtraOpts = lib.mkForce [
        "tpm2-measure-pcr=yes"
        "nofail"
        "headless=true"
      ];
    };
    wrong-fixate = {
      boot.initrd.luks.devices.crypt.crypttabExtraOpts = [
        "fixate-volume-key=${lib.strings.replicate 32 "ab"}"
      ];
    };
    no-initrd-signature =
      { hostKey, ... }:
      {
        boot.lanzaboote.measuredBoot.pcrSignatures = [
          {
            privateKeyFile = "${hostKey}/private.pem";
            phases = [ "enter-initrd:leave-initrd:sysinit:ready" ];
            banks = [ "sha256" ];
          }
        ];
      };
  };
in
{
  name = "lanzaboote-install-guard";

  nodes.machine = {
    imports = [ base ];
    # The variants as specialisations: nothing else puts extra systems into the test image.
    # Their toplevels are what the test installs as new generations; `variant` keeps each one
    # distinct.
    specialisation = lib.mapAttrs (name: variant: {
      inheritParentConfig = true;
      configuration = {
        imports = [ variant ];
        environment.etc."variant".text = name;
      };
    }) variants;
  };

  testScript =
    { nodes, ... }:
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + ''
      machine.wait_for_unit("multi-user.target")
      variants = {
          name: machine.succeed(f"readlink -f /run/current-system/specialisation/{name}").strip()
          for name in ${builtins.toJSON (builtins.attrNames variants)}
      }

      def sh(cmd):
          return machine.succeed(f"set -euo pipefail; {cmd}")

      def entries():
          return sorted(sh("ls /boot/EFI/Linux").split())

      generation = [1]

      def install(name, env=""):
          """Add the variant as the newest generation and run the install hook, as a deploy does.

          The store is read-only (erofs), so the profile link is made by hand, as nix-env would."""
          generation[0] += 1
          sh(
              f"ln -sfn {variants[name]} /nix/var/nix/profiles/system-{generation[0]}-link && "
              f"ln -sfn system-{generation[0]}-link /nix/var/nix/profiles/system"
          )
          return machine.execute(f"{env} {variants[name]}/bin/switch-to-configuration boot 2>&1")

      with subtest("Setup: enroll the disk for the initrd's signed PCR 11 and an unused PCR 15"):
          sh("echo 1234 | cryptsetup luksFormat /dev/vdb - --label crypt")
          sh(
              "echo 1234 | systemd-cryptenroll --unlock-key-file=/dev/stdin --tpm2-device=auto "
              "--tpm2-public-key=/etc/keys/initrd.pem --tpm2-public-key-pcrs=11 "
              "--tpm2-pcrs=15:sha256=" + "0" * 64 + " /dev/vdb"
          )
          # The running generation doesn't know the disk yet; install one that does, then boot it.
          status, out = install("good")
          print(out)
          t.assertEqual(status, 0, "a generation that unlocks installs")
          machine.reboot()
          machine.wait_for_unit("multi-user.target")
          machine.succeed("test -e /dev/mapper/crypt")
          measured = sh(
              "tr -d '\\036' < /run/log/systemd/tpm2-measure.log "
              "| jq -r 'select(.pcr == 15) | .digests[] | select(.hashAlg == \"sha256\") | .digest'"
          ).strip()
          t.assertEqual(len(measured), 64)

      for name, expect in [
          ("no-tpm2-device", "tpm2-device"),
          ("no-initrd-signature", "no such signature"),
          ("wrong-fixate", "not this volume's key"),
      ]:
          with subtest(f"Refused: {name}"):
              before = entries()
              status, out = install(name)
              print(out)
              t.assertNotEqual(status, 0, "the install fails")
              t.assertIn(expect, out)
              t.assertIn("boots the generations it had before", out)
              after = entries()
              t.assertFalse(
                  any(e.startswith(f"nixos-generation-{generation[0]}-") for e in after),
                  "the refused generation is not on the ESP",
              )
              # Nothing is garbage collected. (An earlier refused generation may appear: it is
              # re-signed with this install's PCR signing keys, and then passes.)
              t.assertTrue(set(before) <= set(after), "no entry was removed")

      with subtest("LZBT_ALLOW_RECOVERY installs it anyway"):
          before = entries()
          status, out = install("no-tpm2-device", env="LZBT_ALLOW_RECOVERY=1")
          print(out)
          t.assertEqual(status, 0)
          t.assertNotEqual(entries(), before)

      with subtest("The good generation still unlocks the disk after a reboot"):
          status, out = install("good")
          t.assertEqual(status, 0, out)
          machine.reboot()
          machine.wait_for_unit("multi-user.target")
          machine.succeed("test -e /dev/mapper/crypt")
    '';
}
