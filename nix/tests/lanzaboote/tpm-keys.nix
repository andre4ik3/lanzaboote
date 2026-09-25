# Moving a machine from file Secure Boot keys (the test fixture) to a KEK and db held in its TPM,
# with the PK on a PKCS#11 token (kryoptic stands in for a hardware token such as a YubiKey).
#
# Covers `lzbt tpm init`/`authorize`, `lzbt install --transition-dir` (dual signing, staged
# enrollment, PK deletion), systemd-boot enrolling in setup mode, the PCR 7 prediction, and that
# the keys refuse to sign in any other Secure Boot state.
{ pkgs, ... }:

let
  tokenModule = "${pkgs.kryoptic}/lib/libkryoptic_pkcs11.so";
  pkcs11Config = pkgs.writeText "openssl-pkcs11.cnf" ''
    openssl_conf = init
    [init]
    providers = prov
    [prov]
    default = def
    pkcs11 = p11
    [def]
    activate = 1
    [p11]
    module = ${pkgs.pkcs11-provider}/lib/ossl-modules/pkcs11.so
    pkcs11-module-path = ${tokenModule}
    pkcs11-module-token-pin = 1234
    activate = 1
  '';
in
{
  name = "lanzaboote-tpm-keys";

  extraPythonPackages = p: [ p.virt-firmware ];

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest.persistentRoot = true;
      virtualisation.tpm.enable = true;

      environment.systemPackages = [
        config.boot.lanzaboote.package
        config.boot.lanzaboote.package.openssl-tpm2-engine
        pkgs.kryoptic
        pkgs.opensc
        pkgs.openssl
        pkgs.python3
        pkgs.sbsigntool
        pkgs.tpm2-tools
      ];
      environment.variables = {
        KRYOPTIC_CONF = "/var/lib/token/kryoptic.conf";
      };
      # The image only carries the node's closure: the config, and the install hook the test runs
      # by hand, must be part of it.
      environment.etc."ssl/pkcs11.cnf".source = pkcs11Config;
      system.extraDependencies = [ config.system.build.installBootLoader ];
    };

  testScript =
    { nodes, ... }:
    let
      machine = nodes.machine;
      cfg = machine.boot.lanzaboote;
    in
    (import ./common/image-helper.nix { inherit machine; })
    + ''
      import subprocess

      fixture = "/var/lib/lanzaboote-test-fixture/keys"
      state = "/var/lib/lanzaboote-tpm"
      pk_uri = "pkcs11:token=pk;object=PK;type=private"
      token = "pkcs11-tool --module ${tokenModule}"

      def sh(cmd):
          return machine.succeed(f"set -euo pipefail; {cmd}")

      def pcr7():
          return sh("tpm2_pcrread sha256:7 | awk '$1 == \"7\" {sub(/^0x/, \"\", $3); print tolower($3)}'").strip()

      def db_subjects():
          return sh(
              "python3 - <<'PY'\n"
              "import struct, subprocess\n"
              "d = open('/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f', 'rb').read()[4:]\n"
              "o = 0\n"
              "while o + 28 <= len(d):\n"
              "    ls, hs, ss = struct.unpack_from('<III', d, o + 16)\n"
              "    for p in range(o + 28 + hs, o + ls, ss):\n"
              "        print(subprocess.run(['openssl', 'x509', '-inform', 'der', '-noout', '-subject'], input=d[p + 16:p + ss], capture_output=True).stdout.decode().strip())\n"
              "    o += ls\n"
              "PY"
          ).strip().splitlines()

      def can_sign(key):
          status, _ = machine.execute(
              f"echo -n x | OPENSSL_MODULES=$(dirname ${cfg.package.tpm2Provider}) openssl pkeyutl -sign "
              f"-provider tpm2 -provider default -inkey {state}/{key}.key -rawin -digest sha256 -out /dev/null"
          )
          return status == 0

      def edit_varstore(*args):
          path = str(machine.efi_vars_path)
          subprocess.run(["virt-fw-vars", "-i", path, "-o", path + ".new", *args], check=True)
          subprocess.run(["mv", path + ".new", path], check=True)

      with subtest("Starting point: Secure Boot on with the fixture keys"):
          machine.wait_for_unit("multi-user.target")
          t.assertIn("Secure Boot: enabled (user)", machine.succeed("bootctl status"))
          t.assertEqual(db_subjects(), ["subject=C=Database Key, CN=Database Key"])

      with subtest("PK on a PKCS#11 token"):
          sh("mkdir -p /var/lib/token && printf '[[slots]]\\nslot = 42\\ndbtype = \"sqlite\"\\ndbargs = \"/var/lib/token/token.sql\"\\n' > $KRYOPTIC_CONF")
          sh(f"{token} --init-token --slot 42 --label pk --so-pin 5678")
          sh(f"{token} --slot 42 --init-pin --login --so-pin 5678 --pin 1234")
          sh(f"{token} --slot 42 --login --pin 1234 --keypairgen --key-type rsa:2048 --label PK --id 01")
          sh(f"mkdir -p {state} && {token} --slot 42 --read-object --type pubkey --label PK -o /tmp/pk.der")
          sh(f"openssl pkey -pubin -inform DER -in /tmp/pk.der -out {state}/PK.pub")
          sh(
              f"OPENSSL_CONF=/etc/ssl/pkcs11.cnf openssl req -x509 -new -key '{pk_uri}' "
              "-subj '/CN=Platform Key (token)/' -days 36500 "
              "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,digitalSignature "
              "-out /var/lib/token/PK.crt"
          )

      with subtest("lzbt tpm init: KEK and db in the TPM, unusable so far"):
          sh(f"lzbt tpm init {state}")
          t.assertFalse(can_sign("db"))
          t.assertFalse(can_sign("KEK"))

      with subtest("lzbt tpm authorize: certificates, enrollment updates and approvals from the token"):
          sh(
              f"OPENSSL_CONF=/etc/ssl/pkcs11.cnf lzbt tpm authorize {state} "
              f"--pk '{pk_uri}' --pk-certificate /var/lib/token/PK.crt --transition-minutes 10"
          )
          enrolled = sh(f"cat {state}/pcr7.enrolled").strip()
          sh(f"openssl verify -CAfile /var/lib/token/PK.crt {state}/KEK.crt {state}/db.crt")
          t.assertTrue(can_sign("db"), "the transition approval covers the current state")

      with subtest("lzbt install --transition-dir: dual-signed ESP, staged enrollment, PK deleted"):
          # The NixOS install hook, as switch-to-configuration runs it.
          sh(
              f"LZBT_TRANSITION_DIR={state} "
              f"LZBT_CLEAR_PK_KEY={fixture}/PK/PK.key LZBT_CLEAR_PK_CERTIFICATE={fixture}/PK/PK.pem "
              "${machine.system.build.installBootLoader}"
          )
          for cert in [f"{fixture}/db/db.pem", f"{state}/db.crt"]:
              sh(f"sbverify --cert {cert} /boot/EFI/systemd/systemd-bootx64.efi")
              sh(f"sbverify --cert {cert} /boot/EFI/Linux/nixos-generation-1-*.efi")
          sh("test -e /boot/loader/keys/auto/PK.auth")
          # The PK is gone; SetupMode itself only changes on the next boot.
          machine.fail("test -e /sys/firmware/efi/efivars/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c")

      with subtest("Reboot: systemd-boot enrolls, the TPM-signed chain boots"):
          machine.reboot()
          machine.wait_for_unit("multi-user.target")
          t.assertIn("Secure Boot: enabled (user)", machine.succeed("bootctl status"))
          t.assertEqual(db_subjects(), ["subject=CN=Database Key (TPM)"])

      with subtest("PCR 7 is exactly the predicted value, and both keys sign"):
          t.assertEqual(pcr7(), enrolled)
          t.assertTrue(can_sign("db"))
          t.assertTrue(can_sign("KEK"))

      with subtest("The keys do not depend on PCR 15"):
          # PCR 15 holds a measurement of the volume key that is not secret (it equals
          # fixate-volume-key=), so it proves nothing on its own; the keys are bound to PCR 7.
          sh("tpm2_pcrextend 15:sha256=" + "ab" * 32)
          t.assertTrue(can_sign("db"))

      with subtest("An expiring approval stops working once the TPM clock passes it"):
          # A separate key whose only approval is "this PCR 7 until the clock passes limit".
          sh(f"mkdir -p /tmp/expiring && cp {state}/PK.pub /tmp/expiring/")
          sh("create_tpm2_key --rsa --key-size 2048 --signed-policy /tmp/expiring/PK.pub /tmp/expiring/db.key")
          limit = int(sh("tpm2_readclock | awk '/^ *clock:/{print $2}'").strip()) + 60_000
          sh(
              f"OPENSSL_CONF=/etc/ssl/pkcs11.cnf lzbt tpm approve /tmp/expiring --key db "
              f"--pk '{pk_uri}' --pcr7 {pcr7()} --until-clock {limit} --name window"
          )
          def expiring_signs():
              status, _ = machine.execute(
                  "echo -n x | OPENSSL_MODULES=$(dirname ${cfg.package.tpm2Provider}) openssl pkeyutl -sign "
                  "-provider tpm2 -provider default -inkey /tmp/expiring/db.key -rawin -digest sha256 -out /dev/null"
              )
              return status == 0
          t.assertTrue(expiring_signs(), "inside the window")
          # TPM2_ClockSet only moves the clock forward (owner auth is empty in the VM).
          sh(f"tpm2_setclock {limit + 1000}")
          t.assertFalse(expiring_signs(), "after the window")
          t.assertTrue(can_sign("db"), "the enrolled approval has no expiry")

      with subtest("Secure Boot disabled in firmware: both keys refuse"):
          machine.shutdown()
          edit_varstore("--set-false", "SecureBootEnable")
          machine.start(allow_reboot=True)
          machine.wait_for_unit("multi-user.target")
          t.assertIn("Secure Boot: disabled", machine.succeed("bootctl status"))
          t.assertFalse(can_sign("db"))
          t.assertFalse(can_sign("KEK"))

      with subtest("Firmware keys wiped: re-enrolling the staged updates restores PCR 7 and the keys"):
          machine.shutdown()
          edit_varstore("--delete", "PK", "--delete", "KEK", "--delete", "db", "--set-true", "SecureBootEnable")
          machine.start(allow_reboot=True)
          machine.wait_for_unit("multi-user.target")
          t.assertIn("Secure Boot: enabled (user)", machine.succeed("bootctl status"))
          t.assertEqual(pcr7(), enrolled)
          t.assertTrue(can_sign("db"))
          t.assertTrue(can_sign("KEK"))
    '';
}
