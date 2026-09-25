{
  lib,
  buildRustApp,
  makeBinaryWrapper,
  binutils-unwrapped,
  openssl,
  pkg-config,
  tpm2-tss,
  systemd,
  stub,
}:

buildRustApp {
  pname = "lzbt-systemd";
  src = lib.sourceFilesBySuffices ../../rust/tool [
    ".rs"
    ".toml"
    ".lock"
    # Test fixtures
    ".pem"
    ".key"
    ".esl"
    ".hex"
    ".pub"
  ];
  # tss-esapi links tpm2-tss (the TPM clock, and parsing key files).
  args = {
    nativeBuildInputs = [ pkg-config ];
    buildInputs = [ tpm2-tss ];
  };
  packageArgs = {
    nativeBuildInputs = [
      makeBinaryWrapper
      pkg-config
    ];

    nativeCheckInputs = [
      binutils-unwrapped
      # To inspect signatures in the integration tests.
      openssl
    ];

    env.TEST_SYSTEMD = systemd;

    # systemd-sbsign lives in lib/systemd, which is not on PATH by default.
    preCheck = ''
      export PATH=${systemd}/lib/systemd:$PATH
    '';

    postInstall =
      let
        path = lib.makeBinPath [
          binutils-unwrapped
        ];
      in
      ''
        makeWrapper $out/bin/lzbt-systemd $out/bin/lzbt \
          --prefix PATH : ${path} \
          --set LANZABOOTE_STUB ${stub}/bin/lanzaboote_stub.efi
      '';

    meta.mainProgram = "lzbt";
  };
}
