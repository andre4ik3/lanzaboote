{
  lib,
  buildRustApp,
  makeBinaryWrapper,
  binutils-unwrapped,
  openssl,
  openssl-tpm2-engine,
  tpm2-tools,
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
  ];
  packageArgs = {
    nativeBuildInputs = [
      makeBinaryWrapper
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
          # `lzbt tpm`: signing certificates and enrollment updates, TPM keys and state.
          openssl
          openssl-tpm2-engine
          tpm2-tools
        ];
      in
      ''
        makeWrapper $out/bin/lzbt-systemd $out/bin/lzbt \
          --prefix PATH : ${path} \
          --set LANZABOOTE_STUB ${stub}/bin/lanzaboote_stub.efi \
          --set LZBT_TPM2_PROVIDER ${openssl-tpm2-engine}/lib/ossl-modules/tpm2.so
      '';

    passthru = {
      inherit openssl-tpm2-engine;
      tpm2Provider = "${openssl-tpm2-engine}/lib/ossl-modules/tpm2.so";
    };

    meta.mainProgram = "lzbt";
  };
}
