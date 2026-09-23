{
  lib,
  buildRustApp,
  makeBinaryWrapper,
  binutils-unwrapped,
  openssl,
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
