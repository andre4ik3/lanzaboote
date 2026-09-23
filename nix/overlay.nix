# sbctl 0.18 cannot verify signatures made by systemd-sbsign: it re-encodes the
# signed attributes in a fixed order before checking them, and systemd-sbsign
# (correctly, per DER) sorts them differently. Fixed on master in
# Foxboron/sbctl@ef8427b; drop this once a release includes it.
final: prev: {
  sbctl = prev.sbctl.overrideAttrs {
    version = "0.18-unstable-2026-09-06";
    src = final.fetchFromGitHub {
      owner = "Foxboron";
      repo = "sbctl";
      rev = "3ae0c7e6c7cb28e4f8b8504ec4e49346497cd490";
      hash = "sha256-hXMNVrOOY2o0JG5ldJi9IZfks4xjQInzZWCkUxA+TK0=";
    };
    vendorHash = "sha256-gLOYs4G4XkP/TQn1We1vUfCYELY7QBum0Q1cwE8CTk4=";
  };
}
