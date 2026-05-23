{
  pkgs,
  craneLib,
  src,
}:

let
  inherit (pkgs) gvm-libs;

  cargoToml = fromTOML (builtins.readFile (src + "/rust/Cargo.toml"));

  # Each binary is its own derivation (buildDepsOnly shared, see scannerlib.nix).
  rustOutputs = pkgs.callPackage ./scannerlib.nix {
    inherit craneLib;
    inherit gvm-libs;
    inherit (cargoToml.package) version;
    pname = cargoToml.package.name;
    src = src + "/rust";
    repoRoot = src;
  };

in
{
  inherit gvm-libs;

  inherit (rustOutputs)
    openvasd
    scannerctl
    feed-filter
    scannerlib
    ;

  openvas = pkgs.callPackage ./openvas.nix {
    inherit src;
    inherit gvm-libs;
  };
}
