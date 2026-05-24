{
  pkgs,
  craneLib,
  src,
}:

let
  inherit (pkgs) gvm-libs;

  # Read scanner release version from CMakeLists.txt — upstream releases
  # use this version for both the C scanner and the Rust binaries.
  version = builtins.head (
    builtins.match ".*project[[:space:]]*\\([^)]*VERSION[[:space:]]+([0-9.]+).*" (
      builtins.readFile ./CMakeLists.txt
    )
  );

  cargoToml = fromTOML (builtins.readFile (src + "/rust/Cargo.toml"));

  # Each binary is its own derivation (buildDepsOnly shared, see scannerlib.nix).
  rustOutputs = pkgs.callPackage ./scannerlib.nix {
    inherit craneLib;
    inherit gvm-libs;
    inherit version;
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
    inherit src version;
    inherit gvm-libs;
  };
}
