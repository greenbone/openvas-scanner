{
  description = "openvas rust dev shell";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
      };
    in rec {
      dependencies = with pkgs;
        [
          gcc
          libpcap
          openssl
          pkg-config
          zlib
        ]
        ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
        ]
        ++ pkgs.lib.optionals pkgs.stdenv.isDarwin
        [];
      devShell = pkgs.mkShell {
        buildInputs = dependencies;
      };
    });
}
