{
  description = "OpenVAS — Open Vulnerability Assessment Scanner";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane = {
      url = "github:ipetkov/crane";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        { system, pkgs, ... }:
        let
          rustToolchain = pkgs.fenix.fromToolchainFile {
            dir = self + /rust;
            sha256 = "sha256-gh/xTkxKHL4eiRXzWv8KP7vfjSk61Iq48x47BEDFgfk=";
          };

          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;
        in
        rec {
          formatter = pkgs.nixfmt-rfc-style;

          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.fenix.overlays.default ];
          };

          packages = import ./nix/packages {
            inherit pkgs craneLib;
            src = self;
          };

          apps =
            let
              mkApp = name: {
                type = "app";
                program = "${packages.${name}}/bin/${name}";
              };
            in
            {
              openvasd = mkApp "openvasd";
              scannerctl = mkApp "scannerctl";
              feed-filter = mkApp "feed-filter";
              openvas = mkApp "openvas";
            };

          devShells.default = pkgs.mkShell {
            inputsFrom = builtins.attrValues packages;
            buildInputs = with pkgs; [
              cmake
              gcc
              pkg-config
              bison
              flex
              doxygen
              pandoc
              glib
              json-glib
              libgcrypt
              gpgme
              libpcap
              libssh
              libksba
              gnutls
              curl
              libbsd
              krb5
              file
              net-snmp
              nmap
              redis
              rustToolchain
              clang-tools
              gdb
              valgrind
            ];
          };
        };

      flake.overlays.default = final: prev: {
        inherit (self.packages.${final.system})
          gvm-libs
          openvasd
          scannerctl
          feed-filter
          scannerlib
          openvas
          ;
      };
    };
}
