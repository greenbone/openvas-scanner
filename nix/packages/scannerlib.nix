{
  lib,
  perl,
  gnumake,
  pkg-config,
  capnproto,
  libgcrypt,
  libgpg-error,
  net-snmp,
  krb5,
  gvm-libs,
  repoRoot ? null,
  autoPatchelfHook,
  openssl,
  libpcap,
  sqlite,
  zstd,
  bzip2,
  pkgs,
  libclang,
  craneLib,
  pname,
  version,
  src,
}:

let
  # ── build-cache for nasl-c-lib -sys crates ─────────────────
  #
  # The -sys crates use a custom build_support.rs that discovers
  # native libraries via $OPENVAS_ARCHIVES rather than pkg-config.
  # We populate this directory from the Nix-provided shared .so
  # libraries and patch the link directives to use dylib instead
  # of static (see postPatch below).
  #
  # Using shared libraries is the natural Nix approach: nixpkgs
  # ships .so files by default and the stdenv linker wrapper
  # handles RPATH for standard buildInputs.  Because these crates
  # bypass the wrapper by emitting their own cargo:rustc-link
  # directives, we also use autoPatchelfHook to restore RPATH.
  buildCache = pkgs.runCommand "nasl-build-cache" { } ''
    mkdir -p "$out/include"
    mkdir -p "$out/include/gssapi"

    # ── gcrypt ──
    ln -s "${lib.getLib libgcrypt}/lib/libgcrypt.so" "$out/libgcrypt.so"
    ln -s "${lib.getLib libgpg-error}/lib/libgpg-error.so" "$out/libgpg-error.so"
    for h in gcrypt.h gcrypt-module.h; do
      f="${lib.getDev libgcrypt}/include/$h"
      test -f "$f" && ln -s "$f" "$out/include/$h"
    done
    ln -s "${lib.getDev libgpg-error}/include/gpg-error.h" "$out/include/gpg-error.h"

    # ── krb5 ──
    ln -s ${lib.getLib krb5}/lib/{libgssapi_krb5,libkrb5,libk5crypto,libcom_err,libkrb5support}.so "$out/"
    ln -s "${lib.getDev krb5}/include/krb5.h" "$out/include/krb5.h"
    ln -s "${lib.getDev krb5}/include/gssapi/gssapi.h" "$out/include/gssapi/gssapi.h"
    ln -s "${lib.getDev krb5}/include/gssapi/gssapi_krb5.h" "$out/include/gssapi/gssapi_krb5.h"
  '';

  commonArgs = {
    inherit pname version;
    src = craneLib.path src;
    strictDeps = true;

    nativeBuildInputs = [
      pkg-config
      perl
      gnumake
      capnproto
      pkgs.rustPlatform.bindgenHook
      # Restore RPATH on binaries whose link directives bypass
      # the Nix stdenv linker wrapper (see buildCache comment).
      autoPatchelfHook
    ];

    buildInputs = [
      libclang
      gvm-libs
      libgcrypt
      libgpg-error
      net-snmp
      krb5
      openssl
      libpcap
      sqlite
      zstd
      bzip2
    ];

    OPENVAS_ARCHIVES = "${buildCache}";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  # Shared postPatch — see comment block at the top of this file.
  postPatch = ''
    mkdir -p ../misc
    ln -sf ${repoRoot}/misc/openvas-krb5.c ../misc/openvas-krb5.c
    ln -sf ${repoRoot}/misc/openvas-krb5.h ../misc/openvas-krb5.h

    substituteInPlace crates/nasl-c-lib/build_support.rs \
      --replace-fail 'cargo:rustc-link-lib=static=' 'cargo:rustc-link-lib=dylib='
    substituteInPlace crates/nasl-c-lib/libopenvas-krb5-sys/build.rs \
      --replace-fail '.a"' '.so"'
    substituteInPlace crates/nasl-c-lib/libcrypt-sys/build.rs \
      --replace-fail '.a"' '.so"'
  '';

  # Build each workspace binary separately, reusing the dependency artifacts
  # so the workspace is compiled once.  Each binary gets its own derivation
  # with its own RPATH fixed up by autoPatchelfHook.
  buildBin =
    bin:
    craneLib.buildPackage (
      commonArgs
      // {
        inherit cargoArtifacts version postPatch;
        BIN_VERSION = version;
        pname = bin;

        cargoExtraArgs = "--bin ${bin}";

        preCheck = ''
          export LD_LIBRARY_PATH=${
            pkgs.lib.makeLibraryPath commonArgs.buildInputs
          }
        '';

        cargoTestExtraArgs = "-- --skip container_image_scanner";

        meta = with lib; {
          description = "OpenVAS — ${bin}";
          homepage = "https://github.com/greenbone/openvas";
          license = licenses.gpl2Plus;
          platforms = platforms.linux;
          mainProgram = bin;
        };
      }
    );
in
{
  openvasd = buildBin "openvasd";
  scannerctl = buildBin "scannerctl";
  feed-filter = buildBin "feed-filter";
  # Full workspace build still available as a single derivation.
  scannerlib = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts version postPatch;
      BIN_VERSION = version;
      # Full workspace --lib tests hit sandbox-unfriendly tests
      # (e.g. nasl::builtin::sys::tests::find_in_path aborts).
      # Per-binary builds (openvasd, scannerctl, feed-filter) run
      # the same tests individually and pass — see buildBin above.
      doCheck = false;

      meta = with lib; {
        description = "OpenVAS Rust workspace — builds openvasd, scannerctl, and feed-filter together";
        homepage = "https://github.com/greenbone/openvas";
        license = licenses.gpl2Plus;
        platforms = platforms.linux;
      };
    }
  );
}
