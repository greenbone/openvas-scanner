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
  openssl,
  libpcap,
  sqlite,
  zstd,
  bzip2,
  libclang,
  craneLib,
  pname,
  version,
  rustPlatform,
  stdenvNoCC,
  src,
  libnl,
  keyutils,
  libedit,
  libverto,
}:

let
  libgpgErrorStatic = libgpg-error.overrideAttrs (old: {
    dontDisableStatic = true;
    configureFlags = (old.configureFlags or [ ]) ++ [ "--enable-static" ];
  });

  libgcryptStatic =
    (libgcrypt.override {
      libgpg-error = libgpgErrorStatic;
    }).overrideAttrs
      (old: {
        dontDisableStatic = true;
        configureFlags = (old.configureFlags or [ ]) ++ [ "--enable-static" ];
      });

  libpcapStatic = libpcap.overrideAttrs (old: {
    dontDisableStatic = true;

    configureFlags = (old.configureFlags or [ ]) ++ [
      "--disable-dbus"
      "--without-libnl"
    ];

    buildInputs = lib.remove libnl (old.buildInputs or [ ]);

    propagatedBuildInputs = lib.remove (lib.getDev libnl) (old.propagatedBuildInputs or [ ]);
  });

  krb5OpenvasStatic = krb5.overrideAttrs (old: {
    dontDisableStatic = true;

    configureFlags = lib.remove "--with-libedit" (old.configureFlags or [ ]) ++ [
      "--enable-static"
      "--disable-shared"
      "--without-system-verto"
      "--without-libedit"
      "--without-keyutils"
      "--disable-rpath"
    ];

    buildInputs = lib.remove keyutils (
      lib.remove libedit (lib.remove libverto (old.buildInputs or [ ]))
    );

    propagatedBuildInputs = lib.remove (lib.getDev keyutils) (
      lib.remove (lib.getDev libedit) (
        lib.remove (lib.getDev libverto) (old.propagatedBuildInputs or [ ])
      )
    );

    buildPhase = ''
      runHook preBuild

      for dir in \
        util/support \
        util/et \
        util/profile \
        include \
        lib/crypto \
        lib/krb5 \
        lib/gssapi
      do
        make -C "$dir" -j"$NIX_BUILD_CORES"
      done

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall

      make install-mkdirs

      for dir in \
        util/support \
        util/et \
        util/profile \
        include \
        lib/crypto \
        lib/krb5 \
        lib/gssapi
      do
        make -C "$dir" install
      done

      runHook postInstall
    '';
  });

  # ── archive cache for nasl-c-lib -sys crates ────────────────
  #
  # The -sys crates use custom build scripts that discover native
  # libraries via $OPENVAS_ARCHIVES rather than pkg-config.
  #
  # Upstream expects this directory to contain static archives (.a)
  # and headers.
  openvasArchives = stdenvNoCC.mkDerivation {
    pname = "openvas-archives";
    inherit version;

    dontUnpack = true;

    installPhase = ''
      mkdir -p "$out"
      mkdir -p "$out/include"

      ln -s "${lib.getLib libgcryptStatic}/lib/libgcrypt.a" "$out/libgcrypt.a"
      ln -s "${lib.getLib libgpgErrorStatic}/lib/libgpg-error.a" "$out/libgpg-error.a"
      ln -s "${lib.getLib libpcapStatic}/lib/libpcap.a" "$out/libpcap.a"

      ln -s "${lib.getLib krb5OpenvasStatic}/lib/libgssapi_krb5.a" "$out/libgssapi_krb5.a"
      ln -s "${lib.getLib krb5OpenvasStatic}/lib/libkrb5.a" "$out/libkrb5.a"
      ln -s "${lib.getLib krb5OpenvasStatic}/lib/libk5crypto.a" "$out/libk5crypto.a"
      ln -s "${lib.getLib krb5OpenvasStatic}/lib/libcom_err.a" "$out/libcom_err.a"
      ln -s "${lib.getLib krb5OpenvasStatic}/lib/libkrb5support.a" "$out/libkrb5support.a"

      cp -r "${lib.getDev libgcryptStatic}/include/"* "$out/include/"
      cp -r "${lib.getDev libgpgErrorStatic}/include/"* "$out/include/"
      cp -r "${lib.getDev libpcapStatic}/include/"* "$out/include/"
      cp -r "${lib.getDev krb5OpenvasStatic}/include/"* "$out/include/"
    '';
  };

  commonArgs = {
    inherit pname version;
    src = craneLib.path src;
    strictDeps = true;

    nativeBuildInputs = [
      pkg-config
      perl
      gnumake
      capnproto
      rustPlatform.bindgenHook
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

    OPENVAS_ARCHIVES = "${openvasArchives}";
    LIBPCAP_LIBDIR = "${openvasArchives}";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  # Shared postPatch — see comment block at the top of this file.
  postPatch = ''
    mkdir -p ../misc
    ln -sf ${repoRoot}/misc/openvas-krb5.c ../misc/openvas-krb5.c
    ln -sf ${repoRoot}/misc/openvas-krb5.h ../misc/openvas-krb5.h
  '';

  # Build each workspace binary separately, reusing the dependency artifacts
  # so the workspace is compiled once.
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
          export LD_LIBRARY_PATH=${lib.makeLibraryPath commonArgs.buildInputs}
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
