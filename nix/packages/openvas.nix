{
  stdenv,
  lib,
  autoPatchelfHook,
  cmake,
  pkg-config,
  bison,
  flex,
  glib,
  json-glib,
  libgcrypt,
  gpgme,
  libpcap,
  libssh,
  libksba,
  gnutls,
  curl,
  libbsd,
  krb5,
  file,
  net-snmp,
  nmap,
  redis,
  doxygen,
  pandoc,
  gvm-libs,
  paho-mqtt-c,
  src,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "openvas";
  version = "23.45.5";

  inherit src;

  # GCC 14+ flags a sign-compare warning in the NASL packet-forgery code
  # that upstream treats as -Werror.  Strip -Werror rather than adding a
  # blanket compiler flag.
  postPatch = ''
    substituteInPlace CMakeLists.txt nasl/CMakeLists.txt src/CMakeLists.txt misc/CMakeLists.txt \
      --replace-warn "-Werror" ""
  '';

  nativeBuildInputs = [
    autoPatchelfHook
    cmake
    pkg-config
    bison
    flex
    doxygen
    pandoc
  ];

  buildInputs = [
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
    gvm-libs
    paho-mqtt-c
  ];

  # Install to the Nix store via DESTDIR while keeping runtime paths as
  # standard FHS locations (the binary reads openvas.conf at runtime).
  cmakeFlags = [
    "-DCMAKE_INSTALL_PREFIX=/usr"
    "-DLOCALSTATEDIR=/var"
    "-DSYSCONFDIR=/etc"
    "-DCMAKE_INSTALL_SYSCONFDIR=/etc"
  ];

  installPhase = ''
    runHook preInstall
    DESTDIR="$out" cmake --install .

    mkdir -p "$out/bin"
    for bin in openvas openvas-nasl openvas-nasl-lint; do
      if [ -x "$out/usr/sbin/$bin" ]; then
        ln -s "$out/usr/sbin/$bin" "$out/bin/$bin"
      elif [ -x "$out/usr/bin/$bin" ]; then
        ln -s "$out/usr/bin/$bin" "$out/bin/$bin"
      fi
    done

    runHook postInstall
  '';

  meta = with lib; {
    description = "Open Vulnerability Assessment Scanner";
    homepage = "https://github.com/greenbone/openvas";
    license = licenses.gpl2Plus;
    platforms = platforms.linux ++ platforms.darwin;
    mainProgram = "openvas";
  };
})
