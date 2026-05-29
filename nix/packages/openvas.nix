{
  stdenv,
  lib,
  version,
  autoPatchelfHook,
  cmake,
  pkg-config,
  bison,
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
  gvm-libs,
  paho-mqtt-c,
  src,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "openvas";
  inherit version;

  inherit src;

  # Upstream builds with -Werror; nixpkgs GCC 14+ triggers a sign-compare
  # warning in the NASL packet-forgery code. Strip it rather than adding a
  # blanket -Wno-error= flag.
  postPatch = ''
    substituteInPlace CMakeLists.txt nasl/CMakeLists.txt src/CMakeLists.txt misc/CMakeLists.txt \
      --replace-warn "-Werror" ""
  '';

  nativeBuildInputs = [
    autoPatchelfHook
    cmake
    pkg-config
    bison
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
    gvm-libs
    paho-mqtt-c
  ];

  # CMAKE_INSTALL_PREFIX=/usr sets the *runtime* prefix baked into the
  # binary (so it looks for /etc/openvas/openvas.conf at runtime).
  # DESTDIR=$out overlays the Nix store on top at build time, and
  # autoPatchelfHook fixes RPATH since libs land in $out/usr/lib/.
  cmakeFlags = [ "-DCMAKE_INSTALL_PREFIX=/usr" ];

  installPhase = ''
    runHook preInstall
    DESTDIR="$out" cmake --install .
    mkdir -p "$out/bin"
    ln -sf "$out/usr/sbin/openvas" "$out/bin/openvas"
    runHook postInstall
  '';

  meta = with lib; {
    description = "Open Vulnerability Assessment Scanner";
    homepage = "https://github.com/greenbone/openvas";
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
    mainProgram = "openvas";
  };
})
