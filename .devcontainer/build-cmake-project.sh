#/bin/sh
[ -d "$1" ] && WORKD_DIR="$1" || (
    echo "Usage: $0 <project-dir>"
    exit 1
)
[ -n "$2" ] && ADDITIONAL_BUILD_ARGS="$2"

cd $WORKD_DIR
set -ex
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $ADDITIONAL_BUILD_ARGS
cmake --build build --target install
LDCONFIG="ldconfig"
if [ "$(id -u)" -ne 0 ]; then
    LDCONFIG="sudo ldconfig"
fi
$LDCONFIG
