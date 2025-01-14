#/bin/sh
[ -d "$1" ] && WORKD_DIR="$1" || (
    echo "Usage: $0 <project-dir>"
    exit 1
)
cd $WORKD_DIR
set -ex
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build --target install
LDCONFIG="ldconfig"
if [ "$(id -u)" -ne 0 ]; then
    LDCONFIG="sudo ldconfig"
fi
$LDCONFIG
