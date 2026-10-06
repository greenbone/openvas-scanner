#! /bin/bash
# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

basedir="$(dirname -- "${BASH_SOURCE[0]}")"
basedir="$(cd "${basedir}" && pwd -P)"
version="$(cat "${basedir}/../VERSION")"
date="$(date +"%B %Y")"

declare -A sectionheadbysection=(["1"]="User commands"
                                 ["3nasl"]="Nasl functions manual"
                                 ["8"]="System management commands")


xformman() {
    sourcepath="$1"
    namesection="$(sed -n \
                       -e '1s,^# \([-a-zA-Z0-9_]\+\)[(]\([0-9nasl]\+\)[)]$,\1 \2,p' \
                       -- "${sourcepath}")"
    if [[ -z "${namesection}" ]]; then
        printf "name/section header in %s malformed\n" "${sourcepath}" >&2
        exit 65
    fi
    read -r name section < <(printf "%s\n" "${namesection}")
    sectionhead="${sectionheadbysection[${section}]}"

    sourcefilestem="$(basename -- "${sourcepath}" .md)"
    destpath="${basedir}/man/${sourcefilestem}.${section}"

    pandoc --standalone \
           --metadata "title:${name}(${section}) ${version} | ${sectionhead}" \
           --metadata "section:${section}" \
           --metadata "date:${date}" \
           --lua-filter "${basedir}/man-touchup.lua" \
           -f markdown -t man \
           -o "${destpath}" \
           -- "${sourcepath}"
}


rm -rf -- "${basedir}/man"
mkdir -- "${basedir}/man"

manpagesources="$(find "${basedir}/manual/openvas/openvas.md" \
                       "${basedir}/manual/nasl/"openvas-nasl*.md \
                       "${basedir}/manual/nasl/built-in-functions" \
                       -type f \
                       -a ! -name index.md)"

while read -r sourcepath; do
    xformman "${sourcepath}"
done <<<"${manpagesources}"
