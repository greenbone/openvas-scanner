#!/usr/bin/env bash

function comment_string () {
    ext=$1
    if [[ $ext == "c" || $ext == "h" || $ext == "rs" ]]; then
        echo "//"
    elif [[ $ext == "nasl" || $ext == "cmake" ]]; then
        echo "#"
    fi
}

any_missing_headers=0

exts="c h nasl cmake"

for ext in $exts; do
    find . -not -path "./rust/target/*" -not -path "./rust/crates/nasl-c-lib/tmp/*" -regex ".*\.\($ext\)" -print0 | while read -d $'\0' f; do
        header=$(head -n 3 "$f")
        if ! [[ "$header" =~ SPDX ]]; then
            echo "File does not contain license header: $f"
            any_missing_headers=1

            if [[ "$1" == add_header ]]; then
                tmpfile=$(mktemp)
                cp "$f" "$tmpfile"
                comment=$(comment_string $ext)
                echo -e "$comment SPDX-FileCopyrightText: 2025 Greenbone AG\n$comment\n$comment SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception\n" | cat - $tmpfile > "$f"
            fi
        fi
    done
done

exit $any_missing_headers
