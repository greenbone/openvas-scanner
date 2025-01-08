#!/usr/bin/env bash

any_missing_headers=0

for folder in src misc rust/src; do
    echo "Checking $folder"
    for f in $(find $folder -regex ".*\.\(rs\|c\|h\)"); do
        header=$(head -n 3 "$f")
        if ! [[ "$header" =~ SPDX ]]; then
            echo "File does not contain license header: $f"
            any_missing_headers=1

            if [[ "$1" == add_header ]]; then
                tmpfile=$(mktemp)
                cp "$f" "$tmpfile"
                echo -e "// SPDX-FileCopyrightText: 2025 Greenbone AG\n//\n// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception\n" | cat - $tmpfile > "$f"
            fi
        fi
    done
done

exit $any_missing_headers
