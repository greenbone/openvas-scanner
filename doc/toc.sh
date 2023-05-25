#!/bin/bash
# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

make_toc_entry() {
    name=${file##*/}
    name=${name//.md/}
    entry=$(grep "\*\*$name\*\* - " $file)
    entry=${entry//\*\*${name}\*\* -/- \*\*[${name}](${name}.md)\*\* -}
    toc="$toc\n$entry"
}

make_tocs() {
    for dir in "$root_dir_prefix"/*
    do
        if [[ -d $dir ]]; then
            toc=""
            for file in "$dir"/*
            do
                if [ ${file##*/} != "index.md" ]; then
                    make_toc_entry
                fi
            done
            file_content=""
            while read -r line
            do
                file_content="$file_content$line\n"
                if [[ $line =~ "## TABLE OF CONTENT" ]]; then
                    break
                fi
            done < $dir/index.md
            printf "$file_content$toc\n" > $dir/index.md
        fi
    done
}

base_dir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
root_dir_prefix="$base_dir"/manual/nasl/built-in-functions

make_tocs

exit 0
