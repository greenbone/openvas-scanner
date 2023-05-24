#!/bin/bash
# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

version=0.1
date=$(date +"%B %Y")

make_man () {
    head_name=$(head -n 1 $entry)
    head_name=${head_name//\# /}

    file=$(tail -n +3 $entry)
    file=${file//\#\# /\# }
    file="% $head_name($file_ext) Version 1.0 | OpenVAS User Manual"$'\n'$file

    filename=${filename//.md/.${file_ext}}

    echo "$file" | pandoc --standalone -f markdown -t man -o $man_dir/$filename /dev/stdin
}

recursive_functions () {
    for entry in "$search_dir"/*
    do 
        # In case of folder iterate through it
        if [[ -d $entry ]]; then
            search_dir="$entry"
            recursive_functions
        # Else make an entry for the file
        elif [[ -f $entry ]]; then
            filename="$(basename -- $entry)"
            if [ $filename != index.md ] && [ $filename ]; then
                make_man
            fi
        fi
    done
}

rm -rf man
mkdir man

base_dir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
search_dir="$base_dir"/manual/nasl/built-in-functions
man_dir="$base_dir"/man
file_ext="3"
recursive_functions

exit 0
