#!/bin/bash

make_entry() {
    line=$(head -n 1 "$entry")
    title=${line:2}
    link=${entry/${base_dir}/""}
    for (( i=1; i<"$depth"; i++ ))
    do
        space="  $space"
    done
    echo "$space- [$title]($link)" >> "$base_dir/toc.md"
    space=""
}

recursive_folder() {
    for entry in "$search_dir"/*
    do
        ((depth=depth+1))        
        # In case of folder iterate through it
        if [[ -d $entry ]]; then
            search_dir="$entry"
            entry="$entry"/index.md
            make_entry
            entry=${entry//\/index.md/""}
            recursive_folder
        # Else make an entry for the file
        elif [[ -f $entry ]]; then
            filename="$(basename -- $entry)"
            if [ $filename != index.md ]; then
                make_entry
            fi
        fi
        ((depth=depth-1))
    done
}

base_dir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )/
search_dir="$base_dir"documentation
depth=0

echo "# Table of contents" > "$base_dir/toc.md"

recursive_folder

exit 0