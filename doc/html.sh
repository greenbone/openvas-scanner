#!/bin/bash

make_entry() {
    toc="$toc<li>"

    line=$(head -n 1 "$entry")
    title=${line:2}

    link=$entry
    link=${link//manual/html}
    link=${link//.md/.html}
    link=${link#"$root_dir_prefix"}
    
    toc="$toc<a href=%ROOT%$link>$title</a>"

    toc="$toc</li>"
}

recursive_toc() {
    if [ $first == 0 ]; then
        first=1
        toc="$toc<ul class=\"collapsible\">" 
        entry="$search_dir"/index.md
        make_entry
        toc="$toc</ul>"
    fi
    for entry in "$search_dir"/*
    do
        toc="$toc<ul class=\"collapsible\">"     
        # In case of folder iterate through it
        if [[ -d $entry ]]; then
            search_dir="$entry"
            entry="$entry"/index.md
            make_entry
            entry=${entry//\/index.md/""}
            recursive_toc
        # Else make an entry for the file
        elif [[ -f $entry ]]; then
            filename="$(basename -- $entry)"
            if [ $filename != index.md ]; then
                make_entry
            fi
        fi
        toc="$toc</ul>"
    done
}

create_html_dict() {
    dict=$entry
    dict=${dict//manual/html}
    mkdir $dict
}

make_html() {
    content=$(pandoc -f markdown -t html $entry)
    content=${content//.md/.html}

    head_name=$(head -n 1 $entry)
    head_name=${head_name//\# /}

    html=$template
    html=${html//\%TITLE\%/${head_name}}
    html=${html//\%CSS\%/${root_dir}${css_path}}
    html=${html//\%JS\%/${root_dir}${js_path}}
    toc_relative=${toc//\%ROOT\%/${root_dir}}
    html=${html//\%TOC\%/${toc_relative}}
    html=${html//\%CONTENT\%/${content}}
    
    file=$entry
    file=${file//manual/html}
    file=${file//.md/.html}

    echo "$html" > "$file"
}

recursive_html() {
    for entry in "$search_dir"/*
    do 
        # In case of folder iterate through it
        if [[ -d $entry ]]; then
            create_html_dict
            search_dir="$entry"
            root_dir="$root_dir../"
            recursive_html
            root_dir=${root_dir%"../"}
        # Else make an entry for the file
        elif [[ -f $entry ]]; then
            filename="$(basename -- $entry)"
            make_html
        fi
    done
}

rm -rf html
mkdir html
mkdir html/css
mkdir html/js

first=0
base_dir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )/
template=$(<templates/template.html)
root_dir=""
root_dir_prefix="$base_dir"html/

cp templates/style.css html/css/
css_path=css/style.css
cp templates/script.js html/js/
js_path=js/script.js

toc=""

search_dir="$base_dir"manual
recursive_toc

search_dir="$base_dir"manual
recursive_html

exit 0
