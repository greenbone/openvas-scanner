#!/bin/bash



make_toc_entry() {
    name=${file##*/}
    name=${name//.md/}
    entry=$(grep "\*\*$name\*\* - " $file)
    entry=${entry//${name}/[${name}](${name}.md)}
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
            printf "$file_content$toc" > $dir/index.md
        fi
    done
}

base_dir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
nasl_init="$base_dir"/../nasl/nasl_init.c
nasl_built_in="$base_dir"/manual/nasl/built-in-functions

i=0
begin=0
nasl_functions=()
while read -r line
do
    if [[ $line == "static init_func libfuncs[] = {" ]]; then
        begin=1
    elif [[ $line == "{NULL, NULL}};" ]]; then
        break
    elif [[ $begin == 1 ]]; then
        if [[ $line =~ "{" ]]; then
            [[ $line =~ \"(.*)\" ]] &&
                match=${BASH_REMATCH[1]}
            i=$(( i + 1))
            nasl_functions[$i]=$match
        fi
    fi
done < $nasl_init

j=0
nasl_doc=()
for dir in "$nasl_built_in"/*
do
    if [[ -d $dir ]]; then
        for file in "$dir"/*
        do
            nasl_doc_file=${file##*/}
            if [ $nasl_doc_file != "index.md" ]; then
                j=$(( j + 1))
                nasl_doc[$j]=${nasl_doc_file//.md/}
            fi
        done
    fi
done

not_found=()
k=0
for f1 in "${nasl_functions[@]}"
do
    found=0
    for f2 in "${nasl_doc[@]}"
    do
        if [[ $f1 == $f2 ]]; then
            found=1
            break
        fi
    done
    if [[ $found == 0 ]]; then
        k=$(( k + 1))
        not_found[$k]=$f1
    fi
done

not_exist=()
l=0
for f2 in "${nasl_doc[@]}"
do
    found=0
    for f1 in "${nasl_functions[@]}"
    do
        if [[ $f1 == $f2 ]]; then
            found=1
            break
        fi
    done
    if [[ $found == 0 ]]; then
        l=$(( l + 1))
        not_exist[$l]=$f2
    fi
done

echo "existing functions  : $i"
echo "documented functions: $j"
echo "functions not found : $k"
for f in "${not_found[@]}"
do
    echo $f
done
echo "functions do not exist: $l"
for f in "${not_exist[@]}"
do
    echo $f
done

exit 0
