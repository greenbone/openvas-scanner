#!/bin/bash

if [ -z "$1" ]; then
    echo "Error: Repository name is not provided."
    exit 1
fi

IFS='/' read -r owner repo <<< "$1"

parent_dir="/workspaces"
if [ ! -d "$parent_dir" ]; then
    echo "Parent directory '$parent_dir' does not exist. Creating it."
    mkdir -p "$parent_dir"
fi

owner_dir="$parent_dir/$owner"
if [ ! -d "$owner_dir" ]; then
    echo "Owner directory '$owner_dir' does not exist. Creating it."
    mkdir -p "$owner_dir"
fi

target_dir="/workspaces/$1"

if [ -d "$target_dir" ]; then
    echo "Error: Target directory '$target_dir' already exists."
    exit 1
fi

if ls $HOME/.ssh/id_* &>/dev/null; then
    if git clone git@github.com:$1.git "$target_dir"; then
        echo "Cloning with SSH URL successful."
    else
        echo "Warning: Cloning with SSH URL failed. Falling back to HTTPS URL."
        git clone https://github.com/$1.git "$target_dir"
    fi
else
    git clone https://github.com/$1.git "$target_dir"
fi
