#!/usr/bin/env sh
# I wanted to get the merge base using {{ github.base_ref }}, however this is only
# available for the event that opens the PR or edits it, not on pushes to the branch.
# Comparing to main should be an OK alternative, since it will - at worst - do more
# autoformatting than it otherwise would.

[ -z "$1" ] && merge_base=main || merge_base="$1"

git fetch origin $merge_base:refs/remotes/origin/$merge_base

echo "$(clang-format --version)"
(git diff --name-only "origin/$merge_base") | while read filename; do
    extension="${filename##*.}"
    if [ "$extension" = "c" ] || [ "$extension" = "h" ]; then
        clang-format -i -style=file "$filename"
    fi
done
