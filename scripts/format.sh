#!/usr/bin/env bash
#
# Format the C++ sources -- src/, samples/, tests/ and bench/ -- with the
# house style in .clang-format, then repair the one construct clang-format gets
# wrong.
#
# clang-format 23.1.1 prints C++26 `= delete("reason")` as `= delete ("reason")`:
# it treats `delete` as a control statement, and SpaceBeforeParens is the same
# knob that gives us `if (`, `for (` and `while (`. No setting separates them,
# and SpaceBeforeParensOptions has no `AfterDelete` key in this version. The
# perl pass below restores the spacing; both spellings are the same token
# sequence, so nothing else changes.
#
# Usage: scripts/format.sh [file ...]      (no arguments: the whole tree)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mapfile -t files < <(
    if [ "$#" -gt 0 ]; then
        printf '%s\n' "$@"
    else
        find "$root/src" "$root/samples" "$root/tests" "$root/bench" \
            -type f \( -name '*.hpp' -o -name '*.cpp' \)
    fi
)

clang-format -i --style="file:$root/.clang-format" "${files[@]}"
perl -pi -e 's/= delete \("/= delete("/g' "${files[@]}"
