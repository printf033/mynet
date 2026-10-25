#!/usr/bin/env bash
#
# 使用 .clang-format 中的规范格式化 C++ 源码（src/、examples/、tests/ 与 bench/），
# 随后修复 clang-format 处理不当的特定语法结构。
#
# clang-format 23.1.1 会将 C++26 的 `= delete("reason")` 格式化为 `= delete ("reason")`：
# 它将 `delete` 误归类为控制语句，且 SpaceBeforeParens 与 `if (`、`for (`、`while (` 共用
# 同一个配置项。当前版本中没有任何选项可以将其单独拆分，SpaceBeforeParensOptions 亦无
# `AfterDelete` 配置项。下方的 perl 处理会恢复正确的紧凑空格；两种写法在词法记号上完全等价，
# 因此不会产生其他任何副作用。
#
# 用法：scripts/format.sh [file ...]      （无参数时格式化整棵源码树）
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mapfile -t files < <(
    if [ "$#" -gt 0 ]; then
        printf '%s\n' "$@"
    else
        find "$root/src" "$root/examples" "$root/tests" "$root/bench" \
            -type f \( -name '*.hpp' -o -name '*.cpp' \)
    fi
)

clang-format -i --style="file:$root/.clang-format" "${files[@]}"
perl -pi -e 's/= delete \("/= delete("/g' "${files[@]}"
