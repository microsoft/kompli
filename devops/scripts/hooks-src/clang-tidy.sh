#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Hook: clang-tidy
# Runs clang-tidy --fix via the project wrapper on relevant C/C++ sources and
# fails if any file was modified or if clang-tidy reported an error.
#
# Files checked:
#   src/{engine,benchmarkio,kompli,telemetry}/**/*.{h,hpp,c,cpp}
#   src/tools/lua-evaluator/**/*.{h,hpp,c,cpp}
#   src/modules/complianceengine/src/**/*.{h,hpp,c,cpp}
# Excluded:
#   src/engine/tests/**/*.{h,hpp,c,cpp}

set -euo pipefail

readonly HOOK_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
readonly REPO_ROOT="$(env -u GIT_DIR git -C "$HOOK_DIR" rev-parse --show-toplevel)"
# shellcheck source=common.sh
source "$HOOK_DIR/common.sh"

readonly PATTERN='^src/(engine|benchmarkio|kompli|tools/lua-evaluator|telemetry|modules/complianceengine/src)/.*\.(h|hpp|c|cpp)$'
readonly EXCLUDE='^src/engine/tests/'

mapfile -t _MATCHED < <(filter_files "$PATTERN" "$@")

FILES=()
for f in "${_MATCHED[@]+"${_MATCHED[@]}"}"; do
    rel="${f#"$REPO_ROOT/"}"
    [[ "$rel" =~ $EXCLUDE ]] || FILES+=("$f")
done

[[ ${#FILES[@]} -eq 0 ]] && exit 0

printf '    %d file(s) to check\n' "${#FILES[@]}"

readonly TIDY="$REPO_ROOT/src/tests/clang-tidy/run-clang-tidy.py"
failed=0

for f in "${FILES[@]}"; do
    snapshot_files "$f"
    python3 "$TIDY" "$f" || failed=1
    check_unmodified "$f" || failed=1
done

if [[ $failed -ne 0 ]]; then
    printf '    Re-stage the files above after running clang-tidy --fix locally.\n'
    exit 1
fi
