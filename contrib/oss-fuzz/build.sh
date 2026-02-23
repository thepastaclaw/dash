#!/usr/bin/env bash
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

set -euo pipefail

if [[ -z "${OUT:-}" ]]; then
    echo "OUT must be set" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
if [[ -n "${BUILD_DIR:-}" ]]; then
    :
elif [[ -f "${REPO_ROOT}/config.status" ]]; then
    # If the source tree is already configured in-place, autotools rejects
    # a second out-of-tree configure against the same source directory.
    BUILD_DIR="${REPO_ROOT}"
else
    BUILD_DIR="${REPO_ROOT}/build-oss-fuzz"
fi
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
FUZZ_BINARY="${BUILD_DIR}/src/test/fuzz/fuzz"

mkdir -p "${OUT}" "${BUILD_DIR}"

if [[ ! -x "${REPO_ROOT}/configure" ]]; then
    (cd "${REPO_ROOT}" && ./autogen.sh)
fi

if [[ ! -f "${BUILD_DIR}/config.status" ]]; then
    (
        cd "${BUILD_DIR}"
        "${REPO_ROOT}/configure" \
            --enable-fuzz \
            --disable-shared \
            --disable-bench \
            --disable-tests \
            --with-sanitizers=fuzzer,address,undefined
    )
fi

make -C "${BUILD_DIR}/src" -j"${JOBS}" test/fuzz/fuzz

install -m 0755 "${FUZZ_BINARY}" "${OUT}/dash_fuzz"

TARGET_LIST_FILE="${OUT}/dash_fuzz_targets.txt"
PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 "${FUZZ_BINARY}" > "${TARGET_LIST_FILE}"

if [[ ! -s "${TARGET_LIST_FILE}" ]]; then
    echo "No fuzz targets were discovered" >&2
    exit 1
fi

while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    printf -v escaped_target '%q' "${target}"
    wrapper_path="${OUT}/${target}"
    cat > "${wrapper_path}" <<EOF_WRAPPER
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="\$(cd -- "\$(dirname -- "\${BASH_SOURCE[0]}")" && pwd -P)"
export FUZZ=${escaped_target}
exec "\${SCRIPT_DIR}/dash_fuzz" "\$@"
EOF_WRAPPER
    chmod +x "${wrapper_path}"
done < "${TARGET_LIST_FILE}"
