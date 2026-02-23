#!/usr/bin/env bash
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Continuous fuzzing daemon — cycles through all fuzz targets with
# persistent corpus storage, crash detection, and logging.
#
# Usage:
#   ./continuous_fuzz_daemon.sh [options]
#
# Options:
#   --fuzz-bin <path>       Path to the fuzz binary (default: auto-detect)
#   --corpus-dir <path>     Base directory for corpus storage (default: ~/fuzz_corpus)
#   --crashes-dir <path>    Directory for crash artifacts (default: ~/fuzz_crashes)
#   --log-dir <path>        Directory for log files (default: ~/fuzz_logs)
#   --time-per-target <s>   Seconds to fuzz each target per cycle (default: 600)
#   --rss-limit <mb>        RSS memory limit in MB (default: 4000)
#   --jobs <n>              Parallel fuzzing jobs (default: nproc/2)
#   --targets <list>        Comma-separated list of targets to fuzz (default: all)
#   --exclude <list>        Comma-separated list of targets to exclude
#   --single-cycle          Run one cycle and exit (for cron usage)
#   --dry-run               List targets and exit without fuzzing

set -euo pipefail

# --- Configuration defaults ---
FUZZ_BIN=""
CORPUS_DIR="${HOME}/fuzz_corpus"
CRASHES_DIR="${HOME}/fuzz_crashes"
LOG_DIR="${HOME}/fuzz_logs"
TIME_PER_TARGET=600
RSS_LIMIT_MB=4000
JOBS=""
TARGET_LIST=""
EXCLUDE_LIST=""
SINGLE_CYCLE=false
DRY_RUN=false

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fuzz-bin)      FUZZ_BIN="$2"; shift 2;;
        --corpus-dir)    CORPUS_DIR="$2"; shift 2;;
        --crashes-dir)   CRASHES_DIR="$2"; shift 2;;
        --log-dir)       LOG_DIR="$2"; shift 2;;
        --time-per-target) TIME_PER_TARGET="$2"; shift 2;;
        --rss-limit)     RSS_LIMIT_MB="$2"; shift 2;;
        --jobs)          JOBS="$2"; shift 2;;
        --targets)       TARGET_LIST="$2"; shift 2;;
        --exclude)       EXCLUDE_LIST="$2"; shift 2;;
        --single-cycle)  SINGLE_CYCLE=true; shift;;
        --dry-run)       DRY_RUN=true; shift;;
        -h|--help)
            sed -n '2,/^$/s/^# \?//p' "$0"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1;;
    esac
done

# --- Auto-detect fuzz binary ---
if [[ -z "$FUZZ_BIN" ]]; then
    for candidate in \
        "${HOME}/dash/src/test/fuzz/fuzz" \
        "${HOME}/dash/build_fuzz/src/test/fuzz/fuzz" \
        "$(command -v fuzz 2>/dev/null || true)"; do
        if [[ -x "$candidate" ]]; then
            FUZZ_BIN="$candidate"
            break
        fi
    done
    if [[ -z "$FUZZ_BIN" ]]; then
        echo "ERROR: Could not find fuzz binary. Use --fuzz-bin to specify." >&2
        exit 1
    fi
fi

# --- Set defaults ---
if [[ -z "$JOBS" ]]; then
    JOBS=$(( $(nproc) / 2 ))
    [[ "$JOBS" -lt 1 ]] && JOBS=1
fi

# --- Setup directories ---
mkdir -p "$CORPUS_DIR" "$CRASHES_DIR" "$LOG_DIR"

# --- Discover targets ---
get_all_targets() {
    PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 "$FUZZ_BIN" 2>&1 || true
}

filter_targets() {
    local all_targets="$1"
    local result=()

    if [[ -n "$TARGET_LIST" ]]; then
        # Use only specified targets
        IFS=',' read -ra wanted <<< "$TARGET_LIST"
        for t in "${wanted[@]}"; do
            if echo "$all_targets" | grep -qx "$t"; then
                result+=("$t")
            else
                echo "WARNING: Target '$t' not found in fuzz binary" >&2
            fi
        done
    else
        # Use all targets
        while IFS= read -r t; do
            [[ -n "$t" ]] && result+=("$t")
        done <<< "$all_targets"
    fi

    # Apply exclusions
    if [[ -n "$EXCLUDE_LIST" ]]; then
        IFS=',' read -ra excluded <<< "$EXCLUDE_LIST"
        local filtered=()
        for t in "${result[@]}"; do
            local skip=false
            for ex in "${excluded[@]}"; do
                [[ "$t" == "$ex" ]] && skip=true && break
            done
            $skip || filtered+=("$t")
        done
        result=("${filtered[@]}")
    fi

    printf '%s\n' "${result[@]}"
}

# --- Logging ---
log() {
    local level="$1"; shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "${LOG_DIR}/daemon.log"
}

# --- Run one fuzz target ---
run_target() {
    local target="$1"
    local target_corpus="${CORPUS_DIR}/${target}"
    local target_crashes="${CRASHES_DIR}/${target}"
    local target_log="${LOG_DIR}/${target}.log"

    mkdir -p "$target_corpus" "$target_crashes"

    log "INFO" "Fuzzing target: ${target} for ${TIME_PER_TARGET}s"

    local exit_code=0
    FUZZ="$target" \
    ASAN_OPTIONS="detect_leaks=0" \
    "$FUZZ_BIN" \
        -rss_limit_mb="$RSS_LIMIT_MB" \
        -max_total_time="$TIME_PER_TARGET" \
        -reload=0 \
        -print_final_stats=1 \
        -detect_leaks=0 \
        -artifact_prefix="${target_crashes}/" \
        "$target_corpus" \
        > "$target_log" 2>&1 || exit_code=$?

    # Check for crashes
    local crash_count
    crash_count=$(find "$target_crashes" -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' 2>/dev/null | wc -l)

    if [[ "$crash_count" -gt 0 ]]; then
        log "CRASH" "Target '${target}' produced ${crash_count} crash artifact(s)!"
        log "CRASH" "Artifacts saved to: ${target_crashes}/"

        # Extract crash details from log
        grep -E "SUMMARY|ERROR|BINGO|crash-|timeout-|oom-" "$target_log" 2>/dev/null | while IFS= read -r line; do
            log "CRASH" "  $line"
        done
    fi

    # Log stats
    local corpus_size
    corpus_size=$(find "$target_corpus" -type f | wc -l)
    local corpus_bytes
    corpus_bytes=$(du -sh "$target_corpus" 2>/dev/null | cut -f1)

    if [[ $exit_code -eq 0 ]]; then
        log "INFO" "Target '${target}' completed: corpus=${corpus_size} files (${corpus_bytes}), exit=${exit_code}"
    else
        log "WARN" "Target '${target}' exited with code ${exit_code}: corpus=${corpus_size} files (${corpus_bytes})"
    fi

    return 0  # Don't fail the daemon on individual target failures
}

# --- Main loop ---
main() {
    log "INFO" "=== Continuous Fuzzing Daemon Starting ==="
    log "INFO" "Fuzz binary: ${FUZZ_BIN}"
    log "INFO" "Corpus dir: ${CORPUS_DIR}"
    log "INFO" "Crashes dir: ${CRASHES_DIR}"
    log "INFO" "Time per target: ${TIME_PER_TARGET}s"
    log "INFO" "RSS limit: ${RSS_LIMIT_MB}MB"
    log "INFO" "Parallel jobs: ${JOBS}"

    local all_targets
    all_targets=$(get_all_targets)
    local targets
    targets=$(filter_targets "$all_targets")
    local target_count
    target_count=$(echo "$targets" | wc -l)

    log "INFO" "Found ${target_count} fuzz target(s)"

    if $DRY_RUN; then
        log "INFO" "DRY RUN — targets that would be fuzzed:"
        echo "$targets"
        exit 0
    fi

    local cycle=0
    while true; do
        cycle=$((cycle + 1))
        log "INFO" "=== Starting cycle ${cycle} (${target_count} targets × ${TIME_PER_TARGET}s) ==="

        # Shuffle targets each cycle for variety
        local shuffled
        shuffled=$(echo "$targets" | shuf)

        while IFS= read -r target; do
            [[ -z "$target" ]] && continue
            run_target "$target"
        done <<< "$shuffled"

        # Cycle summary
        local total_corpus
        total_corpus=$(du -sh "$CORPUS_DIR" 2>/dev/null | cut -f1)
        local total_crashes
        total_crashes=$(find "$CRASHES_DIR" -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' 2>/dev/null | wc -l)
        log "INFO" "=== Cycle ${cycle} complete: total corpus=${total_corpus}, total crashes=${total_crashes} ==="

        if $SINGLE_CYCLE; then
            log "INFO" "Single-cycle mode — exiting"
            break
        fi

        # Brief pause between cycles
        log "INFO" "Sleeping 60s before next cycle..."
        sleep 60
    done
}

main
