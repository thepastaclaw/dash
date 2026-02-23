# Dash OSS-Fuzz integration notes

This directory contains a candidate OSS-Fuzz project layout for Dash Core.

## Current status

Dash Core is not currently enrolled as a standalone OSS-Fuzz project in
`google/oss-fuzz`.

The files here are intended to make review and onboarding easier by keeping a
ready-to-submit `build.sh` and `project.yaml` template in-tree.

## Strategy

- Build a single `src/test/fuzz/fuzz` binary with Dash's existing libFuzzer
  harnesses.
- Enumerate harness names from the binary with
  `PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1`.
- Generate one OSS-Fuzz entrypoint wrapper per harness in `$OUT`.
- Each wrapper exports `FUZZ=<target>` and dispatches to the shared fuzz
  binary.

This approach keeps Dash's existing `FUZZ=<target> src/test/fuzz/fuzz` model,
while satisfying OSS-Fuzz's requirement for one executable per fuzz target.

## Local usage

Run from the repository root:

```sh
OUT="$(mktemp -d)" ./contrib/oss-fuzz/build.sh
```

The command will:

- configure and build `src/test/fuzz/fuzz` in `build-oss-fuzz/` by default
- copy the shared binary to `$OUT/dash_fuzz`
- write discovered targets to `$OUT/dash_fuzz_targets.txt`
- generate one wrapper executable per target in `$OUT/`

Try a wrapper directly:

```sh
"$OUT/bech32" -runs=1
```

Optional knobs:

- `BUILD_DIR=/path/to/build-dir` to override the build directory
- `JOBS=<n>` to control parallel build jobs
