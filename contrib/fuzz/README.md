# Dash Seed Corpus Generation

This directory contains deterministic tooling to generate Dash-focused seed corpus
inputs for fuzzing workflows and continuous corpus refresh jobs.

## Files

- `generate_dash_seed_corpus.py`: deterministic corpus generator script
- `target_corpus_manifest.json`: mapping of corpus directories to target IDs and
  runnable fuzz target names

## Generate Corpus Locally

From repository root:

```sh
python3 contrib/fuzz/generate_dash_seed_corpus.py \
  --output-dir ./fuzz_seed_corpus_dash \
  --seed 108 \
  --files-per-target 16 \
  --clean
```

Generated output directories:

- `fuzz_seed_corpus_dash/deserialize_dash`
- `fuzz_seed_corpus_dash/roundtrip_dash`
- `fuzz_seed_corpus_dash/process_message_dash`
- `fuzz_seed_corpus_dash/llmq_messages`
- `fuzz_seed_corpus_dash/coinjoin_status_update`

## Determinism

For the same `--seed`, `--files-per-target`, and script version, output is
stable and reproducible (same file names and bytes).

## Validate Manifest Target Names

To verify that manifest runnable target names exist in a built fuzz binary:

```sh
python3 contrib/fuzz/generate_dash_seed_corpus.py \
  --output-dir ./fuzz_seed_corpus_dash \
  --seed 108 \
  --clean \
  --fuzz-binary ./src/test/fuzz/fuzz
```

This runs `PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1` on the supplied binary and checks
that all `fuzz_target` values in `target_corpus_manifest.json` are valid.

## CI/Cron Usage

The generator is non-interactive and can be run from CI or cron jobs. Example:

```sh
python3 contrib/fuzz/generate_dash_seed_corpus.py \
  --output-dir /var/lib/dash/fuzz_seed_corpus_dash \
  --seed 108 \
  --files-per-target 32 \
  --clean
```
