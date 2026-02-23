#!/usr/bin/env python3
"""Generate deterministic seed corpus files for Dash-focused fuzzing targets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Callable, Dict, Iterable, List


DEFAULT_MANIFEST = Path(__file__).with_name("target_corpus_manifest.json")


def pack_compact_size(value: int) -> bytes:
    if value < 253:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def randbytes(rng: random.Random, size: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(size))


def p2p_message(command: str, payload: bytes, *, magic: bytes = b"\xbf\x0c\x6b\xbd") -> bytes:
    if len(command) > 12:
        raise ValueError(f"Command too long: {command}")
    command_bytes = command.encode("ascii") + (b"\x00" * (12 - len(command)))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return magic + command_bytes + struct.pack("<I", len(payload)) + checksum + payload


def gen_deserialize_dash(seed: int, files: int) -> List[bytes]:
    rng = random.Random(seed ^ 0xD35E)
    vectors: List[bytes] = [
        b"\x00",
        b"\x01",
        b"\xff" * 32,
        struct.pack("<i", 70228) + pack_compact_size(0),
        struct.pack("<q", 0),
    ]
    while len(vectors) < files:
        payload_len = rng.randint(0, 192)
        payload = randbytes(rng, payload_len)
        vectors.append(pack_compact_size(payload_len) + payload)
    return vectors[:files]


def gen_roundtrip_dash(seed: int, files: int) -> List[bytes]:
    rng = random.Random(seed ^ 0xA11CE)
    vectors: List[bytes] = [
        struct.pack("<i", 1) + b"\x00",
        struct.pack("<i", 2) + b"\x01\x00",
        struct.pack("<i", 3) + b"\x02\x00\x00",
    ]
    while len(vectors) < files:
        version = rng.randint(1, 4)
        payload = randbytes(rng, rng.randint(1, 220))
        vectors.append(struct.pack("<i", version) + pack_compact_size(len(payload)) + payload)
    return vectors[:files]


def gen_process_message_dash(seed: int, files: int) -> List[bytes]:
    rng = random.Random(seed ^ 0x50CC)
    commands = ["version", "verack", "ping", "pong", "inv", "addr", "getdata", "headers"]
    vectors: List[bytes] = [
        p2p_message("verack", b""),
        p2p_message("ping", struct.pack("<Q", 1)),
        p2p_message("pong", struct.pack("<Q", 2)),
    ]
    while len(vectors) < files:
        command = rng.choice(commands)
        payload = randbytes(rng, rng.randint(0, 260))
        vectors.append(p2p_message(command, payload))
    return vectors[:files]


def gen_llmq_messages(seed: int, files: int) -> List[bytes]:
    rng = random.Random(seed ^ 0x11A0)
    commands = ["qfcommit", "qsigsesann", "qsigsinv", "qgetdata", "qbsigs"]
    vectors: List[bytes] = [
        p2p_message("qfcommit", b"\x01" + (b"\x00" * 32)),
        p2p_message("qbsigs", b"\x00" + (b"\x11" * 96)),
    ]
    while len(vectors) < files:
        command = rng.choice(commands)
        msg_type = struct.pack("<B", rng.randint(0, 255))
        quorum_hash = randbytes(rng, 32)
        extra = randbytes(rng, rng.randint(0, 160))
        vectors.append(p2p_message(command, msg_type + quorum_hash + extra))
    return vectors[:files]


def gen_coinjoin_status_update(seed: int, files: int) -> List[bytes]:
    rng = random.Random(seed ^ 0xC01A)
    states = ["IDLE", "QUEUE", "ACCEPTING_ENTRIES", "SIGNING", "ERROR"]
    vectors: List[bytes] = []
    for idx, state in enumerate(states):
        vectors.append(f"{idx}|{state}|{idx * 10}|ok".encode("ascii"))
    while len(vectors) < files:
        session = rng.randint(0, 5000)
        state = rng.choice(states)
        denom = rng.choice([100001, 1000010, 10000100])
        flags = rng.randint(0, 0xFFFF)
        vectors.append(f"{session}|{state}|{denom}|{flags}".encode("ascii"))
    return vectors[:files]


GENERATORS: Dict[str, Callable[[int, int], List[bytes]]] = {
    "deserialize_dash": gen_deserialize_dash,
    "roundtrip_dash": gen_roundtrip_dash,
    "process_message_dash": gen_process_message_dash,
    "llmq_messages": gen_llmq_messages,
    "coinjoin_status_update": gen_coinjoin_status_update,
}


def load_manifest(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_vectors(target_dir: Path, vectors: Iterable[bytes]) -> int:
    target_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for idx, data in enumerate(vectors):
        digest = hashlib.sha256(data).hexdigest()[:16]
        out_path = target_dir / f"{idx:04d}_{digest}.bin"
        out_path.write_bytes(data)
        count += 1
    return count


def list_fuzz_targets(fuzz_binary: Path) -> List[str]:
    env = os.environ.copy()
    env["PRINT_ALL_FUZZ_TARGETS_AND_ABORT"] = "1"
    result = subprocess.run(
        [str(fuzz_binary)],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())


def validate_manifest_targets(manifest: Dict, fuzz_binary: Path) -> None:
    available = set(list_fuzz_targets(fuzz_binary))
    referenced = sorted({entry["fuzz_target"] for entry in manifest["targets"]})
    missing = [name for name in referenced if name not in available]
    if missing:
        raise SystemExit(
            "Manifest references unknown runnable fuzz target(s): " + ", ".join(missing)
        )
    print(f"Validated {len(referenced)} manifest fuzz target name(s) against {fuzz_binary}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Root output directory for generated corpus directories.",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="Target manifest path.")
    parser.add_argument("--seed", type=int, default=108, help="Deterministic seed value.")
    parser.add_argument(
        "--files-per-target",
        type=int,
        default=16,
        help="Number of files to emit per target corpus directory.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove existing target corpus directories before writing files.",
    )
    parser.add_argument(
        "--fuzz-binary",
        type=Path,
        help="Optional path to src/test/fuzz/fuzz for target-name validation.",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    if args.fuzz_binary is not None:
        validate_manifest_targets(manifest, args.fuzz_binary)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    generated = []

    for entry in manifest["targets"]:
        target = entry["target"]
        corpus_dir = entry["corpus_dir"]
        if target not in GENERATORS:
            raise SystemExit(f"No generator implemented for target '{target}'")

        target_dir = args.output_dir / corpus_dir
        if args.clean and target_dir.exists():
            shutil.rmtree(target_dir)

        vectors = GENERATORS[target](args.seed, args.files_per_target)
        written = write_vectors(target_dir, vectors)
        generated.append((target, corpus_dir, written))

    for target, corpus_dir, written in generated:
        print(f"{target}: wrote {written} file(s) -> {args.output_dir / corpus_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
