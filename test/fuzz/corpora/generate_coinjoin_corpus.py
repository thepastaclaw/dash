#!/usr/bin/env python3
"""
Generate seed corpus files for CoinJoin state machine fuzz targets.

Each corpus file is a raw byte sequence that FuzzedDataProvider will consume.
The structure must match what the harness expects to consume.
"""

import os
import struct
import hashlib
import random

random.seed(42)  # Deterministic corpus generation

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Dash denomination amounts (from common.h)
COIN = 100_000_000
DENOMS = [
    (10 * COIN) + 10000,   # denom bit 0 (1 << 0 = 1)
    (1 * COIN) + 1000,     # denom bit 1 (1 << 1 = 2)
    (COIN // 10) + 100,    # denom bit 2 (1 << 2 = 4)
    (COIN // 100) + 10,    # denom bit 3 (1 << 3 = 8)
    (COIN // 1000) + 1,    # denom bit 4 (1 << 4 = 16)
]
VALID_DENOM_BITS = [1, 2, 4, 8, 16]


def random_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def pack_outpoint():
    """32 bytes hash + 4 bytes index"""
    return random_bytes(32) + struct.pack('<I', random.randint(0, 10))


def pack_p2pkh_script_data():
    """20 bytes for the hash used in MakeP2PKHScript"""
    return random_bytes(20)


def pack_collateral():
    """Outpoint (36 bytes) + P2PKH script data (20 bytes)"""
    return pack_outpoint() + pack_p2pkh_script_data()


def pack_valid_denom_index():
    """1 byte: index 0-4 into VALID_DENOMS array"""
    return struct.pack('B', random.randint(0, 4))


# ──────────────────────────────────────────────────────────────────
# coinjoin_state_transitions corpus
# Format: sequence of (op_byte + op-specific data)
# ──────────────────────────────────────────────────────────────────
def gen_state_transitions():
    target_dir = os.path.join(SCRIPT_DIR, 'coinjoin_state_transitions')
    os.makedirs(target_dir, exist_ok=True)

    # Seed 1: Simple happy path (create → add users → check queue → add entries → check pool)
    data = b''
    # CREATE_SESSION (op=0) + denom index
    data += struct.pack('B', 0) + pack_valid_denom_index() + pack_collateral()
    # ADD_USER (op=1) x3 with matching denom
    for _ in range(3):
        data += struct.pack('B', 1) + struct.pack('B', 1)  # ConsumeBool=true (use session denom)
        data += pack_collateral()
    # CHECK_COMPLETE_QUEUE (op=2)
    data += struct.pack('B', 2)
    # ADD_ENTRY (op=3) x4
    for _ in range(4):
        data += struct.pack('B', 3)
        # num_inputs (1 byte, range 1-9)
        data += struct.pack('B', 2)
        # Entry data: 2 inputs * (outpoint + sequence + prevPubKey + txout_script) + collateral
        for _ in range(2):
            data += pack_outpoint() + pack_p2pkh_script_data() + pack_p2pkh_script_data()
        data += pack_collateral()
    # CHECK_POOL (op=4)
    data += struct.pack('B', 4)
    with open(os.path.join(target_dir, 'happy_path'), 'wb') as f:
        f.write(data)

    # Seed 2: Reset cycle
    data = b''
    for _ in range(5):
        data += struct.pack('B', 0) + pack_valid_denom_index() + pack_collateral()
        data += struct.pack('B', 6)  # RESET
    with open(os.path.join(target_dir, 'reset_cycle'), 'wb') as f:
        f.write(data)

    # Seed 3: Wrong-state operations
    data = b''
    # Try to add entry before session
    data += struct.pack('B', 3) + struct.pack('B', 1) + pack_outpoint() + pack_p2pkh_script_data() * 2 + pack_collateral()
    # Try to add scriptsig before signing
    data += struct.pack('B', 5) + pack_outpoint() + struct.pack('<I', 0xffffffff) + random_bytes(40)
    # Check pool in idle
    data += struct.pack('B', 4)
    with open(os.path.join(target_dir, 'wrong_state'), 'wb') as f:
        f.write(data)

    # Seed 4: Time manipulation
    data = b''
    data += struct.pack('B', 0) + pack_valid_denom_index() + pack_collateral()
    data += struct.pack('B', 7) + struct.pack('<q', 1000000)  # SET_MOCK_TIME
    data += struct.pack('B', 1) + struct.pack('B', 1) + pack_collateral()
    data += struct.pack('B', 7) + struct.pack('<q', 2000000000)  # far future
    data += struct.pack('B', 2)
    with open(os.path.join(target_dir, 'time_manipulation'), 'wb') as f:
        f.write(data)

    print(f"  Generated {len(os.listdir(target_dir))} seeds for coinjoin_state_transitions")


# ──────────────────────────────────────────────────────────────────
# coinjoin_queue_fuzz corpus
# ──────────────────────────────────────────────────────────────────
def gen_queue_fuzz():
    target_dir = os.path.join(SCRIPT_DIR, 'coinjoin_queue_fuzz')
    os.makedirs(target_dir, exist_ok=True)

    # Seed 1: Push + check cycle
    data = b''
    for _ in range(10):
        data += struct.pack('B', 0)  # push
        data += struct.pack('B', 1)  # ConsumeBool for valid denom
        data += pack_valid_denom_index()
        data += pack_outpoint()
        data += struct.pack('<q', random.randint(1600000000, 1800000000))  # nTime
        data += struct.pack('B', random.randint(0, 1))  # fReady
    data += struct.pack('B', 1)  # CheckQueue
    with open(os.path.join(target_dir, 'push_and_check'), 'wb') as f:
        f.write(data)

    # Seed 2: Timeout stress
    data = b''
    data += struct.pack('B', 4) + struct.pack('<q', 1600000000)  # set mock time
    for _ in range(5):
        data += struct.pack('B', 0)  # push
        data += struct.pack('B', 1)
        data += pack_valid_denom_index()
        data += pack_outpoint()
        data += struct.pack('<q', 1600000000 - 60)  # 60s old
        data += struct.pack('B', 0)
    data += struct.pack('B', 1)  # CheckQueue (should remove timed-out)
    with open(os.path.join(target_dir, 'timeout_stress'), 'wb') as f:
        f.write(data)

    # Seed 3: GetQueueItemAndTry exhaustion
    data = b''
    for _ in range(3):
        data += struct.pack('B', 0)  # push
        data += struct.pack('B', 1)
        data += pack_valid_denom_index()
        data += pack_outpoint()
        data += struct.pack('<q', int(random.random() * 2**63))
        data += struct.pack('B', 0)
    for _ in range(10):
        data += struct.pack('B', 2)  # GetQueueItemAndTry
    with open(os.path.join(target_dir, 'try_exhaustion'), 'wb') as f:
        f.write(data)

    print(f"  Generated {len(os.listdir(target_dir))} seeds for coinjoin_queue_fuzz")


# ──────────────────────────────────────────────────────────────────
# coinjoin_protocol_flow corpus
# ──────────────────────────────────────────────────────────────────
def gen_protocol_flow():
    target_dir = os.path.join(SCRIPT_DIR, 'coinjoin_protocol_flow')
    os.makedirs(target_dir, exist_ok=True)

    for denom_idx in range(5):
        data = b''
        # denom index
        data += pack_valid_denom_index()
        # collateral for creator
        data += pack_collateral()
        # num_participants (byte in range 3-20)
        num_p = random.randint(3, 5)
        data += struct.pack('B', num_p)
        # collaterals for remaining participants
        for _ in range(num_p - 1):
            data += pack_collateral()
        # inputs_per_entry
        data += struct.pack('B', random.randint(1, 3))
        # entries for each participant
        for _ in range(num_p):
            for _ in range(3):  # up to 3 inputs per entry
                data += pack_outpoint() + pack_p2pkh_script_data() * 2
            data += pack_collateral()
        # scriptsigs
        for _ in range(num_p * 3):
            sig_len = random.randint(30, 73)
            data += struct.pack('B', sig_len)
            data += random_bytes(sig_len)
        with open(os.path.join(target_dir, f'denom_{denom_idx}'), 'wb') as f:
            f.write(data)

    print(f"  Generated {len(os.listdir(target_dir))} seeds for coinjoin_protocol_flow")


# ──────────────────────────────────────────────────────────────────
# coinjoin_multi_entry_scriptsig corpus
# ──────────────────────────────────────────────────────────────────
def gen_multi_entry_scriptsig():
    target_dir = os.path.join(SCRIPT_DIR, 'coinjoin_multi_entry_scriptsig')
    os.makedirs(target_dir, exist_ok=True)

    data = b''
    data += pack_valid_denom_index()
    # num_entries
    data += struct.pack('B', 3)
    # collaterals
    for _ in range(3):
        data += pack_collateral()
    # entries
    outpoints = []
    for _ in range(3):
        data += struct.pack('B', 2)  # num_inputs
        for _ in range(2):
            op = pack_outpoint()
            outpoints.append(op)
            data += op + pack_p2pkh_script_data() * 2
        data += pack_collateral()
    # scriptsig attempts: mix valid and random
    for i in range(20):
        data += struct.pack('B', 1 if i % 2 == 0 else 0)  # ConsumeBool: use real input?
        if i % 2 == 0 and outpoints:
            # index into outpoints
            data += struct.pack('B', i % len(outpoints))
        else:
            data += pack_outpoint() + struct.pack('<I', 0xffffffff)
        sig_len = random.randint(10, 73)
        data += struct.pack('B', sig_len)
        data += random_bytes(sig_len)
    with open(os.path.join(target_dir, 'multi_entry_signing'), 'wb') as f:
        f.write(data)

    print(f"  Generated {len(os.listdir(target_dir))} seeds for coinjoin_multi_entry_scriptsig")


# ──────────────────────────────────────────────────────────────────
# coinjoin_broadcasttx_structure corpus
# ──────────────────────────────────────────────────────────────────
def gen_broadcasttx_structure():
    target_dir = os.path.join(SCRIPT_DIR, 'coinjoin_broadcasttx_structure')
    os.makedirs(target_dir, exist_ok=True)

    # Seed: valid structure + mutation bytes
    for denom_idx in range(5):
        data = b''
        # num_participants
        data += struct.pack('B', 3)
        # denom index
        data += pack_valid_denom_index()
        # inputs_per
        data += struct.pack('B', 1)
        # I/O data
        for _ in range(3):
            data += pack_outpoint() + pack_p2pkh_script_data()
        # protx hash + mn outpoint
        data += pack_outpoint()
        # mutation bytes
        for _ in range(20):
            data += struct.pack('B', random.randint(0, 6))
            data += random_bytes(30)  # extra data for mutations
        with open(os.path.join(target_dir, f'valid_base_{denom_idx}'), 'wb') as f:
            f.write(data)

    print(f"  Generated {len(os.listdir(target_dir))} seeds for coinjoin_broadcasttx_structure")


if __name__ == '__main__':
    print("Generating CoinJoin state machine fuzz corpus...")
    gen_state_transitions()
    gen_queue_fuzz()
    gen_protocol_flow()
    gen_multi_entry_scriptsig()
    gen_broadcasttx_structure()
    print("Done.")
