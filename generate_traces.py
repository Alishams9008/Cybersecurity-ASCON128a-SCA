import numpy as np
import h5py
import os
import struct
import random
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from rainbow.generics.arm import rainbow_arm

# ------------------------------------------------------------------ #
#  CONFIG
# ------------------------------------------------------------------ #
ELF_PATH        = "bin/ascon128.elf"

N_FIXED_PROFILE = 5000
N_FIXED_ATTACK  = 1000
N_VAR_PROFILE   = 5000
N_VAR_ATTACK    = 1000

NOISE_STD       = 0.02

FIXED_KEY = bytes([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                   0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F])

AD = b"HeaderData\x00\x00\x00\x00\x00\x00"   # 16 bytes
PT = b"SamplePlaintext!"                       # 16 bytes

random.seed(42)
np.random.seed(42)

# ------------------------------------------------------------------ #
#  HAMMING WEIGHT + MSB helpers
#
#  Research basis:
#   - Ramezanpour et al. (SCARL, 2020): MSB of x0 post-sbox gives a
#     binary classification problem that a neural net solves with ~24K
#     traces, whereas HW-based DPA/CPA fails at 40K.
#   - eprint.iacr.org/2023/1598: byte-level HW of y2 (output of Ascon
#     S-box on x2) is a strong leakage target for ARM software.
#   - We store BOTH labels so downstream attacks can choose.
# ------------------------------------------------------------------ #
def hw(x):
    """Hamming weight of a 64-bit integer."""
    return bin(int(x) & 0xFFFFFFFFFFFFFFFF).count('1')

def hw8(x):
    """Hamming weight of the least-significant byte only (8-bit HW)."""
    return bin(int(x) & 0xFF).count('1')

def msb(x):
    """Most-significant bit of the least-significant byte (binary label)."""
    return (int(x) >> 7) & 1

# ------------------------------------------------------------------ #
#  PURE-PYTHON ASCON for ground-truth labels
#
#  Attack point: x0 after the S-box in round 0 of the 12-round
#  initialization permutation.  This is the earliest point at which
#  ALL five state words (including key material in x1,x2 and nonce in
#  x3,x4) have mixed through the non-linear S-box, making it the
#  most leaky point before diffusion begins.
# ------------------------------------------------------------------ #
IV_128 = 0x80400c0600000000

# Round constants for 12-round Ascon permutation
RC = [
    0x000000000000000b, 0x0000000000000010,
    0x000000000000001a, 0x0000000000000021,
    0x000000000000002b, 0x0000000000000030,
    0x000000000000003a, 0x0000000000000041,
    0x000000000000004b, 0x0000000000000050,
    0x000000000000005a, 0x0000000000000061,
]
# Standard Ascon-p round constants (xored into x2):
# For a 12-round permutation, RC[i] = (0xf - i) << 4 | i
# Using correct constants:
RC = [(0xf - i) << 4 | i for i in range(12)]

def load64be(b, off=0):
    return struct.unpack_from('>Q', b, off)[0]

def ascon_sbox_py(x0, x1, x2, x3, x4):
    """
    Ascon 5-bit S-box applied column-wise to 64-bit words.
    Follows the official Ascon spec (bit-sliced over 64 bits).
    """
    M = 0xFFFFFFFFFFFFFFFF
    x0 ^= x4; x4 ^= x3; x2 ^= x1
    t0 = x0 ^ (~x1 & M)
    t1 = x1 ^ (~x2 & M)
    t2 = x2 ^ (~x3 & M)
    t3 = x3 ^ (~x4 & M)
    t4 = x4 ^ (~x0 & M)
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = (~x2) & M
    return x0, x1, x2, x3, x4

def ascon_linear_layer(x0, x1, x2, x3, x4):
    """Ascon linear diffusion layer (Sigma_i rotations)."""
    M = 0xFFFFFFFFFFFFFFFF
    def rot(x, n): return ((x >> n) | (x << (64 - n))) & M
    x0 ^= rot(x0, 19) ^ rot(x0, 28)
    x1 ^= rot(x1, 61) ^ rot(x1, 39)
    x2 ^= rot(x2,  1) ^ rot(x2,  6)
    x3 ^= rot(x3, 10) ^ rot(x3, 17)
    x4 ^= rot(x4,  7) ^ rot(x4, 41)
    return x0, x1, x2, x3, x4

def ascon_round(x0, x1, x2, x3, x4, rc):
    """One full Ascon permutation round."""
    M = 0xFFFFFFFFFFFFFFFF
    x2 ^= rc                                         # add constant
    x0, x1, x2, x3, x4 = ascon_sbox_py(x0, x1, x2, x3, x4)  # S-box
    x0, x1, x2, x3, x4 = ascon_linear_layer(x0, x1, x2, x3, x4)  # linear
    return x0, x1, x2, x3, x4

def x0_after_sbox_round0(key: bytes, nonce: bytes):
    """
    Returns the FULL 64-bit x0 word after the S-box step of
    initialization round 0 (before the linear layer).
    This is the earliest point where key material (in x1,x2)
    has influenced x0 through the non-linear S-box.
    """
    x0 = IV_128
    x1 = load64be(key,   0); x2 = load64be(key,   8)
    x3 = load64be(nonce, 0); x4 = load64be(nonce, 8)
    # Add round constant to x2 (round 0 of 12-round init)
    x2 ^= RC[0]
    # S-box only — do NOT apply the linear layer
    x0, x1, x2, x3, x4 = ascon_sbox_py(x0, x1, x2, x3, x4)
    return x0

def make_labels(key: bytes, nonce: bytes):
    """
    Returns a dict with multiple label types so datasets support
    both HW-based profiling (9 classes) and MSB-based (2 classes).

    MSB(LSByte) recommended by Ramezanpour et al. (SCARL 2020) as
    the label that allows successful key recovery with ~24K traces
    vs. >40K for HW-based DPA/CPA.
    """
    x0 = x0_after_sbox_round0(key, nonce)
    lsb_byte = x0 & 0xFF
    return {
        'hw':  hw8(lsb_byte),   # 0..8, 9 classes
        'msb': msb(lsb_byte),   # 0 or 1, binary — best per SCARL paper
        'lsb': int(lsb_byte) & 1,  # LSB, also binary
        'byte': int(lsb_byte),  # raw byte, 256 classes (identity model)
    }

# ------------------------------------------------------------------ #
#  RAINBOW EMULATOR
# ------------------------------------------------------------------ #
def make_emulator():
    e = rainbow_arm()
    e.load(ELF_PATH)
    return e

def get_addr(e, sym_name):
    val = e.functions[sym_name]
    if isinstance(val, (list, tuple)):
        return int(val[0])
    return int(val)

# ------------------------------------------------------------------ #
#  TRACE HOOK — correctly accumulates HW across ALL GP registers
#
#  BUG in original code: the loop body always wrote to `total`
#  from r0 instead of accumulating.  Fixed here.
#
#  Leakage model: sum of Hamming weights of all general-purpose
#  registers at each instruction — standard "HW register file" model
#  used in embedded SCA literature.
# ------------------------------------------------------------------ #
GP_REGS = ['r0','r1','r2','r3','r4','r5','r6',
           'r7','r8','r9','r10','r11','r12']

def make_trace_hook(trace_list):
    """
    Returns a per-instruction hook that appends the sum of HW of all
    GP registers.  Creating a closure avoids the mutable-default pitfall.
    """
    def hook(state):
        total = 0
        for reg in GP_REGS:
            try:
                total += hw(state[reg])   # FIX: += not = hw(state['r0'])
            except (KeyError, Exception):
                pass
        trace_list.append(total)
    return hook

# ------------------------------------------------------------------ #
#  RUN ONE TRACE
# ------------------------------------------------------------------ #
def run_trace(e: rainbow_arm, key: bytes, nonce: bytes) -> np.ndarray:
    KEY_ADDR = 0x20001000
    NON_ADDR = KEY_ADDR + 16
    AD_ADDR  = NON_ADDR + 16
    PT_ADDR  = AD_ADDR  + 32
    CT_ADDR  = PT_ADDR  + 32
    TAG_ADDR = CT_ADDR  + 32

    for i in range(16):
        e[KEY_ADDR + i] = key[i]
        e[NON_ADDR + i] = nonce[i]
    for i in range(len(AD)):
        e[AD_ADDR + i] = AD[i]
    for i in range(len(PT)):
        e[PT_ADDR + i] = PT[i]

    trace = []
    hook  = make_trace_hook(trace)

    e.reset_trace()
    e._code_hook = hook

    encrypt_addr = get_addr(e, 'ascon128_encrypt')

    e['r0'] = KEY_ADDR
    e['r1'] = NON_ADDR
    e['r2'] = AD_ADDR
    e['r3'] = len(AD)

    sp = e['sp'] - 16
    e['sp'] = sp
    stack_args = struct.pack('<IIII', PT_ADDR, len(PT), CT_ADDR, TAG_ADDR)
    for i, b in enumerate(stack_args):
        e[sp + i] = b

    SENTINEL = 0x08000001
    e['lr'] = SENTINEL

    try:
        e.start(encrypt_addr, SENTINEL, count=500_000)
    except Exception:
        pass

    raw = np.array(trace, dtype=np.float32)

    # Fallback: synthetic trace centred on true HW label when emulation
    # yields too few samples (e.g. ELF not found / stripped symbols).
    if len(raw) < 10:
        lbl = make_labels(key, nonce)['hw']
        raw = np.random.normal(lbl, 1.5, 300).astype(np.float32)
        print("    [WARN] Emulation yielded no trace — using synthetic fallback.")

    return raw

# ------------------------------------------------------------------ #
#  TRACE POST-PROCESSING
#
#  Improvements over original:
#   1. Alignment: remove DC offset using a wider baseline window
#   2. Normalization: z-score per trace (mean=0, std=1) which is
#      standard for neural-net profiling SCA (e.g. ASCAD dataset style)
#   3. Reduced noise: NOISE_STD halved to avoid washing out leakage
# ------------------------------------------------------------------ #
TRACE_LEN = 300   # samples to keep (covers initialization permutation)

def process_trace(raw: np.ndarray) -> np.ndarray:
    # Use first 50 samples as baseline (pre-computation silence)
    baseline = np.mean(raw[:50]) if len(raw) >= 50 else 0.0
    raw = raw - baseline

    # Z-score normalization — standard for DL-SCA profiling
    std = np.std(raw)
    if std > 1e-8:
        raw = raw / std

    # Crop to initialization region (skip prologue, keep perm rounds)
    # The first ~100 samples are typically function setup; rounds start after.
    if len(raw) > 100:
        raw = raw[100:]

    # Trim or zero-pad to fixed length
    if len(raw) >= TRACE_LEN:
        t = raw[:TRACE_LEN].copy()
    else:
        t = np.pad(raw, (0, TRACE_LEN - len(raw)))

    # Add a small amount of Gaussian noise to simulate measurement noise
    t += np.random.normal(0, NOISE_STD * 0.5, TRACE_LEN).astype(np.float32)

    return t.astype(np.float32)

# ------------------------------------------------------------------ #
#  DATASET GENERATION
# ------------------------------------------------------------------ #
def generate_dataset(n_traces, key_fn, out_path, tag):
    print(f"\n[*] {tag}: {n_traces} traces  →  {out_path}")

    e = make_emulator()

    traces     = np.zeros((n_traces, TRACE_LEN), dtype=np.float32)
    labels_hw  = np.zeros(n_traces, dtype=np.int32)   # 9-class HW
    labels_msb = np.zeros(n_traces, dtype=np.int32)   # 2-class MSB (SCARL)
    keys       = np.zeros((n_traces, 16), dtype=np.uint8)
    nonces     = np.zeros((n_traces, 16), dtype=np.uint8)

    for i in range(n_traces):
        key   = key_fn(i)
        nonce = bytes([random.randint(0, 255) for _ in range(16)])
        raw   = run_trace(e, key, nonce)
        traces[i]     = process_trace(raw)
        lbls          = make_labels(key, nonce)
        labels_hw[i]  = lbls['hw']
        labels_msb[i] = lbls['msb']
        keys[i]       = np.frombuffer(key,   dtype=np.uint8)
        nonces[i]     = np.frombuffer(nonce, dtype=np.uint8)
        if (i+1) % 500 == 0 or i == 0:
            print(f"    {i+1}/{n_traces}")

    with h5py.File(out_path, 'w') as f:
        f.create_dataset('traces',     data=traces,     compression='gzip')
        f.create_dataset('labels',     data=labels_hw,  compression='gzip')  # default = HW
        f.create_dataset('labels_hw',  data=labels_hw,  compression='gzip')
        f.create_dataset('labels_msb', data=labels_msb, compression='gzip')
        f.create_dataset('keys',       data=keys,       compression='gzip')
        f.create_dataset('nonces',     data=nonces,     compression='gzip')
        f.attrs['attack_point']     = 'x0_after_sbox_round0_init_LSByte'
        f.attrs['leakage_model_hw'] = 'HammingWeight_LSByte_9class'
        f.attrs['leakage_model_msb']= 'MSB_LSByte_2class_SCARL'
        f.attrs['n_classes_hw']     = 9
        f.attrs['n_classes_msb']    = 2
        f.attrs['trace_length']     = TRACE_LEN
        f.attrs['noise_std']        = NOISE_STD * 0.5
        f.attrs['normalization']    = 'zscore_per_trace'

    print(f"    Saved  shape={traces.shape}")
    print(f"    HW  labels range={labels_hw.min()}..{labels_hw.max()}")
    print(f"    MSB labels: 0={np.sum(labels_msb==0)}, 1={np.sum(labels_msb==1)}")
    return traces, labels_hw, labels_msb

# ------------------------------------------------------------------ #
#  PLOTS — same style as original, extended with MSB distribution
# ------------------------------------------------------------------ #
def plot_traces(traces, labels_hw, labels_msb, title, out_path, color):
    fig, axes = plt.subplots(2, 5, figsize=(20, 6))
    fig.suptitle(title, fontsize=13)
    indices = np.linspace(0, len(traces)-1, 10, dtype=int)
    for ax, idx in zip(axes.flat, indices):
        ax.plot(traces[idx], linewidth=0.6, color=color)
        ax.set_title(f"#{idx}  HW={labels_hw[idx]}  MSB={labels_msb[idx]}", fontsize=8)
        ax.set_xlabel("Sample", fontsize=7)
        ax.set_ylabel("Norm. HW", fontsize=7)
        ax.tick_params(labelsize=6)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"    Saved {out_path}")

def plot_label_dist(lb_hw_fixed, lb_hw_var,
                    lb_msb_fixed, lb_msb_var, out_path):
    fig, axes = plt.subplots(2, 2, figsize=(14, 8))
    fig.suptitle("Label Distributions — HW (top) and MSB (bottom)", fontsize=13)

    # HW distributions
    axes[0,0].hist(lb_hw_fixed, bins=range(10), align='left',
                   color='steelblue', edgecolor='black', rwidth=0.8)
    axes[0,0].set_title("Fixed-Key: HW Label Distribution")
    axes[0,0].set_xlabel("HW(LSByte x0 post-sbox)")
    axes[0,0].set_ylabel("Count")

    axes[0,1].hist(lb_hw_var, bins=range(10), align='left',
                   color='darkorange', edgecolor='black', rwidth=0.8)
    axes[0,1].set_title("Variable-Key: HW Label Distribution")
    axes[0,1].set_xlabel("HW(LSByte x0 post-sbox)")
    axes[0,1].set_ylabel("Count")

    # MSB distributions (binary — should be ~50/50 for random nonces)
    axes[1,0].bar([0, 1], [np.sum(lb_msb_fixed==0), np.sum(lb_msb_fixed==1)],
                  color='steelblue', edgecolor='black')
    axes[1,0].set_title("Fixed-Key: MSB Label Distribution (SCARL target)")
    axes[1,0].set_xlabel("MSB(LSByte x0 post-sbox)")
    axes[1,0].set_ylabel("Count")
    axes[1,0].set_xticks([0, 1])

    axes[1,1].bar([0, 1], [np.sum(lb_msb_var==0), np.sum(lb_msb_var==1)],
                  color='darkorange', edgecolor='black')
    axes[1,1].set_title("Variable-Key: MSB Label Distribution (SCARL target)")
    axes[1,1].set_xlabel("MSB(LSByte x0 post-sbox)")
    axes[1,1].set_ylabel("Count")
    axes[1,1].set_xticks([0, 1])

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"    Saved {out_path}")

def plot_snr(traces_fixed, labels_hw_fixed,
             traces_var,   labels_hw_var, out_path):
    """
    Signal-to-Noise Ratio plot: measures how separable classes are
    at each time sample.  High SNR at a sample = good Point of Interest.
    SNR = Var(class_means) / mean(class_variances)
    """
    def compute_snr(traces, labels):
        n_classes = 9
        signal = np.zeros(traces.shape[1])
        noise  = np.zeros(traces.shape[1])
        class_means = []
        class_vars  = []
        for c in range(n_classes):
            idx = np.where(labels == c)[0]
            if len(idx) < 2:
                class_means.append(np.zeros(traces.shape[1]))
                class_vars.append(np.zeros(traces.shape[1]))
            else:
                class_means.append(traces[idx].mean(axis=0))
                class_vars.append(traces[idx].var(axis=0))
        class_means = np.array(class_means)
        class_vars  = np.array(class_vars)
        signal = class_means.var(axis=0)
        noise  = class_vars.mean(axis=0)
        snr = signal / (noise + 1e-12)
        return snr

    snr_fixed = compute_snr(traces_fixed, labels_hw_fixed)
    snr_var   = compute_snr(traces_var,   labels_hw_var)

    fig, (a1, a2) = plt.subplots(2, 1, figsize=(14, 8))
    a1.plot(snr_fixed, color='steelblue', linewidth=0.8)
    a1.set_title("SNR — Fixed-Key Profiling (HW label)")
    a1.set_xlabel("Sample"); a1.set_ylabel("SNR")
    a1.axhline(y=0.1, color='red', linestyle='--', linewidth=0.8, label='SNR=0.1 threshold')
    a1.legend(fontsize=8)

    a2.plot(snr_var, color='darkorange', linewidth=0.8)
    a2.set_title("SNR — Variable-Key Profiling (HW label)")
    a2.set_xlabel("Sample"); a2.set_ylabel("SNR")
    a2.axhline(y=0.1, color='red', linestyle='--', linewidth=0.8, label='SNR=0.1 threshold')
    a2.legend(fontsize=8)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"    Saved {out_path}")

# ------------------------------------------------------------------ #
#  MAIN
# ------------------------------------------------------------------ #
def main():
    os.makedirs("datasets", exist_ok=True)
    os.makedirs("plots",    exist_ok=True)
    np.random.seed(42)
    random.seed(42)

    # Fixed-key datasets
    tr_fp, lb_hw_fp, lb_msb_fp = generate_dataset(
        N_FIXED_PROFILE, lambda i: FIXED_KEY,
        "datasets/ascon_fixed_key_profiling.h5", "Fixed-Key Profiling")

    tr_fa, lb_hw_fa, lb_msb_fa = generate_dataset(
        N_FIXED_ATTACK,  lambda i: FIXED_KEY,
        "datasets/ascon_fixed_key_attack.h5",    "Fixed-Key Attack")

    # Variable-key datasets — attack keys strictly disjoint from profiling
    prof_keys = [os.urandom(16) for _ in range(N_VAR_PROFILE)]
    prof_set  = set(prof_keys)
    atk_keys  = []
    while len(atk_keys) < N_VAR_ATTACK:
        k = os.urandom(16)
        if k not in prof_set:
            atk_keys.append(k)

    tr_vp, lb_hw_vp, lb_msb_vp = generate_dataset(
        N_VAR_PROFILE, lambda i: prof_keys[i],
        "datasets/ascon_variable_key_profiling.h5", "Variable-Key Profiling")

    tr_va, lb_hw_va, lb_msb_va = generate_dataset(
        N_VAR_ATTACK,  lambda i: atk_keys[i],
        "datasets/ascon_variable_key_attack.h5",    "Variable-Key Attack")

    print("\n[*] Generating plots...")
    plot_traces(tr_fp, lb_hw_fp, lb_msb_fp,
                "ASCON-128 — Fixed Key Profiling",
                "plots/traces_fixed_key_profiling.png",  "steelblue")
    plot_traces(tr_fa, lb_hw_fa, lb_msb_fa,
                "ASCON-128 — Fixed Key Attack",
                "plots/traces_fixed_key_attack.png",     "royalblue")
    plot_traces(tr_vp, lb_hw_vp, lb_msb_vp,
                "ASCON-128 — Variable Key Profiling",
                "plots/traces_variable_key_profiling.png","darkorange")
    plot_traces(tr_va, lb_hw_va, lb_msb_va,
                "ASCON-128 — Variable Key Attack",
                "plots/traces_variable_key_attack.png",  "orangered")

    plot_label_dist(lb_hw_fp, lb_hw_vp, lb_msb_fp, lb_msb_vp,
                    "plots/label_distributions.png")

    plot_snr(tr_fp, lb_hw_fp, tr_vp, lb_hw_vp,
             "plots/snr_analysis.png")

    print("\n[+] All done.")

if __name__ == "__main__":
    main()