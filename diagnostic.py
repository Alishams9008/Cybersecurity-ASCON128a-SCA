"""
Rainbow Emulation Diagnostic Script
Run this FIRST before generate_traces.py to understand what is failing.
Output will tell you exactly which step is broken.
"""

import struct
import numpy as np

ELF_PATH = "bin/ascon128.elf"

# ── Step 1: Import ─────────────────────────────────────────────────
print("=" * 60)
print("STEP 1: Importing rainbow_arm")
try:
    from rainbow.generics.arm import rainbow_arm
    print("  [OK] rainbow_arm imported successfully")
except ImportError as ex:
    print(f"  [FAIL] Cannot import rainbow: {ex}")
    print("  → Run:  pip install rainbow-hw")
    raise SystemExit(1)

# ── Step 2: Load ELF ───────────────────────────────────────────────
print("\nSTEP 2: Loading ELF")
try:
    e = rainbow_arm()
    e.load(ELF_PATH)
    print(f"  [OK] ELF loaded: {ELF_PATH}")
except FileNotFoundError:
    print(f"  [FAIL] ELF not found at '{ELF_PATH}'")
    print("  → Check ELF_PATH in your config")
    raise SystemExit(1)
except Exception as ex:
    print(f"  [FAIL] ELF load error: {ex}")
    raise SystemExit(1)

# ── Step 3: Inspect symbols ────────────────────────────────────────
print("\nSTEP 3: Available function symbols")
fns = e.functions
if not fns:
    print("  [WARN] e.functions is empty — ELF may be stripped of symbols")
    print("  → Recompile with:  arm-none-eabi-gcc -g -O0 ...")
else:
    for name, addr in list(fns.items())[:30]:
        val = addr[0] if isinstance(addr, (list, tuple)) else addr
        print(f"    {name:40s} @ 0x{val:08x}")
    if len(fns) > 30:
        print(f"    ... and {len(fns)-30} more")

# ── Step 4: Find encrypt symbol ────────────────────────────────────
print("\nSTEP 4: Locating 'ascon128_encrypt'")
TARGET = 'ascon128_encrypt'
candidates = [k for k in fns if 'ascon' in k.lower() or 'encrypt' in k.lower()]
print(f"  Ascon/encrypt-related symbols found: {candidates}")

if TARGET in fns:
    val = fns[TARGET]
    addr = val[0] if isinstance(val, (list, tuple)) else val
    print(f"  [OK] '{TARGET}' found @ 0x{addr:08x}")
    ENCRYPT_ADDR = addr
elif candidates:
    first = candidates[0]
    val   = fns[first]
    addr  = val[0] if isinstance(val, (list, tuple)) else val
    print(f"  [WARN] '{TARGET}' not found, will try '{first}' @ 0x{addr:08x}")
    ENCRYPT_ADDR = addr
else:
    print(f"  [FAIL] No ascon/encrypt symbol found at all")
    print("  → Recompile with debug symbols, or check function name with:")
    print("      arm-none-eabi-nm bin/ascon128.elf | grep -i ascon")
    raise SystemExit(1)

# ── Step 5: Test hook attachment ───────────────────────────────────
print("\nSTEP 5: Testing instruction hook")
hook_count = [0]

def test_hook(state):
    hook_count[0] += 1

e.reset_trace()
e._code_hook = test_hook

# Minimal setup
KEY_ADDR = 0x20001000
NON_ADDR = KEY_ADDR + 16
AD_ADDR  = NON_ADDR + 16
PT_ADDR  = AD_ADDR  + 32
CT_ADDR  = PT_ADDR  + 32
TAG_ADDR = CT_ADDR  + 32
AD       = b"HeaderData\x00\x00\x00\x00\x00\x00"
PT       = b"SamplePlaintext!"
key      = bytes(range(16))
nonce    = bytes(range(16, 32))

for i in range(16):
    e[KEY_ADDR + i] = key[i]
    e[NON_ADDR + i] = nonce[i]
for i in range(len(AD)):
    e[AD_ADDR + i] = AD[i]
for i in range(len(PT)):
    e[PT_ADDR + i] = PT[i]

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

print(f"  Starting emulation at 0x{ENCRYPT_ADDR:08x} ...")
try:
    e.start(ENCRYPT_ADDR, SENTINEL, count=500_000)
except Exception as ex:
    print(f"  [INFO] Emulation stopped (normal): {type(ex).__name__}: {ex}")

print(f"  Hook fired {hook_count[0]} times")
if hook_count[0] == 0:
    print("  [FAIL] Hook never fired — code hook may not be supported this way")
    print("  → Try attaching hook via e.emu.hook_add() directly (see below)")
elif hook_count[0] < 10:
    print(f"  [WARN] Only {hook_count[0]} instructions executed — execution stopped early")
    print(f"         Current PC: 0x{e['pc']:08x}")
    print("  → Possible causes:")
    print("    1. SENTINEL address was branched to immediately (check LR setup)")
    print("    2. Unmapped memory access caused unicorn to abort")
    print("    3. ELF entry point mismatch (THUMB bit?)")
else:
    print(f"  [OK] {hook_count[0]} instructions executed")

# ── Step 6: Check hook API ─────────────────────────────────────────
print("\nSTEP 6: Checking _code_hook API compatibility")
print(f"  e._code_hook type after assignment: {type(e._code_hook)}")
# Some rainbow versions use a different attribute name
for attr in ['_code_hook', 'code_hook', '_hook', 'hook']:
    if hasattr(e, attr):
        print(f"  [INFO] Attribute '{attr}' exists on emulator")

# ── Step 7: Try unicorn hook directly ─────────────────────────────
print("\nSTEP 7: Trying direct Unicorn hook (alternative method)")
try:
    import unicorn
    from unicorn import UC_HOOK_CODE

    e2 = rainbow_arm()
    e2.load(ELF_PATH)

    direct_count = [0]

    def direct_hook(uc, address, size, user_data):
        direct_count[0] += 1

    e2.emu.hook_add(UC_HOOK_CODE, direct_hook)

    for i in range(16):
        e2[KEY_ADDR + i] = key[i]
        e2[NON_ADDR + i] = nonce[i]
    for i in range(len(AD)):
        e2[AD_ADDR + i] = AD[i]
    for i in range(len(PT)):
        e2[PT_ADDR + i] = PT[i]

    e2['r0'] = KEY_ADDR
    e2['r1'] = NON_ADDR
    e2['r2'] = AD_ADDR
    e2['r3'] = len(AD)
    e2['sp'] = sp
    for i, b in enumerate(stack_args):
        e2[sp + i] = b
    e2['lr'] = SENTINEL

    try:
        e2.start(ENCRYPT_ADDR, SENTINEL, count=500_000)
    except Exception as ex:
        pass

    print(f"  Direct UC_HOOK_CODE fired {direct_count[0]} times")
    if direct_count[0] > 10:
        print("  [OK] Direct unicorn hook WORKS — use this instead of _code_hook")
        print("  → Update generate_traces.py to use emu.hook_add(UC_HOOK_CODE, ...)")
    else:
        print("  [WARN] Direct hook also fired few times — emulation itself is the issue")
        if direct_count[0] == 0:
            print("  → Possible THUMB mode issue: try ENCRYPT_ADDR | 1")

except ImportError:
    print("  [SKIP] unicorn not directly importable, skip direct hook test")
except Exception as ex:
    print(f"  [ERROR] {ex}")

# ── Step 8: THUMB mode check ───────────────────────────────────────
print("\nSTEP 8: THUMB mode check")
addr_thumb = ENCRYPT_ADDR | 1
print(f"  Normal addr:  0x{ENCRYPT_ADDR:08x}")
print(f"  THUMB  addr:  0x{addr_thumb:08x}")
print(f"  Addr is already THUMB-aligned (odd): {bool(ENCRYPT_ADDR & 1)}")
if not (ENCRYPT_ADDR & 1):
    print("  [WARN] Address is even — for Cortex-M THUMB code, rainbow.start()")
    print("         may need addr|1.  Try passing (ENCRYPT_ADDR|1) to e.start()")

# ── Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("DIAGNOSTIC COMPLETE")
print("Share the output above and I can give you the exact fix.")
print("=" * 60)