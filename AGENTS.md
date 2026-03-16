# Guzzle — AI Agent Guide

Guzzle is a desktop app that wraps libFuzzer to make fuzzing C/C++ code accessible. This file tells AI agents (Claude Code, Codex, etc.) how to help a user fuzz their code using Guzzle — either by driving the GUI workflow or by replicating it manually from the CLI.

## What Guzzle does

1. Open a C/C++ source file and pick a function
2. AI generates a libFuzzer harness for that function
3. Compile the harness with clang + AddressSanitizer + libFuzzer
4. Run the fuzzer and capture crashes
5. For each crash: compile a standalone reproducer, extract ROP gadgets, generate a pwntools exploit scaffold

## Driving the workflow manually (CLI / agent-assisted)

If the user wants you to drive fuzzing directly without the GUI, follow these steps:

### 1. Find a target function

Look for functions that handle untrusted input — parsers, decoders, format readers, protocol handlers. Good candidates:
- Take a buffer + length (`const uint8_t *data, size_t size`)
- Take a filename or file pointer
- Parse structured data (images, packets, config files)

### 2. Generate a harness

Write a file `harness.cpp`:

```cpp
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Forward-declare the target
extern "C" int TargetFunction(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // parse / coerce data into what the target expects, then call it
    TargetFunction(data, size);
    return 0;
}
```

Rules:
- No `exit()` or `abort()`
- No platform-specific headers (`<unistd.h>`, `<fcntl.h>`) without `#ifndef _WIN32` guards
- If the function needs a file path, write to `/tmp/guzzle_input` (Linux/macOS) or `C:\Temp\guzzle_input` (Windows) — never the current directory
- Guard all pointer dereferences

### 3. Compile

```bash
# Linux / macOS
clang++ -fsanitize=fuzzer,address -O1 -g \
  harness.cpp target.c \
  -o fuzzer

# Windows (clang-cl / LLVM)
clang++ -fsanitize=fuzzer,address -O1 -g \
  -D_CRT_SECURE_NO_WARNINGS -ldbghelp -lshell32 \
  harness.cpp target.c \
  -o fuzzer.exe
```

If the target has a `main()`, rename it: add `-Dmain=__target_main` to the compile flags.

### 4. Run the fuzzer

```bash
mkdir -p corpus crashes
./fuzzer corpus/ -artifact_prefix=crashes/ -max_total_time=300
```

Crashes are written to `crashes/`. The fuzzer prints `SUMMARY: AddressSanitizer` on a find.

### 5. Reproduce a crash

```bash
./fuzzer crashes/crash-<hash>
```

Or compile a standalone reproducer (no libFuzzer dependency):

```c
// reproducer_main.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f); fclose(f);
    LLVMFuzzerTestOneInput(buf, sz);
    free(buf);
}
```

```bash
clang++ -O0 -no-pie -fno-stack-protector -g \
  harness.cpp target.c reproducer_main.c \
  -o reproducer
./reproducer crashes/crash-<hash>
```

### 6. Triage the crash

Run the fuzzer binary (not the reproducer) on the crash file to get the full ASan report:

```bash
./fuzzer crashes/crash-<hash>
```

The report tells you the bug class, the exact write address and size, and both stack traces
(allocation site + overflow site). That determines the exploitation path:

| ASan report says | Exploitation path |
|---|---|
| `heap-buffer-overflow` | Heap grooming → corrupt adjacent object → write primitive → ROP |
| `stack-buffer-overflow` | Find offset to saved return address → ROP chain |
| `heap-use-after-free` | Reclaim freed chunk with controlled data → type confusion |
| `SEGV on unknown address 0x0` | Null deref — usually not directly exploitable |

### 7. Extract ROP gadgets

```bash
# macOS (Mach-O):
r2 -q -c "aaa;/R;q" reproducer
# Linux (ELF):
ROPgadget --binary reproducer --rop --nosys | head -200
# or: ropper -f reproducer
```

### 8. Deep exploitation (iterative agent loop)

The Guzzle GUI generates a one-shot PoC scaffold. For complex heap vulnerabilities
(CVE-style, multi-stage primitives) an agent working iteratively will go much further.
The loop is:

```
read source → understand allocator state → craft input → run → observe → refine
```

#### 8a. Map the heap layout from source

Read the target source and build a picture of what lives on the heap:

- What structs are allocated, in what order, and at what sizes?
- Which allocations happen before the vulnerable one?
- Which allocation immediately follows the vulnerable buffer? That's your corruption target.
- What fields does the target struct contain — function pointers, lengths, pointers to other allocations?

```bash
# Check allocation sizes for tcache bucket alignment (glibc: round to 16 bytes + 8 header)
# A malloc(N) lives in the tcache/fastbin for chunk size ceil((N+8)/16)*16
python3 -c "n=48; print(f'chunk size: {((n+8+15)//16)*16}')"
```

#### 8b. Inspect heap state at crash time

Compile the reproducer with debug info and run it under a debugger:

```bash
# Linux — enable core dumps, then examine
ulimit -c unlimited
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
./reproducer crashes/crash-<hash>   # produces core
gdb reproducer core
(gdb) heap chunks      # requires gef/pwndbg
(gdb) x/32gx <addr>   # inspect raw memory around the overflow

# macOS — use lldb
lldb -- ./reproducer crashes/crash-<hash>
(lldb) settings set target.disable-aslr true
(lldb) run
(lldb) memory read --size 8 --format x <addr>
```

Key things to find:
- What chunk immediately follows the overflow buffer in memory?
- Is it a struct you control the contents of (e.g. from a previous input field)?
- Does it contain a length, a pointer, or a function pointer you can redirect?

#### 8c. Craft a grooming sequence

Heap grooming means arranging allocations so the right object lands adjacent to the
overflow buffer. The general pattern:

1. **Drain the freelist** — allocate enough same-sized chunks to exhaust the tcache/fastbin
   for the target size, forcing the next allocation to come from the top of the heap
2. **Allocate the victim** — allocate the object you want to corrupt right after draining
3. **Allocate the overflow buffer** — now it lands immediately before the victim
4. **Trigger the overflow** — corrupt exactly the field you identified in 8b

Translate this into input bytes. For a parser like msgparse, each field in the input
controls one allocation — use multiple TLV records to set up the heap before the
vulnerable one fires.

Test each grooming attempt:

```bash
# Write candidate input to a file, run under ASan to observe what gets corrupted
python3 -c "
import struct
# Build a grooming input: several allocations to drain tcache, then the victim
payload  = b'\\x04' + struct.pack('>H', 48) + b'A'*48   # drain: BLOB 48 bytes
payload += b'\\x04' + struct.pack('>H', 48) + b'B'*48   # victim: BLOB 48 bytes
payload += b'\\x01' + struct.pack('>H', 47) + b'C'*47   # overflow: STRING 47 bytes
open('/tmp/candidate', 'wb').write(payload)
"
./fuzzer /tmp/candidate 2>&1 | grep -A5 'heap-buffer-overflow'
```

Observe the ASan shadow output — it shows which chunk was corrupted. Adjust sizes and
ordering based on what you see, then repeat.

#### 8d. Turn a write into execution

Once you can reliably corrupt a specific field:

- **Corrupt a length field** → turns a bounded read/write into an unbounded one (second-order primitive)
- **Corrupt a function pointer** → direct PC control; point at a ROP gadget or shellcode
- **Corrupt a pointer** → redirect where data is written; aim at GOT/PLT (Linux, no RELRO) or a known writable address

For stack pivot + ROP on Linux (no PIE):

```python
from pwn import *
e = ELF('./reproducer')
rop = ROP(e)
rop.call('system', [next(e.search(b'/bin/sh\x00'))])
payload = fit({offset: rop.chain()})
```

For macOS (PIE, no GOT): leak a heap address from the ASan output or a read primitive,
calculate the slide, then use gadgets from the radare2 output at `base + gadget_offset`.

#### 8e. Verify and minimise

```bash
# Confirm the exploit works end-to-end
python3 exploit.py

# Minimise the crash input (libFuzzer built-in)
./fuzzer -minimize_crash=1 -exact_artifact_path=crashes/min-<hash> crashes/crash-<hash>
```

A minimised input makes the grooming sequence easier to understand and the PoC easier
to explain.

## Tips for agents

- **Start simple**: fuzz one function at a time, not the whole binary
- **Check for companion headers**: if fuzzing `msgparse.c`, include `msgparse.h` in the harness for type definitions
- **Seed the corpus**: put small valid inputs in `corpus/` before running — the fuzzer explores much faster
- **ASLR**: disable for reliable addresses: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
- **Crash triage**: `AddressSanitizer: heap-buffer-overflow` and `stack-buffer-overflow` are the most exploitable; `SEGV on unknown address 0x0` is usually just a null deref
- **The GUI Gen PoC is a scaffold**: it gets you the bug class and a starting script; complex heap exploits require the iterative loop in section 8
- **Iterate on grooming**: wrong chunk size or ordering means you corrupt the wrong object — read the ASan shadow output after each attempt and adjust
- **Minimise before exploiting**: `./fuzzer -minimize_crash=1` strips the crash input to its essential bytes, making the heap layout easier to reason about

## Guzzle GUI quick reference

| Step | What happens |
|---|---|
| Open file | Load C/C++ source into Monaco editor |
| Click function | Tree-sitter parses and identifies the function signature |
| Fuzz Wizard → Harness | AI generates the harness; you can edit before compiling |
| Fuzz Wizard → Compile | clang + ASan + libFuzzer; output goes to `.guzzle/fuzzer` |
| Fuzz Wizard → Running | Fuzzer runs; crashes appear in real time |
| Results → Gen PoC | Compiles reproducer, extracts ROP gadgets, calls AI for pwntools script |

All artifacts live in `.guzzle/` next to your source file:
```
.guzzle/
  fuzzer           # compiled fuzzer binary
  reproducer       # standalone crash reproducer
  corpus/          # fuzzer-generated test cases
  crashes/         # crash inputs
  harness.cpp      # the harness as compiled
  harness_cache.json  # cached AI-generated harnesses (keyed by file hash + function name)
```
