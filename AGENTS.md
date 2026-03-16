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

### 6. Analyse the crash

```bash
# Extract ROP gadgets
# macOS (Mach-O):
r2 -q -c "aaa;/R;q" reproducer
# Linux (ELF):
ROPgadget --binary reproducer --rop --nosys | head -200
# or: ropper -f reproducer
```

Use the gadgets + crash input to write a pwntools exploit scaffold:

```python
from pwn import *
p = process(['./reproducer', 'crash_file'])
# ... cyclic, offset finding, ROP chain
```

## Tips for agents

- **Start simple**: fuzz one function at a time, not the whole binary
- **Check for companion headers**: if fuzzing `msgparse.c`, include `msgparse.h` in the harness for type definitions
- **Seed the corpus**: put small valid inputs in `corpus/` before running — the fuzzer explores much faster
- **ASLR**: disable for reliable addresses: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
- **Crash triage**: `AddressSanitizer: heap-buffer-overflow` and `stack-buffer-overflow` are the most exploitable; `SEGV on unknown address 0x0` is usually just a null deref
- **The PoC script needs manual tuning**: offsets and libc addresses are build/system-specific; treat the generated script as scaffolding, not a finished exploit

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
