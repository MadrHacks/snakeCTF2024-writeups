#!/usr/bin/env python3

from Crypto.Util.number import isPrime, bytes_to_long as btl, long_to_bytes as ltb
from pwn import *

r = remote(HOST, PORT)


def decrypt_msg(msg, sk):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', msg)
    r.sendlineafter(b': ', sk)
    return r.recvline(False).decode()


def get_flag(n, d):
    r.sendlineafter(b'> ', b'2')
    r.recvuntil(b'Message: ')
    m = int(r.recvline(False).decode())
    s = pow(m, d, n)
    r.sendlineafter(b': ', str(s).encode())
    r.recvline()
    return r.recvline(False)


if __name__ == "__main__":
    # receiving public keys and encrypted secret keys
    r.recvuntil(b'n: ')
    n = int(r.recvline(False).decode())
    r.recvuntil(b'e: ')
    e = int(r.recvline(False).decode())
    r.recvuntil(b'sk: ')
    sk = ltb(int(r.recvline(False).decode()))

    iv = sk[:16]
    sk = sk[16:]

    # randomly modify second-last block, so the server will obtain u' != u
    blocks = [sk[i:i + 16] for i in range(0, len(sk), 16)]
    blocks[len(blocks) - 1] = os.urandom(16)
    new_sk = btl(iv + b''.join(b for b in blocks))

    # start finding 1 bit of q per request
    q = 0
    for i in range(1024, -1, -1):
        m = q + 2 ** i
        c = pow(m, e, n)
        res = decrypt_msg(str(c).encode(), str(new_sk).encode())
        if 'Message received' == res:
            q += 2 ** i

    q += 1
    assert (isPrime(q))

    # now with q we can compute d and sign the message
    p = n // q
    d = pow(e, -1, (p - 1) * (q - 1))

    print(get_flag(n, d))
