# Mega secure [_snakeCTF 2024 Quals_]

**Category**: CRYPTO

## Description

My friend keeps bragging about how "mega secure" his new encryption system is, but is it really as secure as he thinks?

## Solution

In this challenge a public RSA key and an AES-CBC encrypted payload are provided. The payload contains the concatenated private key components in the following format:`len(p) | p | len(q) | q | len(dp) | dp | len(dq) | dq | len(u) | u`, where `p` and `q` are the prime factors of RSA modulus, `dp` and `dq` are the CRT exponents and `u` is the CRT coefficient.\
It's possible to interact with the server to decrypt any message encrypted with the given public RSA key. The decryption process relies on the encrypted payload containing the private key components that is given to the server.\
To get the flag a randomly generated message must be signed correctly. To do that, the secret `d` must be recovered.

The first thing to notice is that the server doesn't check if the encrypted payload received is correct. Exploiting this, a fault attack can be performed. In fact, randomly changing the value of `u` leaks information about the secret `q`. Once obtained, `d` can be computed to get the flag.\
Now consider changing the encrypted keys such that the server obtains $u' \neq u$ (to do this just randomly modify an encrypted block of `u`). There are two cases when decrypting a message $c = m^e \mod N$:

### 1. $m < q$

In this case the decryption of $c$ with $u'$ returns $m' = m$. Since $m < q$, it follows that $m'_q = m$, while for $m'_q$ it holds that $m \equiv m'_p \mod p$. Therefore, there exists $k$ such that $m = m'_p + k \cdot p$. Combining this observation it holds that $t = m'_p - m'_q = m'_p - m = m'_p - m'_p - k \cdot p = - k \cdot p$. But $t \mod p = 0$ and therefore $h = t \cdot u' = 0$. This implies that regardless of the value of $u',$ $h$ will have no effect on the outcome. For this reason the correct value is returned: $m' = h \cdot q + m'_q = 0 \cdot q + m'_q = m$.

### 2. $m \geq q$

In this case the decryption of $c$ with $u'$ returns $m' \neq m$. It holds that $m \equiv m'_p \mod p$ and $m \equiv m'_q \mod q$. Therefore, there exist $k_1$ and $k_2$ such that $m'_p = m - k_1 \cdot p$ and $m'_q = m - k_2 \cdot q$. Then $t = m'_p - m'_q = m - k_1 \cdot p - m + k_2 \cdot q = - k_1 \cdot p + k_2 \cdot q \equiv k_2 \cdot q \mod p$. Now $t \neq 0$ if and only if $k_2$ and $p$ are coprime. However, since the probability of $k_2$ and $p$ not being coprime is only $1 / p$, it is almost certain that they are coprime. So it holds that $h = t \cdot u' \mod p \neq 0$ and $m' = h \cdot q + m'_q \neq m$.

From being able to distinguish the two cases, it can be exploited to recover the secret key and obtain the flag. Below is a script that solves this challenge.

```python
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
```
