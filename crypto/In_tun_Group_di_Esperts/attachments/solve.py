#!/usr/bin/env python3
from pwn import *

io = remote(args.HOST, args.PORT, ssl=args.SSL)



io.sendlineafter(b"> ", b"1")
io.recvuntil(b"flag is ")
encrypted_flag = bytes.fromhex(io.recvuntil(b"> ").split()[0].decode())


def send_ciphertext(ciphertext):
    io.sendline(b"2")
    io.sendlineafter(b': ',ciphertext.hex().encode())
    result = io.recvuntil(b"> ")
    return result


def unpad(bytes_list):
    last_element = bytes_list[-1]
    if 0 < last_element < 17:
        # valid value for padding
        if all([True if el == last_element else False for el in bytes_list[-last_element:]]):
            return bytes_list[:-last_element]
        else:
            raise Exception("Invalid padding!")
    else:
        raise Exception("Invalid padding!")

iv1 = encrypted_flag[:16]
iv2 = encrypted_flag[16:32]
cc = encrypted_flag[32:]
blocks_ciphertext = [cc[i:i + 16] for i in range(0, len(cc), 16)]
flag = b""
for block_number in range(len(blocks_ciphertext)):
    block = b""

    for j in range(15, -1, -1):
        for i in range(2, 256):
            IV1 = list(iv1)
            IV2 = list(iv2)
            CC = list(blocks_ciphertext[block_number])
            delta = 16 - j
            for k in range(j + 1, 16):
                IV1[k] = IV1[k] ^ delta ^ block[k - (j + 1)]
            IV1[j] = IV1[j] ^ delta ^ i
            if b"Cemut? I no ai capit" not in send_ciphertext(bytes(IV1) + bytes(IV2) + bytes(CC)):
                block = i.to_bytes(1) + block
                break
            
        print(block)
    flag = flag + block
    
    iv1 = blocks_ciphertext[block_number]
    iv2 = block
try:
    print(bytes(unpad(list(flag))).decode())
except:
    print("Wrong")