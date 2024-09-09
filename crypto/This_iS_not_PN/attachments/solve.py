#!/usr/bin/env python3
import sys

output_dir = sys.argv[1]


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def multiple_byte_xor(lista):
    res = lista[0]
    for i in range(1, len(lista)):
        res = byte_xor(res, lista[i])

    return res


with open(f"{output_dir}/challenge.txt", "r") as f:
    c5 = f.readline()[3:]
    t1_5 = eval(f.readline()[4:])
    t2_5 = eval(f.readline()[4:])
    c6 = f.readline()[3:]
    t1_6 = eval(f.readline()[4:])
    t2_6 = eval(f.readline()[4:])

    flag = b""
    # con 5 round
    c = bytes.fromhex(c5)
    t1 = [bytes.fromhex(el) for el in t1_5]
    t2 = [bytes.fromhex(el) for el in t2_5]

    A = c[:16]
    B = c[16:]

    B2 = multiple_byte_xor([t2[3], t2[4], A, t1[4]])
    B3 = multiple_byte_xor([B2, t2[2], t1[3], B, A, t2[4]])
    p2 = multiple_byte_xor([t2[1], t1[2], B2, t2[0], t1[1]])

    flag += p2

    # con 6 round
    c = bytes.fromhex(c6)
    t1 = [bytes.fromhex(el) for el in t1_6]
    t2 = [bytes.fromhex(el) for el in t2_6]

    A = c[:16]
    B = c[16:]

    B2 = multiple_byte_xor([t2[4], t2[5], A, t1[5]])
    B3 = multiple_byte_xor([B2, t2[3], t1[4], B, A, t2[5]])
    B5 = multiple_byte_xor([t2[2], t1[3], B2, t2[1], t1[2]])
    p1 = multiple_byte_xor([B5, t1[0]])

    flag = p1 + flag

    print(flag.decode())
