#!/usr/bin/env python3
from pwn import *
import multiprocessing as mp
from random import randrange
from copy import deepcopy
from forkaes import *
from AES.aes_utilities import *
from data import out_diff_for_tweak
import itertools
import time

CORES = 8
EXP = 3

HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
SSL = args.SSL

r = remote(HOST, PORT, ssl=SSL)

# getting plaintext / ciphertext couple and tweak
text = r.recvuntil(b">").decode().split("\n")
ref_plaintext = eval(text[2])
ref_tweak = eval(text[5])

ref_left_ciphertext = eval(text[8][6:])
ref_right_ciphertext = eval(text[9][7:])


"""
Given the i-th key in the key scheduling, it computes all the other keys
"""
def get_key_scheduling_from_intermediate_key(key, from_index, max):
    keys = [[0 for _ in range(16)] for i in range(max + 1)]

    for i in range(16):
        keys[from_index][i] = key[i]

    for i in range(from_index, 0, -1):
        keys[i - 1][12] = keys[i][12] ^ keys[i][8]
        keys[i - 1][13] = keys[i][13] ^ keys[i][9]
        keys[i - 1][14] = keys[i][14] ^ keys[i][10]
        keys[i - 1][15] = keys[i][15] ^ keys[i][11]

        keys[i - 1][8] = keys[i][8] ^ keys[i][4]
        keys[i - 1][9] = keys[i][9] ^ keys[i][5]
        keys[i - 1][10] = keys[i][10] ^ keys[i][6]
        keys[i - 1][11] = keys[i][11] ^ keys[i][7]

        keys[i - 1][4] = keys[i][4] ^ keys[i][0]
        keys[i - 1][5] = keys[i][5] ^ keys[i][1]
        keys[i - 1][6] = keys[i][6] ^ keys[i][2]
        keys[i - 1][7] = keys[i][7] ^ keys[i][3]

        temp = keys[i - 1][12]
        keys[i - 1][0] = SBOX[keys[i - 1][13]] ^ keys[i][0] ^ Rcon[i]
        keys[i - 1][1] = SBOX[keys[i - 1][14]] ^ keys[i][1]
        keys[i - 1][2] = SBOX[keys[i - 1][15]] ^ keys[i][2]
        keys[i - 1][3] = SBOX[temp] ^ keys[i][3]

    for i in range(from_index + 1, max + 1):
        temp = keys[i - 1][12]
        keys[i][0] = SBOX[keys[i - 1][13]] ^ keys[i - 1][0] ^ Rcon[i]
        keys[i][1] = SBOX[keys[i - 1][14]] ^ keys[i - 1][1]
        keys[i][2] = SBOX[keys[i - 1][15]] ^ keys[i - 1][2]
        keys[i][3] = SBOX[temp] ^ keys[i - 1][3]

        keys[i][4] = keys[i - 1][4] ^ keys[i][0]
        keys[i][5] = keys[i - 1][5] ^ keys[i][1]
        keys[i][6] = keys[i - 1][6] ^ keys[i][2]
        keys[i][7] = keys[i - 1][7] ^ keys[i][3]

        keys[i][8] = keys[i - 1][8] ^ keys[i][4]
        keys[i][9] = keys[i - 1][9] ^ keys[i][5]
        keys[i][10] = keys[i - 1][10] ^ keys[i][6]
        keys[i][11] = keys[i - 1][11] ^ keys[i][7]

        keys[i][12] = keys[i - 1][12] ^ keys[i][8]
        keys[i][13] = keys[i - 1][13] ^ keys[i][9]
        keys[i][14] = keys[i - 1][14] ^ keys[i][10]
        keys[i][15] = keys[i - 1][15] ^ keys[i][11]

    return keys


def get_sibling(ciphertext: list, tweak: list, side="left"):
    r.sendline(b"1")
    r.sendlineafter(b"ciphertext : ", ",".join([str(a) for a in ciphertext]).encode())
    r.sendlineafter(b"tweak : ", ",".join([str(a) for a in tweak]).encode())
    r.sendlineafter(b"): ", side.encode())
    result = eval(r.recvuntil(b">").decode().split("\n")[1])

    return result


def get_encrypted_flag():
    r.sendline(b"2")
    res = r.recvuntil(b"> ").strip().split()
    return res[0], res[1]


manager = mp.Manager()
key_bytes_possibilities_counter = manager.list(
    [
        manager.list([manager.list([0 for _ in range(256)]) for _ in range(16)]),
        manager.list([manager.list([0 for _ in range(256)]) for _ in range(16)]),
    ]
)


def attack_byte_thread(
    exp,
    index,
    possible_t1_value,
    possible_t2_value,
    tweak1,
    tweak2,
    column,
    byte_number,
    start_side,
):
    global key_bytes_possibilities_counter
    tested_t1 = [0 for _ in range(16)]
    tested_t2 = [0 for _ in range(16)]
    new_exp = 8 - exp

    for key in range(index * (2**new_exp), ((index + 1) * ((2**new_exp)))):
        # for key in range(0, 256):
        for i in range(16):
            tested_t1[i] = deepcopy(possible_t1_value[i])
            tested_t2[i] = deepcopy(possible_t2_value[i])

        key0 = (key & 0xFF) % 256

        tested_t1[4 * column + byte_number] ^= key0
        tested_t2[4 * column + byte_number] ^= key0

        tested_t1 = inverse_sub_bytes(tested_t1)
        tested_t2 = inverse_sub_bytes(tested_t2)

        tested_t1 = add_tweak(tested_t1, tweak1)
        tested_t2 = add_tweak(tested_t2, tweak2)

        tested_t1 = inverse_round(tested_t1)
        tested_t2 = inverse_round(tested_t2)

        risultato = 1

        for i in range(16):
            if tested_t1[i] ^ tested_t2[i] > 0:
                risultato = 0
                break

        if risultato == 1:
            key_bytes_possibilities_counter[start_side][4 * column + byte_number][
                key0
            ] += 1


def attack_byte(column, byte_number, start_side, key_number):
    # maybe we need to launch a thread every 0.100 ms
    tweak_difference = randrange(0, 256)
    tweak1 = [randrange(0, 256) for _ in range(8)] + [0] * 8
    tweak1 = inverse_shift_row(tweak1)
    tweak2 = deepcopy(tweak1)
    # putting the difference within tweak 2
    tweak2[4 * column + byte_number] = (
        tweak2[4 * column + byte_number] ^ tweak_difference
    )

    tweak1 = shift_rows(tweak1)[:8]
    tweak2 = shift_rows(tweak2)[:8]
    # the ciphertext we will use
    base_c = [randrange(0, 256) for _ in range(16)]

    possible_t1_values = [[0 for _ in range(16)] for _ in range(256)]
    possible_t2_values = [[0 for _ in range(16)] for _ in range(256)]

    for possible_c1_value in range(0, 256):
        c1_tilde = deepcopy(base_c)
        c1_tilde[4 * column + byte_number] = possible_c1_value

        c1_tilde = shift_rows(c1_tilde)
        c1_tilde = mix_columns(c1_tilde)
        c1_tilde = add_tweak(c1_tilde, tweak1)
        c1_tilde = get_sibling(c1_tilde, tweak1, side=start_side)
        c1_tilde = add_tweak(c1_tilde, tweak1)
        c1_tilde = inverse_mix_columns(c1_tilde)
        c1_tilde = inverse_shift_row(c1_tilde)

        for i in range(0, 16):
            possible_t1_values[possible_c1_value][i] = c1_tilde[i]

    for possible_c1_value in range(0, 256):
        c1_tilde = deepcopy(base_c)
        c1_tilde[4 * column + byte_number] = possible_c1_value

        c1_tilde = shift_rows(c1_tilde)
        c1_tilde = mix_columns(c1_tilde)
        c1_tilde = add_tweak(c1_tilde, tweak2)
        c1_tilde = get_sibling(c1_tilde, tweak2, side=start_side)
        c1_tilde = add_tweak(c1_tilde, tweak2)
        c1_tilde = inverse_mix_columns(c1_tilde)
        c1_tilde = inverse_shift_row(c1_tilde)

        for i in range(0, 16):
            possible_t2_values[possible_c1_value][i] = c1_tilde[i]

    print("DONE")

    # finding a correct couple in order to find the key byte
    indext1 = -1
    indext2 = -1

    for i in range(0, 256):
        for j in range(0, 256):
            indext1 = -1
            indext2 = -1

            result = 1
            for byte in range(0, 16):
                if byte != 4 * column + byte_number:
                    if possible_t1_values[i][byte] ^ possible_t2_values[j][byte] > 0:
                        result = 0
                        break

            if result == 1:
                result = 0
                for poss in range(0, 127):
                    if (
                        possible_t1_values[i][4 * column + byte_number]
                        ^ possible_t2_values[j][4 * column + byte_number]
                        == out_diff_for_tweak[tweak_difference - 1][poss]
                    ):
                        result = 1
                        break

                if result == 1:
                    indext1 = i
                    indext2 = j
                    break

    start = 0 if start_side == "right" else 1

 
    procs = []
    if indext1 > -1 and indext2 > -1:
        for bb in range(0, CORES):
            proc = mp.Process(
                target=attack_byte_thread,
                args=(
                    EXP,
                    bb,
                    possible_t1_values[indext1],
                    possible_t2_values[indext2],
                    tweak1,
                    tweak2,
                    column,
                    byte_number,
                    start,
                ),
            )
            procs.append(proc)
            proc.start()

    # complete the processes
    for proc in procs:
        proc.join()


def compute_possibilities_for_key(side):
    global key_bytes_possibilities_counter
    key_possibilities_counter_per_side = [
        key_bytes_possibilities_counter[side][0],
        key_bytes_possibilities_counter[side][5],
        key_bytes_possibilities_counter[side][10],
        key_bytes_possibilities_counter[side][15],
        key_bytes_possibilities_counter[side][4],
        key_bytes_possibilities_counter[side][9],
        key_bytes_possibilities_counter[side][14],
        key_bytes_possibilities_counter[side][3],
    ]
    number_of_keys = 0

    possibilities_for_byte = [0 for _ in range(8)]
    max_for_byte = [0 for _ in range(8)]

    values_for_byte = [[] for _ in range(8)]

    for j in range(0, 8):
        counter = 0
        max = 0
        for i in range(0, 256):
            if key_possibilities_counter_per_side[j][i] > max:
                max = key_possibilities_counter_per_side[j][i]

        if max > 0:
            for i in range(0, 256):
                if key_possibilities_counter_per_side[j][i] == max:
                    counter += 1
                    values_for_byte[j].append(i)

        possibilities_for_byte[j] = counter
        max_for_byte[j] = max

    column_possibilities = [0, 0]

    for i in range(2):
        column_possibilities[i] = (
            possibilities_for_byte[0 + 4 * i]
            * possibilities_for_byte[1 + 4 * i]
            * possibilities_for_byte[2 + 4 * i]
            * possibilities_for_byte[3 + 4 * i]
        )

    return (values_for_byte, column_possibilities[0] * column_possibilities[1])


if __name__ == "__main__":

    #### MAIN ####
    print("[+] Finding first column possibilities\n")
    attack_byte(0, 0, "right", 7)
    attack_byte(1, 1, "right", 7)
    attack_byte(2, 2, "right", 7)
    attack_byte(3, 3, "right", 7)

    print("[+] Finding second column possibilities\n")
    attack_byte(1, 0, "right", 7)
    attack_byte(2, 1, "right", 7)
    attack_byte(3, 2, "right", 7)
    attack_byte(0, 3, "right", 7)

    print("[+] Finding first column possibilities\n")
    attack_byte(0, 0, "left", 9)
    attack_byte(1, 1, "left", 9)
    attack_byte(2, 2, "left", 9)
    attack_byte(3, 3, "left", 9)

    print("[+] Finding second column possibilities\n")
    attack_byte(1, 0, "left", 9)
    attack_byte(2, 1, "left", 9)
    attack_byte(3, 2, "left", 9)
    attack_byte(0, 3, "left", 9)

    # compute the number of possible keys
    key_values_for_byte_7, counter_possible_keys_7 = compute_possibilities_for_key(0)
    key_values_for_byte_9, counter_possible_keys_9 = compute_possibilities_for_key(1)

    print(counter_possible_keys_7)
    print(counter_possible_keys_9)

    key_values_for_byte = key_values_for_byte_7 + key_values_for_byte_9
    list_of_possible_keys = list(itertools.product(*key_values_for_byte))

    print()
    for kk in list_of_possible_keys:
        kkk = list(kk)
        k7 = [0] * 16
        k8 = [0] * 16
        k9 = [0] * 16

        k7[0] = kkk[0]
        k7[5] = kkk[1]
        k7[10] = kkk[2]
        k7[15] = kkk[3]
        k7[4] = kkk[4]
        k7[9] = kkk[5]
        k7[14] = kkk[6]
        k7[3] = kkk[7]

        k9[0] = kkk[8]
        k9[5] = kkk[9]
        k9[10] = kkk[10]
        k9[15] = kkk[11]
        k9[4] = kkk[12]
        k9[9] = kkk[13]
        k9[14] = kkk[14]
        k9[3] = kkk[15]

       
        k7 = shift_rows(k7)
        k9 = shift_rows(k9)

        

        k7 = mix_columns(k7)
        k9 = mix_columns(k9)

        # get second column of k8
        k8[4] = k9[4] ^ k9[0]
        k8[5] = k9[5] ^ k9[1]
        k8[6] = k9[6] ^ k9[2]
        k8[7] = k9[7] ^ k9[3]

        # get first column of k8
        k8[0] = k7[4] ^ k8[4]
        k8[1] = k7[5] ^ k8[5]
        k8[2] = k7[6] ^ k8[6]
        k8[3] = k7[7] ^ k8[7]

        # get 4th column of k7
        k7[13] = INV_SBOX[k8[0] ^ k7[0] ^ Rcon[8]]
        k7[14] = INV_SBOX[k8[1] ^ k7[1]]
        k7[15] = INV_SBOX[k8[2] ^ k7[2]]
        k7[12] = INV_SBOX[k8[3] ^ k7[3]]

        # get 4th column of k8
        k8[13] = INV_SBOX[k9[0] ^ k8[0] ^ Rcon[9]]
        k8[14] = INV_SBOX[k9[1] ^ k8[1]]
        k8[15] = INV_SBOX[k9[2] ^ k8[2]]
        k8[12] = INV_SBOX[k9[3] ^ k8[3]]

        # get third column of k8
        k8[8] = k8[12] ^ k7[12]
        k8[9] = k8[13] ^ k7[13]
        k8[10] = k8[14] ^ k7[14]
        k8[11] = k8[15] ^ k7[15]

        original_key = k8
        keys = get_key_scheduling_from_intermediate_key(original_key, 8, 9)
        k0 = keys[0]
        x, y = encrypt(ref_plaintext, k0, ref_tweak)
        if x == ref_left_ciphertext and y == ref_right_ciphertext:
           
            true_key = bytes(k0)
            iv, ct = get_encrypted_flag()
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            from base64 import b64decode

            iv = b64decode(iv.decode())
            ct = b64decode(ct.decode())
            cipher = AES.new(true_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)

            print(pt.decode())
            break
