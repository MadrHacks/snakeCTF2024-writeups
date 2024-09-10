#!/usr/bin/env python3
import sys

from mpmath.ctx_mp_python import return_mpc


def convert_block(block):
    # the 10th line of each block is unique, easier to script
    bibbia = {'330003003003000000300003000003000000030000000000000000000000000000000000000': '0',
              '330030303033003000003000003030000000000000000000000000000000000000000000000': '1',
              '300330300000330030000000000000000000003000000000000000000000000000000000000': '2',
              '330033333003000000000300000000000000000000000000000000000000000000000000000': '3',
              '300000330030303000300300300333000000000000000000000000000000000000000000000': '4',
              '330030030030030333030030000000000300300330000030000000000000000000000000000': '5',
              '330033333003000000030003030000030003303300300300000000000000000000000000000': '6',
              '330300330030003300000030000000000000000000000000000000000000000000000000000': '7',
              '330033300000000030000000300000033300003000000000000000000000000000000000000': '8',
              '330003300300000000333000000000000000000000000000000000000000000000000000000': '9',
              '333333330030000333003003003030303003030000000000000000000000000000000000000': 'a',
              '330030003303030000300033300300000000000000000000000000000000000000000000000': 'b',
              '333003330003003003000000000000000000000000000000000000000000000000000000000': 'c',
              '300003330003330000000003000333300300000000000000000000000000000000000000000': 'd',
              '330030000030333000003003000000300000000000000000000000000000000000000000000': 'e',
              '333003000300000000000000030330030303030300000000000000000000000000000000000': 'f',
              '000000000030000000000000000000000000000000000000000000000000000000000000000': '&',
              '333333333333333003000030003333333333333333333333333333333333333333333333333': 'S'}

    l = ''.join(map(str, [col[10] for col in block]))

    if l not in bibbia:
        return 'R'

    return bibbia[l]



def extract_blocks(matrix):
    blocks = []
    print(matrix[0])
    for i in range(0, len(matrix[0]) // 40):
        for j in range(len(matrix) // 75):
            b = []
            for r in range(j * 75, (j+1) * 75):
                b.append(matrix[r][i * 40:(i + 1) * 40])
            blocks.append(b)


    return blocks


def parse_file(c):
    h = int.from_bytes(c.read(2))
    w = int.from_bytes(c.read(2))
    steps = int.from_bytes(c.read(4))

    m = []
    for i in range(h):
        r = c.read(w).replace(b"\x53", b"0").replace(b"\x35", b"1").replace(b"\x20", b"2").replace(b"\x73", b"3").decode()
        m.append([int(x) for x in r])

    return h//75, w//40, extract_blocks(m)


dir = './challenge'

with open(f"{dir}/circuit", "rb") as f:
    h, w, blocks = (parse_file(f))

    for x in range(w):
        for y in range(h):
            index = y * w + x
            print(f'{convert_block(blocks[index])}', end='')
        print()

