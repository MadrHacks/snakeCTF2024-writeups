# Guessing Pro [_snakeCTF 2024 Quals_]

**Category**: pwn

## Description

The title says "Pro", but this is a baby challenge.
Everybody likes guessing after all.

## Solution

This is a baby-level heap challenge that has a double free vulnerability, which
allows an attacker to get two references to the same chunk in different
variables.

A menu with few options is shown:

1. Take a guess
2. Confirm guess
3. Delete guess
4. Generate new value
5. Exit

By inspecting the binary, it can be seen that if "Delete guess" is chosen, a
`free` is executed without any check, so here lies the most straightforward way
to exploit the binary. Moreover, the `libc` used by the binary is version 2.27,
which is vulnerable to double free attacks.

The function `profit`, if called, prints the flag, and this happens if the user
is able to "guess" a value that gets randomly generated.

The random value gets allocated on the heap with a `malloc(50)`, but 50 is also
the same size that gets allocated to store the current guess. So that means that
the random value and the guess end up in the same heap bin.

With this knowledge, the following steps allow to win the guessing game:

1. Take a guess, allocating a chunk that will be freed
2. Delete the guess twice
3. Generate a new value, so the chunk that was freed twice gets re-allocated
4. Take a new guess, and since `malloc` is called, the input is actually being
   written in the same chunk where the random value was stored
5. Confirm the guess. At this point, the pointers to the guess and random value
   are pointing to the same address, so the equality check passes and `profit`
   gets called
