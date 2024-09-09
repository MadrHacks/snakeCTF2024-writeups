# TLN (Thread-Local Notes) [_snakeCTF 2024 Quals_]

**Category**: pwn

## Description

Yet another notes challenge...

No heap this time I promise 😉

## Solution

The provided binary is a simple note-taking application that allows the user to store (but not to retrieve) 7-bytes null terminated notes at a given index.

Due to the lack of validation on the index, this easily leads to a relative write primitive starting from the `notes` thread-local variable, declared as `static thread_local item_t notes[SIZE];`

The main objective of the challenge is in fact to gain code execution starting from this primitive.

### Leaking `libc`

Both the challenge binary and the docker's `libc` (2.40) are Full RELRO, thus an attack on either of their GOT isn't feasible.

FILE* struct related shenanigans are also not possible, as no FILE* related function is called since the input/output is done directly through the `read` and `write` syscalls.

An interesting fact is that the `notes` variable is 0x800 bytes before the main thread's `tcbhead_t` struct (pointed by FS), which contains interesting security-related fields such as `stack_guard` and `pointer_guard`. It is also of relevance that in the provider Docker setup the `libc` is right after the TCB memory area.

![TCB, notes, and `libc` are all relative to each other](images/notes_fs_libc_position.png)

Given the control on the `pointer_guard` field, and the ability to alter `libc`'s memory space, a spicy target are the exit handlers, located at the [`initial`](https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/stdlib/cxa_atexit.c#L73) symbol.

Looking at the source of [`__run_exit_handlers`](https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/stdlib/exit.c#L36) (the function that calls the exit handlers), it is possible to see that the handlers' list is iterated in reverse order for `idx` times, and each entry's functor is decoded through the [`PTR_DEMANGLE`](https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h#L31) macro, which boils down to a `xor` with the `pointer_guard` value and a rotation.

An entry in the exit handlers list is a struct built as follows:

```c
struct exit_function
  {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union
      {
	void (*at) (void);
	struct
	  {
	    void (*fn) (int status, void *arg);
	    void *arg;
	  } on;
	struct
	  {
	    void (*fn) (void *arg, int status);
	    void *arg;
	    void *dso_handle;
	  } cxa;
      } func;
  };
```

The `flavor` field is used to differentiate between the different types of exit handlers, and the `func` union contains the actual function pointer and its arguments.

Given that the value of status can be changed by re-calling exit inside the handler list (as seen in the comments of `__run_exit_handlers`), using the `on` and `cxa` flavours it is possible to either control `edi` and `rsi` or `rdi` and `esi`. A check with `gdb` will also reveal that during the execution of a `on` handler, the value of `rdx` is 1.

This can be used to leak `libc` by setting up a chain of exit handlers that set status to 1 and call 1-byte `write`s on a GOT address. Of course, this also requires the `pointer_guard` value to be zeroed out, which can be done with the provided primitive.

### Getting code execution

Knowing the address of `libc`, popping a shell is as easy as setting up a `cxa` handler that calls `system` with `arg` set to the address of `/bin/sh`.

Special care must be taken to manually set the last byte of the address since the primitive only allows 7-byte writes, but this can be easily solved by adding a `read` call that reads into the last byte.

### [Final exploit](attachments/solve.py)
