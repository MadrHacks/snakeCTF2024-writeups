# Annuitka [_snakeCTF 2024 Quals_]

**Category**: reversing

## Description

Python is slow but simple. C is fast but complex.

What if you could have the best of both worlds?

To run the chall use this Dockerfile

```Dockerfile
FROM python:3.12.5-bullseye

RUN pip3 install --no-cache-dir cryptography
COPY chall /chall

ENTRYPOINT ["/chall"]
```

## Solution

### Step 1: Analysis

Trying to statically analyse the binary will prove to be harder than usual, as the binary is compiled with `nuitka`.
Dynamic analysis instead will prove more effective, running the program with `strace` will show this:

```
openat(AT_FDCWD, "/usr/local/lib/libpython3.12.so.1.0", O_RDONLY|O_CLOEXEC) = 3
...
openat(AT_FDCWD, "/usr/local/lib/python3.12/site-packages/cryptography/__pycache__/__init__.cpython-312.pyc", O_RDONLY|O_CLOEXEC) = 3
```

Which means that the python libraries are loaded from the user's system and not from the binary itself.
This means that code can be injected into the binary by modifying the python libraries.

### Step 2: Injecting code

Modifying the `__init__.py` file in the cryptography package to inject code will allow
running arbitrary code in the binary.
Probably the main function uses `input()` to get the user input, so it can be overwritten.

The following code will print the main module's directory:

```python
def inject(*x,**y):
    import __main__
    print(dir(__main__))
import builtins
builtins.input=inject

# output: ['Cipher', '__annotations__', '__builtins__', '__cached__', '__compiled__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', 'algorithms', 'base64', 'check', 'decrypt', 'default_backend', 'encrypt', 'flag', 'key', 'main', 'modes', 'pad', 'padding', 'sha256', 'unpad', 'xor']

```

Just printing the `flag` variable will result in random bytes,
but the `decrypt` function can help in recovering the flag:

```python
def inject(*x,**y):
    import __main__
    print(__main__.decrypt(__main__.key,__main__.flag))
import builtins
builtins.input=inject
```

Running the binary will give the flag.
