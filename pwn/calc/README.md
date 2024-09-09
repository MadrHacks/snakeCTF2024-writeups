# calc.exe [_snakeCTF 2024 Quals_]

**Category**: pwn

## Description

What's this `calc.exe` everyone is talking about?

## Solution

`calc.exe` is a simple console calculator-like 32-bit app for Windows that allows a user to do basic operations and store up to 28 results in memory.

The application is run under wine, which doesn't provide ASLR, thus all the stack, executable and `.DLLs` addresses are known and constant.

The main vulnerability is a weak bound check when the application asks the user for the index of where to store the result.

The location is computed as `stored_results[abs(idx - 1) % 28]`, which looks safe, however using an index such as `-2147483647` will result in `abs` (ran with `-2147483647 - 1 = -2147483648`) returning `-2147483648`, as there is no representation for the integer minimum due to how two's complement works. Plugging that inside the modulo operation (which is defined such that `(x / y) * y + x % y == x`, and may give a negative result), `-2147483648 % 28`, will result in `-16`, thus giving an out-of-bounds 4-byte write.

### SEH

An important thing to note is that the application uses Windows' Structured Exception Handling (SEH) to handle invalid operations such as divisions by zero or invalid operators.

[Microsoft's official documentation on it](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170) offers a great explanation, but in short SEH can be thought of as some kind of local signal handlers (as things like Linux's `SIGSEGV` or `SIGFPE` get represented as exceptions in Windows).

Most applications use the `_except_handler3` as the actual SEH handler (`_EH3_EXCEPTION_REGISTRATION.ExceptionHandler`) and rely on the compiler to produce a table of valid exception handlers (`ScopeTable`) and to set `TryLevel` (which is used as an index to `ScopeTable`) on each `try` block.

```c
struct CPPEH_RECORD
{
    DWORD old_esp;
    EXCEPTION_POINTERS *exc_ptr;
    struct _EH3_EXCEPTION_REGISTRATION registration;
};

struct _EH3_EXCEPTION_REGISTRATION
{
    struct _EH3_EXCEPTION_REGISTRATION *Next;
    PVOID ExceptionHandler;
    PSCOPETABLE_ENTRY ScopeTable;
    DWORD TryLevel;
};

struct _SCOPETABLE_ENTRY
{
    DWORD EnclosingLevel;
    PVOID FilterFunc;
    PVOID HandlerFunc;
};
```

It is possible to locate a `CPPEH_RECORD` structure, as defined above, inside the `do_calc` function at `ebp - 0x24`.

As nested `try` blocks are allowed, the `TryLevel` is used as an index to the `ScopeTable` array, which is defined globally in a read-only section and contains entries for each `catch` block and its relative filter inside the application.

A brief explanation of `_except_handler3` is that each time the application enters a `try` block (identified by the compiler setting the `TryLevel` field to point to the correct `ScopeTable` entry) and an exception happens, the filter function gets called and determines, based on its return value, whether:

- the relative handler should be executed (`EXCEPTION_EXECUTE_HANDLER`)
- the exception should be passed to the previous level, defined in the `EnclosingLevel` field (`EXCEPTION_CONTINUE_SEARCH`)
- execution should be continued normally (eventually retrying the faulting instruction, `EXCEPTION_CONTINUE_EXECUTION`)

When a return value of `EXCEPTION_CONTINUE_EXECUTION` happens, and `TryLevel` is not `-1`, the filter function of `ScopeTable[EnclosingLevel]` is called, and the process repeats.

A more thorough explanation of the internals of this whole process can be found [here](https://www-user.tu-chemnitz.de/~heha/hsn/chm/Win32SEH.chm/)

### Exploitation

The exception handler of the function containing the out-of-bounds write is composed of a filter, which sets a message to be printed, and a handler, which zeroes the targeted index and prints the message using `system("echo " message)`.

Some observations:

- The buffer containing the message is located right before a copy of the stored results (which is created when printing them)
- When an unexpected exception (that is, not a division by zero or an invalid operator) happens, the message fits the buffer exactly, not allowing for a null byte to be added

If an attacker were able to cause an unexpected exception, they could execute arbitrary commands by writing ` && command` to the results array.

By carefully crafting a scope table (possibly on the result array itself) and setting an invalid address as the handler, the application will try to execute it and cause a 0xc0000005 (Access Violation) exception. Now, if a `EnclosingLevel` is specified, the `ScopeTable[EnclosingLevel]` block will be run with the Access Violation exception.

If that block's filter is set to the calculator's filter, it will cause an unexpected exception, and the message will be _strcpy-ed_. That code path returns `EXCEPTION_CONTINUE_SEARCH`, thus an additional level needs to be specified, with a `FilterFunc` that returns `EXCEPTION_EXECUTE_HANDLER` and a `HandlerFunc` set to the calculator's handler.

Now, if the attacker set things right, an arbitrary command may be run, such as `type flag`, which will print the flag.

The full exploit can be found [here](attachments/solve.py)
