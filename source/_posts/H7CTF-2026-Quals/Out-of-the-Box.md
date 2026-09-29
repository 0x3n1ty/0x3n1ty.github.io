---
title: Out of the Box
date: 2026-09-30
tags:
  - misc
  - python
  - sandbox
  - eval
  - ctf-writeups
---

![chall](../writings/H7CTF-2026-Quals/Out-of-the-Box/1.png)

We need to connect to the server using netcat to solve this challenge.

We are given a Python script `jail.py` in the `sandboxed.zip` file that reads one expression per line, checks it against a denylist, and if it passes, evaluates it with `eval(src, {"__builtins__": {}}, {})`. The flag is at `/flag.txt`.

```python
#!/usr/bin/env python3
# "Sandboxed" - a locked-down Python expression evaluator.
# You may send one expression per line. It is checked against a denylist and then eval'd with an
# empty builtins namespace. The flag is in /flag.txt on the server. Good luck reading it.
import sys

BANNED = [
    "import", "eval", "exec", "compile", "system", "popen", "subprocess",
    "open", "input", "breakpoint", "help", "pickle", "marshal", "os", "sys",
    "flag", "print", "write", "\\", "chr", "getattr", "setattr", "vars", "dir",
]
MAXLEN = 400

def jailed(src: str) -> str:
    src = src.strip()
    if not src:
        return ""
    if len(src) > MAXLEN:
        return "error: too long"
    low = src.lower()
    for b in BANNED:
        if b in low:
            return f"denied: '{b}' is not allowed"
    try:
        return repr(eval(src, {"__builtins__": {}}, {}))
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"

def main():
    print("== sandboxed evaluator ==")
    print("one expression per line. builtins are empty. the flag is /flag.txt.")
    sys.stdout.flush()
    for line in sys.stdin:
        out = jailed(line)
        if out:
            print(out)
        sys.stdout.flush()

if __name__ == "__main__":
    main()
```

The `eval` call uses an empty builtins namespace. So inside our expression we have no built-in functions: no `open`, no `__import__`, no `getattr`, no `eval`, nothing. We only have literals (strings, numbers, tuples, lists, dicts), operators like `+` and `[]`, and attribute access with `.`.

The denylist is a list of strings:

```python
BANNED = [
    "import", "eval", "exec", "compile", "system", "popen", "subprocess",
    "open", "input", "breakpoint", "help", "pickle", "marshal", "os", "sys",
    "flag", "print", "write", "\\", "chr", "getattr", "setattr", "vars", "dir",
]
```

The check lowercases the whole source and rejects it if any banned string appears anywhere in it as a contiguous substring. This is the first weakness: it only catches exact character sequences. If we build a banned word at runtime without typing it contiguously, the check passes. For example `'op'+'en'` evaluates to `"open"` but does not contain the substring `"open"` in the source. Same for `'/fla'+'g.txt'` which evaluates to `"/flag.txt"` but does not contain `"flag"` as a contiguous substring.

The second weakness is more fundamental. Clearing `__builtins__` in the eval namespace only affects the eval itself. It does not remove Python's object model. Every object still has `__class__`, `__bases__`, `__subclasses__`, `__init__`, `__globals__`, and so on. These are not built-in functions, they are language features. We can use them to walk from a simple literal all the way to the real builtins stored in other modules.

We start with an empty tuple: `()`. It has `__class__`, which is the `tuple` class. `tuple.__bases__` is `(<class 'object'>,)`. So `().__class__.__bases__[0]` is `object`. The `object` class has a method `__subclasses__()` which returns a list of every class that directly inherits from `object` and is currently alive in the process. This list includes hundreds of classes from all imported modules.

Some of these classes are written in Python, some are C extension types. Python classes have `__init__` methods that are Python function objects. Python function objects have a `__globals__` attribute, which is the global namespace dictionary of the module where the function was defined. That dictionary always contains a `__builtins__` entry, and in a normal module this is the real builtins dictionary. That is where `open` lives.

So the plan is: find a Python class in `object.__subclasses__()`, access its `__init__`, get its `__globals__`, get `__builtins__` from there, and use `open` to read the flag. We use string concatenation for `"open"` and `"/flag.txt"` to avoid the denylist.

A reliable class to use is `Quitter`, defined in `_sitebuiltins.py` and imported by `site.py` at startup. Its name contains no banned substring, it is a direct subclass of `object`, and its `__init__` is a Python function. We find it with a list comprehension:

```python
[c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__=='Quitter']
```

Then we take `[0]`, access `.__init__.__globals__['__builtins__']`, and get `open` with `['op'+'en']`. We call it with `('/fla'+'g.txt')` and call `.read()` on the result.

## Final payload:

```python
[c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__=='Quitter'][0].__init__.__globals__['__builtins__']['op'+'en']('/fla'+'g.txt').read()
```

![flag](../writings/H7CTF-2026-Quals/Out-of-the-Box/2.png)

Got the flag :)

## What if?

If the sandbox is started with `python -S`, the `site` module is not imported, so `_sitebuiltins` is not imported, and `Quitter` does not exist. The list comprehension returns an empty list and `[0]` raises `IndexError`. The same can happen if `warnings` is missing and `catch_warnings` is not there either. To handle this, we can search for any Python class instead of a specific one. A Python function has `__class__.__name__` equal to `'function'`, while C extension methods are `wrapper_descriptor` or `slot wrapper`. So this filter finds the first Python class:

```python
[c for c in ().__class__.__bases__[0].__subclasses__() if c.__init__.__class__.__name__=='function'][0]
```

The rest is the same:

```python
[c for c in ().__class__.__bases__[0].__subclasses__() if c.__init__.__class__.__name__=='function'][0].__init__.__globals__['__builtins__']['op'+'en']('/fla'+'g.txt').read()
```

This works even with `-S` because Python always defines some Python classes as part of the import system, like `FileLoader` from `_frozen_importlib_external`, which is always imported.

The two things that make this work are: `__globals__` on a Python function gives us access to the real builtins of its defining module, which bypasses the empty builtins in the eval context; and string concatenation lets us build `"open"` and `"/flag.txt"` at runtime without typing them contiguously in the source, which bypasses the denylist. The same idea is used in Jinja2 SSTI with `cycler.__init__.__globals__.os.popen(...)`. Here we do not have a template engine, so we start from `()` and use `__subclasses__()` to find a class with `__globals__`.
