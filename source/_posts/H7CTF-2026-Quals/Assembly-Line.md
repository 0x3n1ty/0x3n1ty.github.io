---
title: Assembly Line
date: 2026-09-30
tags:
  - misc
  - ctf-writeups
---

![chall](../writings/H7CTF-2026-Quals/Assembly-Line/1.png)

After starting the instance, We are given an interactive server to connect using netcat.

![nc](../writings/H7CTF-2026-Quals/Assembly-Line/2.png)

We need to answer 250 questions and each question should be answered within 2 seconds.

the questions are formatted like

[x/250] Operation to perform: input

Even though they are basic mathematical and encoding/decoding problems like Base64 etc.. It is still impossible to answer manually.

So I asked deepseek to *write a script to interact with the server to answer the questions based on the operation and input given which are separated by a semicolon.*

```python
import socket, re, time, base64, codecs, binascii, hashlib, json, urllib.parse

HOST = 'pwn.h7tex.com'
PORT = 43856

s = socket.create_connection((HOST, PORT))
f = s.makefile('rwb', buffering=0)

def recvline():
    return f.readline().decode(errors='replace').rstrip('\n')

def sendline(x):
    f.write((str(x) + '\n').encode())

def nums(data):
    return [int(x) for x in re.split(r'[,\s]+', data.strip()) if x]

def solve(op, data):
    op = op.lower()

    # ---- string ops ----
    if op == 'reverse':      return data[::-1]
    if op == 'upper':        return data.upper()
    if op == 'lower':        return data.lower()
    if op == 'len':          return len(data)
    if op == 'count':        return len(data)  # fallback; see note below
    if op == 'swapcase':     return data.swapcase()
    if op == 'title':        return data.title()

    # ---- number ops ----
    if op == 'sum':          return sum(nums(data))
    if op == 'max':          return max(nums(data))
    if op == 'min':          return min(nums(data))
    if op == 'avg' or op == 'mean': return sum(nums(data)) // len(nums(data))
    if op == 'sort':         return ','.join(str(n) for n in sorted(nums(data)))
    if op == 'eval':         return eval(data)

    # ---- encodings ----
    if op == 'b64' or op == 'base64':
        # decode if it looks like b64 of text, else encode
        try:
            return base64.b64decode(data).decode()
        except Exception:
            return base64.b64encode(data.encode()).decode()
    if op == 'unb64' or op == 'b64decode':
        return base64.b64decode(data).decode()
    if op == 'hex':
        try:
            return bytes.fromhex(data).decode()
        except Exception:
            return data.encode().hex()
    if op == 'unhex':
        return bytes.fromhex(data).decode()
    if op == 'rot13':        return codecs.encode(data, 'rot13')
    if op == 'url' or op == 'urldecode':
        return urllib.parse.unquote(data)
    if op == 'urlencode':
        return urllib.parse.quote(data)
    if op == 'bin' or op == 'binary':
        return ''.join(f'{ord(c):08b}' for c in data)
    if op == 'ord':
        return ' '.join(str(ord(c)) for c in data)
    if op == 'chr':
        return ''.join(chr(int(x)) for x in data.split())
    if op == 'md5':          return hashlib.md5(data.encode()).hexdigest()
    if op == 'sha1':         return hashlib.sha1(data.encode()).hexdigest()
    if op == 'sha256':       return hashlib.sha256(data.encode()).hexdigest()

    # ---- math ----
    if op == 'factorial':    import math; return math.factorial(int(data))
    if op == 'sqrt':         import math; return int(math.isqrt(int(data)))
    if op == 'pow':          a,b = nums(data); return a**b
    if op == 'mod':          a,b = nums(data); return a % b

    # ---- fallback: don't crash, log it ----
    print(f"!!! UNKNOWN OP: {op} | data={data}")
    return data  # send it back unchanged just to keep going

# banner
while True:
    line = recvline()
    print(line)
    if 'go.' in line:
        break

for i in range(250):
    line = recvline()
    print(line)
    m = re.match(r'\[\d+/\d+\]\s+(\w+):\s+(.+)', line)
    if not m:
        print("Unparsed:", line)
        break
    op, data = m.group(1), m.group(2)
    ans = solve(op, data)
    print(f"  -> {ans}")
    sendline(ans)

time.sleep(1)
print(s.recv(65536).decode(errors='replace'))

```

By running the script, I got the flag :)


![running script](../writings/H7CTF-2026-Quals/Assembly-Line/3.png)

![flag](../writings/H7CTF-2026-Quals/Assembly-Line/4.png)

