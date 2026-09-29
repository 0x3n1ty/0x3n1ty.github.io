---
title: WorldOutter
date: 2026-09-30
tags:
  - ctf-writeups
  - web
  - git-dumper
---

![chall](../writings/H7CTF-2026-Quals/WorldOutter/1.png)

![chall](../writings/H7CTF-2026-Quals/WorldOutter/1_1.png)

After reading the briefing, We can understand that we need to be league commissioner to get the flag.

I opened the challenge URL and tried to access the settings console but got 403. Inspected the localStorage and cookies in the browser's developer tools. I found a JWT in cookies being used for authentication.

I decoded the token and confirmed that it was using the `HS256` algorithm. I initially tried a few common JWT attacks, including changing the algorithm to `none`, brute-forcing a weak signing secret key, and forging a token with `role: commissioner` using an random secret.

None of these worked. It suggested that the server was properly enforcing the JWT algorithm and that the secret key is not a weak one.

I thought it was a dead end for me. But then I ran `ffuf` to see I can find any useful stuff.

![ffuf](../writings/H7CTF-2026-Quals/WorldOutter/2.png)

Nice. I found several files under `/.git/`. This indicates that the application Git repository is exposed through the web server.
This is interesting because exposed `.git` directory can be used to recover the repo's source code, commit history etc.

I used `git-dumper` to dump the exposed .git directory and reconstruct the repo locally.

![git-dumper](../writings/H7CTF-2026-Quals/WorldOutter/3.png)

![git-dumper](../writings/H7CTF-2026-Quals/WorldOutter/4.png)

Now, I went through the repo files to see if I can find anything interesting.

![repo](../writings/H7CTF-2026-Quals/WorldOutter/5.png)
![repo](../writings/H7CTF-2026-Quals/WorldOutter/6.png)

The flag is loaded from the `.env` file. So tried the `ls -la` command to see hidden files.
Also the `JWT_SECRET` is loaded from `config/secret` file!!!

![jwt](../writings/H7CTF-2026-Quals/WorldOutter/7.png)

No `.env` but we found the `JWT_SECRET`
Now I forged a jwt with `"role": "commissioner"` using [jwt auditor site](https://jwtauditor.com/) simply.

![forging jwt](../writings/H7CTF-2026-Quals/WorldOutter/8.png)

Replaced the token value in cookies with this forged one and refreshed the page and got the flag :)

![flag](../writings/H7CTF-2026-Quals/WorldOutter/9.png)
