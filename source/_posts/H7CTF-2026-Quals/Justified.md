---
title: Justified
date: 2026-09-30
tags:
  - web
  - latex
  - ctf-writeups
---

![chall](../writings/H7CTF-2026-Quals/Justified/1.png)

![chall](../writings/H7CTF-2026-Quals/Justified/1_1.png)

Upon opening the challenge URL, we can see that the application uses pdflatex to compile the LaTeX code supplied by the user.

![webpage](../writings/H7CTF-2026-Quals/Justified/2.png)

In the Typesetting log, we can see that `\write18` is enabled. 

![write18 enabled](../writings/H7CTF-2026-Quals/Justified/3.png)

Let's see the latex documentation.

![latex docs](../writings/H7CTF-2026-Quals/Justified/4.png)
![latex docs](../writings/H7CTF-2026-Quals/Justified/5.png)

Let's try `\immediate\write18{cat /flag.txt}` assuming the flag is located at `/flag.txt` as the previous challenge [Merged](../Merged/) also has flag at the same location.

![flag](../writings/H7CTF-2026-Quals/Justified/7.png)

We got the flag :)

I did this exact same thing in [overleaf.com](https://overleaf.com) but it was a docker container and that docker image is isolated and only contain the files related to that particular project. so no use :(

As I already did this in overleaf, I was able to solve this challenge easily and quickly.
