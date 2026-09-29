---
title: Overexposed
date: 2026-09-30
tags:
  - misc
  - png
  - zip
  - zsteg
  - ctf-writeups
---

![chall](../writings/H7CTF-2026-Quals/Overexposed/1.png)

We are given a PNG image file.

![PNG](../writings/H7CTF-2026-Quals/Overexposed/overexposed.png)

We start by checking what the file actually is, not trusting the extension.

```bash
[cva@archvm overexposed]$ ls
overexposed.png
[cva@archvm overexposed]$ file overexposed.png 
overexposed.png: PNG image data, 520 x 220, 8-bit/color RGB, non-interlaced
```

Confirmed its a PNG image.

Let's check the metadata of it.

```bash
[cva@archvm overexposed]$ exiftool overexposed.png 
ExifTool Version Number         : 13.55
File Name                       : overexposed.png
Directory                       : .
File Size                       : 3.4 kB
File Modification Date/Time     : 2026:09:29 22:52:42+05:30
File Access Date/Time           : 2026:09:29 22:53:13+05:30
File Inode Change Date/Time     : 2026:09:29 22:52:42+05:30
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 520
Image Height                    : 220
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Part 1                          : 06da61b
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 520x220
Megapixels                      : 0.114
```

Nothing useful :(

Read the description again. It says *Nothing left in the pixels*.
Let's check if the image has any extra data with `zsteg`

```bash
[cva@archvm overexposed]$ zsteg -a overexposed.png
[?] 372 bytes of extra data after image end (IEND), offset = 0xbcd
extradata:0         .. file: Zip archive data, at least v2.0 to extract, compression method=deflate
    00000000: 50 4b 03 04 14 00 00 00  08 00 00 00 00 00 3e e7  |PK............>.|
    00000010: 38 c1 9f 00 00 00 eb 00  00 00 0a 00 00 00 72 65  |8.............re|
    00000020: 61 64 6d 65 2e 74 78 74  4d 8f bb 15 c2 30 0c 45  |adme.txtM....0.E|
    00000030: 7b a6 78 1d 55 32 00 1d  03 d0 65 01 61 0b ac 83  |{.x.U2....e.a...|
    00000040: 6d e5 d8 0a 09 db 23 02  05 a5 ee fb 48 9a 92 74  |m.....#.....H..t|
    00000050: 50 0b 49 9e 7c ec 88 d2  38 98 b6 17 b2 74 eb d0  |P.I.|...8....t..|
    00000060: ca b8 49 e6 11 53 e2 3f  d5 43 55 0d e6 f0 17 1e  |..I..S.?.CU.....|
    00000070: 0f 17 2e 57 6e 1d 81 2a  78 f3 38 56 b1 a4 cb d7  |...Wn..*x.8V....|
    00000080: 26 35 f2 06 8a 45 cc a4  de 3f ac 60 18 d0 98 e2  |&5...E...?.`....|
    00000090: 6e 68 b4 22 6b a0 8c e4  c8 8b c6 c3 b9 46 d7 cb  |nh."k........F..|
    000000a0: de 8b 35 91 e1 a5 8b 2f  64 37 ea e3 d3 42 76 02  |..5..../d7...Bv.|
    000000b0: 61 96 60 8b d3 40 ad 09  77 14 f5 c1 92 df 21 fe  |a.`..@..w.....!.|
    000000c0: c3 2c 1b 67 6f 7b 03 50  4b 03 04 14 00 00 00 08  |.,.go{.PK.......|
    000000d0: 00 00 00 00 00 5e 1a 45  8e 09 00 00 00 07 00 00  |.....^.E........|
    000000e0: 00 09 00 00 00 70 61 72  74 32 2e 74 78 74 33 4d  |.....part2.txt3M|
    000000f0: 36 33 48 35 b0 00 00 50  4b 03 04 14 00 00 00 08  |63H5...PK.......|
meta part1          .. text: "06da61b"
chunk:0:IHDR        .. file: Adobe Photoshop Color swatch, version 0, 520 colors; 1st RGB space (0), w 0xdc, x 0x802, y 0, z 0; 2nd RGB space (0), w 0, x 0, y 0, z 0
b4,rgb,msb,xy       .. file: Intel Itanium COFF object file, not stripped, 32 sections, symbol offset=0x20020020, 2097664 symbols, optional header size 8194, created Sun Jan 24 10:57:06 1971, 2nd section name ""
b8,rgb,lsb,xy       .. file: PEX Binary Archive
```
We got the part 1 of the flag. 

And also, the output says, there is 372 bytes of extra data after IEND. (We can see the readme.txt and part2.txt in the zip contents here)

Let's run binwalk to get the zip file.

```bash
[cva@archvm overexposed]$ binwalk -e overexposed.png 
[2026-09-29T17:32:45Z ERROR binwalk::extractors::common] Failed to execute command 7z["x", "-y", "-o.", "/home/cva/Downloads/overexposed/extractions/overexposed.png.extracted/BCD/zip_BCD.bin"]: No such file or directory (os error 2)
[2026-09-29T17:32:45Z ERROR binwalk::extractors::common] Failed to spawn external extractor for 'zip' signature: No such file or directory (os error 2)

                                                                                          /home/cva/Downloads/overexposed/extractions/overexposed.png
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DECIMAL                            HEXADECIMAL                        DESCRIPTION
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0                                  0x0                                PNG image, total size: 3021 bytes
3021                               0xBCD                              ZIP archive, file count: 1, total size: 372 bytes
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[#] Extraction of png data at offset 0x0 declined
[-] Extraction of zip data at offset 0xBCD failed!
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Analyzed 1 file for 85 file signatures (187 magic patterns) in 8.0 milliseconds
```

Binwalk locates the ZIP at `0xBCD` but fails to extract because it can't spawn `7z` on this system. That's fine, we know the offset. Carve it manually.

```bash
[cva@archvm overexposed]$ python3 - <<'EOF'
data = open("overexposed.png","rb").read()
i = data.find(b"PK\x03\x04")
print("zip starts at", hex(i), "size", len(data)-i)
open("payload.zip","wb").write(data[i:])
EOF
zip starts at 0xbcd size 372
[cva@archvm overexposed]$ ls
extractions  overexposed.png  payload.zip
```

The signature `PK\x03\x04` marks the start of a ZIP local file header. We slice from there to end of file.

Let's Check what we got in the zip.

```bash
[cva@archvm overexposed]$ unzip -l payload.zip 
Archive:  payload.zip
error [payload.zip]:  missing 3021 bytes in zipfile
  (attempting to process anyway)
  Length      Date    Time    Name
---------  ---------- -----   ----
      235  1980-00-00 00:00   readme.txt
---------                     -------
      235                     1 file
```

`unzip` complains that 3021 bytes are missing and lists only `readme.txt`. That mismatch is deliberate — something is hidden. (the part2.txt we have observed!)

Let's unzip it.

```bash
[cva@archvm overexposed]$ unzip payload.zip 
Archive:  payload.zip
error [payload.zip]:  missing 3021 bytes in zipfile
  (attempting to process anyway)
error: invalid zip file with overlapped components (possible zip bomb)
 To unzip the file anyway, rerun the command with UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE environmnent variable

[cva@archvm overexposed]$ UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE unzip payload.zip 
Archive:  payload.zip
error [payload.zip]:  missing 3021 bytes in zipfile
  (attempting to process anyway)
  inflating: readme.txt   

[cva@archvm overexposed]$ cat readme.txt 
This archive's directory lists one file. The directory is not the archive.
Members can exist without the index admitting them -- read the raw local headers.
And remember what you are looking at: a picture carries more than its pixels.
```

The readme tells us exactly what's going on. The central directory lists one file, but ZIP local headers can exist without being in the index, so we should read them ourselves.

So we walk every `PK\x03\x04` header in the ZIP manually.

```bash
[cva@archvm overexposed]$ python3 - <<'EOF'
import struct, zlib

data = open("payload.zip","rb").read()
i = 0
while True:
    j = data.find(b"PK\x03\x04", i)
    if j < 0: break
    # Local file header layout (30 bytes):
    #   sig(4) ver(2) flags(2) method(2) mtime(2) mdate(2)
    #   crc(4) csize(4) usize(4) namelen(2) extralen(2)
    (sig, ver, flags, method, mtime, mdate,
     crc, csize, usize, nlen, elen) = struct.unpack("<IHHHHHIIIHH",
                                                    data[j:j+30])
    name = data[j+30:j+30+nlen].decode()
    dstart = j + 30 + nlen + elen
    comp = data[dstart:dstart+csize]
    raw = zlib.decompress(comp, -15) if method == 8 else comp
    print(f"===== {name} (offset {hex(j)}) =====")
    print(raw.decode("utf-8","replace"))
    i = dstart + csize
EOF
===== readme.txt (offset 0x0) =====
This archive's directory lists one file. The directory is not the archive.
Members can exist without the index admitting them -- read the raw local headers.
And remember what you are looking at: a picture carries more than its pixels.

===== part2.txt (offset 0xc7) =====
5c60e08
===== part3.txt (offset 0xf7) =====
7c87c9
```

Each local file header is 30 bytes followed by the filename and the compressed data. The `-15` in `zlib.decompress` means raw deflate, which is what ZIP uses. Three entries come out: `readme.txt`, `part2.txt` with `5c60e08`, and `part3.txt` with `7c87c9`. `unzip` never showed us those last two because they weren't in the central directory.

We already got the part 1 using `zsteg`.

All three parts:

```
part1 = 06da61b
part2 = 5c60e08
part3 = 7c87c9
```

Concatenate them in the flag format:

```
H7CTF{06da61b5c60e087c87c9}
```

what we learned from this - a container's index is not its contents. PNG viewers stop at IEND, and `unzip` trusts the central directory. Both hide data that's still present in the raw bytes. Parsing the file formats directly is what exposes it.
