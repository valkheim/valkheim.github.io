+++ 
draft = false
date = 2022-10-31T00:00:00+02:00
title = "ECW 2022 - Minifilter"
description = "The ECW 2022 Minifilter official write-up"
slug = ""
authors = []
tags = [
    "CTF",
    "ECW",
    "Windows",
    "kernel",
    "Minifilter"
]
categories = [
    "CTF"
]
externalLink = ""
series = [ "ECW" ]
+++

**Minifilter** is a reverse-engineering challenge I designed for the 2022 edition of the [European Cyber Week](https://www.european-cyber-week.eu/).
Here is the [source code for this challenge](https://github.com/valkheim/ECW-2022-MINIFILTER).

For this challenge, you’re given a `truc.sys` driver and a `file.txt.lock` file and the following scenario: "some user tried to save his file using her notepad but the saved file looks funny. Find out what’s going on there, find the file.txt cleartext".

The `truc.sys` implements a Windows minifilter that is xor-encoding the file when saved to disk. The key is randomly generated but not saved anywhere. Or is it?
The file is UTF-16 encoded (with BOM). We are able to recover the xor key using some null bytes in the flag, due to xor properties.

Here is my annotated resolution script:

```python
import math
import codecs

CHUNK_SIZE = 7
KEY_SIZE = 4

# Step 0: read the data
with open(r"./secret/file.txt.lock", "rb") as fh:
    data = fh.read()

# Step 1: read the key using the xored null bytes of UTF16-LE encoding while skipping BOM
key = [0xff] * KEY_SIZE
found = 0
for i in range(
    KEY_SIZE - 1, # Skip BOM
    len(data)
):
    if found == KEY_SIZE:
        break

    if i % 2: # Even bytes reveal one byte of the key
        chunk_idx = (int)(i / CHUNK_SIZE) + 1
        if found == 0:
            key[0] = data[i]  ^ chunk_idx
        elif found == 1:
            key[2] = data[i]  ^ chunk_idx
        elif found == 2:
            key[3] = data[i]  ^ chunk_idx
        elif found == 3:
            key[1] = data[i]  ^ chunk_idx

        found += 1

# Little endian repr
key = key[::-1]

print("Key: ", end="")
for k in key:
    print(f"{k:#x}, ", end="")
print("")

# Step 2: decode data
def chunks(xs, n):
    for i in range(0, len(xs), n):
        yield xs[i:i + n]

print("Chunks:")
clear = []
chunks = list(chunks(data, CHUNK_SIZE))
for chunk_idx, chunk in enumerate(chunks):
    for chunk_offset, byte in enumerate(chunk):
        # We can use chunk_offset because CHUNK_SIZE > KEY_SIZE, we don't need an offset from the beginning here
        byte = byte ^ key[chunk_offset % KEY_SIZE] ^ (chunk_idx + 1)
        print(f"0x{byte:02x}, ", end="")
        clear.append(byte)
        #print(f"{byte:c}", end="")
    print("")

# Step 3: reconstruct the text file
with open("clear.txt", "wb") as fh:
    decoded = bytes(clear).decode("utf-16-le")
    fh.write(decoded.encode('utf-16-le'))
    print(f"Contents: {decoded}")
```

```console
$ xxd file.txt.lock
00000000: fc32 be2f 40cc ac00 b4f8 6a00 a3f8 36ce  .2./@.....j...6.
00000010: a62d 71ce b606 fcfe 7e06 f9fe 57c8 a02b  .-q.....~...W..+
00000020: 61c8 b604 85fc 6104 b8fc 4dca ce29 41ca  a.....a...M..)A.
00000030: a20a 95f2 740a f5f2 48c4 c027 58c4 c608  ....t...H..'X...
00000040: aef0 4a08 80f0 74c6 fc25 03c6            ..J...t..%..
$ xxd original.txt
00000000: fffe 4500 4300 5700 7b00 4600 6c00 3700  ..E.C.W.{.F.l.7.
00000010: 5f00 7000 4f00 3500 5400 3000 5000 5f00  _.p.O.5.T.0.P._.
00000020: 6600 4900 4e00 4900 7300 4800 3300 4400  f.I.N.I.s.H.3.D.
00000030: 5f00 5000 5200 3000 4300 3300 5300 3500  _.P.R.0.C.3.S.5.
00000040: 6900 6e00 4700 7d00 0d00 0a00            i.n.G.}.....
```

flag: `ECW{Fl7_pO5T0P_fINIsH3D_PR0C3S5inG}`
