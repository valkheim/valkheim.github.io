+++ 
draft = false
date = 2022-11-17T00:00:00+02:00
title = "ECW 2022 - Crackme16"
description = "The ECW 2022 Crackme16 official write-up"
slug = ""
authors = []
tags = [
    "CTF",
    "ECW",
    "BIOS",
    "bootloader"
]
categories = [
    "CTF"
]
externalLink = ""
series = [ "ECW" ]
+++

**Crackme16** is a reverse-engineering challenge I designed for the finals of the [European Cyber Week](https://www.european-cyber-week.eu/) 2022.
Here is the [source code for this challenge](https://github.com/valkheim/ECW-2022-CRACKME16).

We're given an `os.bin` file. Let's see what it is:

```console
$ file os.bin
os.bin: DOS/MBR boot sector; partition 1 : ID=0xb2, active 0xb0, start-CHS
(0x194,19,46), end-CHS (0x3e0,51,38), startsector 1456018950, 2168693133
sectors; partition 3 : ID=0x22, active 0xc1, start-CHS (0x330,141,6), end-CHS
(0x362,150,34), startsector 3705749179, 1985222079 sectors
```

A DOS/MBR boot sector? Ok let's figure it out. To do so, one can use the
awesome [kaitai parsing library](https://formats.kaitai.io/mbr_partition_table/python.html).
In the following snippet, i've added a pdb breakpoint for me to play with the code:

```python3
# This is a generated file! Please edit source .ksy file and use
# kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class MbrPartitionTable(KaitaiStruct):
    """MBR (Master Boot Record) partition table is a traditional way of
    MS-DOS to partition larger hard disc drives into distinct
    partitions.
    
    This table is stored in the end of the boot sector (first sector) of
    the drive, after the bootstrap code. Original DOS 2.0 specification
    allowed only 4 partitions per disc, but DOS 3.2 introduced concept
    of "extended partitions", which work as nested extra "boot records"
    which are pointed to by original ("primary") partitions in MBR.
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.bootstrap_code = self._io.read_bytes(446)
        self.partitions = [None] * (4)
        for i in range(4):
            self.partitions[i] = MbrPartitionTable.PartitionEntry(self._io, self, self._root)

        self.boot_signature = self._io.read_bytes(2)
        if not self.boot_signature == b"\x55\xAA":
            raise kaitaistruct.ValidationNotEqualError(b"\x55\xAA", self.boot_signature, self._io, u"/seq/2")

    class PartitionEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.status = self._io.read_u1()
            self.chs_start = MbrPartitionTable.Chs(self._io, self, self._root)
            self.partition_type = self._io.read_u1()
            self.chs_end = MbrPartitionTable.Chs(self._io, self, self._root)
            self.lba_start = self._io.read_u4le()
            self.num_sectors = self._io.read_u4le()


    class Chs(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.head = self._io.read_u1()
            self.b2 = self._io.read_u1()
            self.b3 = self._io.read_u1()

        @property
        def sector(self):
            if hasattr(self, '_m_sector'):
                return self._m_sector if hasattr(self, '_m_sector') else None

            self._m_sector = (self.b2 & 63)
            return self._m_sector if hasattr(self, '_m_sector') else None

        @property
        def cylinder(self):
            if hasattr(self, '_m_cylinder'):
                return self._m_cylinder if hasattr(self, '_m_cylinder') else None

            self._m_cylinder = (self.b3 + ((self.b2 & 192) << 2))
            return self._m_cylinder if hasattr(self, '_m_cylinder') else None


import pdb
breakpoint()
```

The partition table looks invalid, here is an extract of the partitions types
and associated number of sectors:

```console
$ python3 mbr_partition_table.py
--Return--
> /mbr_partition_table.py(84)<module>()->None
-> breakpoint()
(Pdb) print([(p.num_sectors, p.partition_type) for p in data.partitions])
[(2168693133, 178), (1533615329, 184), (1985222079, 34), (4289785985, 238)]
```

We can dump the bootstrap of the boot sector:

```console
(Pdb) out = open("code.bin", "wb")
(Pdb) out.write(data.bootstrap_code)
446
```

The hex view:

```console
$ xxd -o 0x7c00 code.bin
00007c00: 8816 4c7d bc00 8089 e5e8 3b00 bb8b 7c0f  ..L}......;...|.
00007c10: b60e cd7c 0fb6 16b4 7ce8 5700 bb97 7c0f  ...|....|.W...|.
00007c20: b60e 8a7c 0fb6 16b3 7ce8 4700 e8ac 00bb  ...|....|.G.....
00007c30: 0010 b605 8a16 4c7d e893 00e8 df00 ebfe  ......L}........
00007c40: e8bb 93ff ffeb fe50 b803 00cd 1058 c350  .......P.....X.P
00007c50: b40e b00d cd10 b00a cd10 58c3 60b4 0e8a  ..........X.`...
00007c60: 073c 0074 05cd 1043 ebf5 61c3 e8ed ffe8  .<.t...C..a.....
00007c70: ddff c360 b40e 8a07 30d0 cd10 4349 83f9  ...`....0...CI..
00007c80: 0074 02eb f1e8 c7ff 61c3 1a14 4a29 051a  .t......a...J)..
00007c90: 060b 040e 4a25 397a 2454 766b 6071 6770  ....J%9z$Tvk`qgp
00007ca0: 2446 7d24 5065 676c 6d66 656a 6524 4865  $F}$Peglmfeje$He
00007cb0: 6617 0104 6a46 4c43 497d 6135 6e54 6772  f...jFLCI}a5nTgr
00007cc0: 6139 6867 6179 4b72 3544 617f 010c b402  a9hgayKr5Da.....
00007cd0: 88f0 b500 b102 b600 cd13 c3bb b57c 0fb6  .............|..
00007ce0: 0eb1 7cb4 00cd 1602 06cc 7c32 06b2 7c3a  ..|.......|2..|:
00007cf0: 0775 0a43 4983 f900 7e02 ebe7 c3eb fe00  .u.CI...~.......
00007d00: 0000 0000 0000 00ff ff00 0000 9acf 00ff  ................
00007d10: ff00 0000 92cf 0017 00ff 7c00 00fa 0f01  ..........|.....
00007d20: 1617 7d0f 20c0 0c01 0f22 c0ea 307d 0800  ..}. ...."..0}..
00007d30: 66b8 1000 8ed8 8ed0 8ec0 8ee0 8ee8 bd00  f...............
00007d40: 8000 0089 e4e8 f6fe ffff ebfe 00cc 7866  ..............xf
00007d50: ac01 8798 d28a 2b8e db9a c2cc 059c 5933  ......+.......Y3
00007d60: 5550 8421 f27a 86c0 7e5f 247c 2028 1171  UP.!.z..~_$| (.q
00007d70: 6428 c1a4 0e7a 961c c726 21f0 fbc1 ba21  d(...z...&!....!
00007d80: 129e 0280 0acc c967 f744 caad d216 8e4e  .......g.D.....N
00007d90: 4a6a 7519 bab5 b8d1 ce0a 1896 18bd 10c0  Jju.............
00007da0: 287f da82 16c9 338b d1ed b3ed 732c 5f88  (.....3.....s,_.
00007db0: 197e 8e92 cd21 14c8 0138 b373 c2a5       .~...!...8.s..
```

We can dump assembly and annotate it. I begin by isolating the calls, splitting
the code with vertical spaces. I then annotate the code I encounter.

```console
$ objdump -D -b binary -mi386 -Maddr16,data16 -Mintel --adjust-vma=0x7c00 code.bin
code.bin:     file format binary


Disassembly of section .data:

00007c00 <.data>:
  7c00:  88 16 4c 7d          mov    BYTE PTR ds:0x7d4c,dl ; save initial dl value (driver number)
                                                           ; setup initial stack frame
  7c04:  bc 00 80             mov    sp,0x8000             ; setup stack ptr
  7c07:  89 e5                mov    bp,sp                 ; setup base  ptr
  7c09:  e8 3b 00             call   0x7c47                ; cls

  7c0c:  bb 8b 7c             mov    bx,0x7c8b             ; xor_string_ptr
  7c0f:  0f b6 0e cd 7c       movzx  cx,BYTE PTR ds:0x7ccd ; xor_string_length
  7c14:  0f b6 16 b4 7c       movzx  dx,BYTE PTR ds:0x7cb4 ; xor_key
  7c19:  e8 57 00             call   0x7c73                ; print_xor_string

  7c1c:  bb 97 7c             mov    bx,0x7c97
  7c1f:  0f b6 0e 8a 7c       movzx  cx,BYTE PTR ds:0x7c8a
  7c24:  0f b6 16 b3 7c       movzx  dx,BYTE PTR ds:0x7cb3
  7c29:  e8 47 00             call   0x7c73

  7c2c:  e8 ac 00             call   0x7cdb                ; read_passwd

  7c2f:  bb 00 10             mov    bx,0x1000
  7c32:  b6 05                mov    dh,0x5
  7c34:  8a 16 4c 7d          mov    dl,BYTE PTR ds:0x7d4c
  7c38:  e8 93 00             call   0x7cce

  7c3b:  e8 df 00             call   0x7d1d                 ; where?

  7c3e:  eb fe                jmp    0x7c3e                 ; loop forever
  7c40:  e8 bb 93             call   0xffe

  7c43:  ff                   (bad)  
  7c44:  ff                   (bad)  
  7c45:  eb fe                jmp    0x7c45

cls:
  7c47:  50                   push   ax      ; save ax
  7c48:  b8 03 00             mov    ax,0x3  ; ah == 0 -> clear screen
  7c4b:  cd 10                int    0x10    ; bios int 10 for video services
  7c4d:  58                   pop    ax      ; restore ax
  7c4e:  c3                   ret    

print_newline:
  7c4f:  50                   push   ax
  7c50:  b4 0e                mov    ah,0xe  ; display char
  7c52:  b0 0d                mov    al,0xd  ; char is 0xd or '\r'
  7c54:  cd 10                int    0x10    ; video int
  7c56:  b0 0a                mov    al,0xa  ; char is 0xa or '\n'
  7c58:  cd 10                int    0x10
  7c5a:  58                   pop    ax
  7c5b:  c3                   ret    

  [...]

print_xor_string(bx: xor_string_ptr, cx: xor_string_length, dl: xor_key):
  7c73:  60                   pusha                   ; save registers
  7c74:  b4 0e                mov    ah,0xe           ; display char
  7c76:  8a 07                mov    al,BYTE PTR [bx] ; store char at bx in al
  7c78:  30 d0                xor    al,dl            ; xor al char with dl
  7c7a:  cd 10                int    0x10             ; video
  7c7c:  43                   inc    bx               ; increment bx
  7c7d:  49                   dec    cx               ; decrement cx
  7c7e:  83 f9 00             cmp    cx,0x0           ; end of cx coutner
  7c81:  74 02                je     0x7c85           ; chain with 0x7c4f
  7c83:  eb f1                jmp    0x7c76           ; loop
  7c85:  e8 c7 ff             call   0x7c4f           ; print_newline
  7c88:  61                   popa                    ; restore registers
  7c89:  c3                   ret    

  [...]

read_passwd
  7cdb:  bb b5 7c             mov    bx,0x7cb5              ; encoded_pass_ptr
  7cde:  0f b6 0e b1 7c       movzx  cx,BYTE PTR ds:0x7cb1  ; pass_length
  7ce3:  b4 00                mov    ah,0x0                 ; read keyboard scancode (blocking)
  7ce5:  cd 16                int    0x16                   ; keyboard service
  7ce7:  02 06 cc 7c          add    al,BYTE PTR ds:0x7ccc  ; rot scancode value
  7ceb:  32 06 b2 7c          xor    al,BYTE PTR ds:0x7cb2  ; xor scancode value
  7cef:  3a 07                cmp    al,BYTE PTR [bx]       ; compare value with encoded password
  7cf1:  75 0a                jne    0x7cfd                 ; bad boy!
  7cf3:  43                   inc    bx                     ; increment encoded password ptr
  7cf4:  49                   dec    cx                     ; decrement password length
  7cf5:  83 f9 00             cmp    cx,0x0                 ; end of password?
  7cf8:  7e 02                jle    0x7cfc                 ; yes -> access granted
  7cfa:  eb e7                jmp    0x7ce3                 ; nope -> loop
  7cfc:  c3                   ret    

  [...]
```

At this point, we can write a script to recover the encoded strings (offset may differ):

```python3
import struct

with open("os.bin", "rb") as fh:
    code = fh.read()

print("key(s)\t\tlength\t\tstring")
print("===\t\t======\t\t======")
key = struct.unpack_from("B", code, offset=0xB0)[0]
length = struct.unpack_from("B", code, offset=0xC2)[0]
encoded_string = struct.unpack_from(f"{length}B", code, offset=0x8A)
decoded_string = "".join([chr(c ^ key) for c in encoded_string])
print(f"{key:#x}\t\t{length:#x}\t\t{decoded_string}")

key = struct.unpack_from("B", code, offset=0xC6)[0]
length = struct.unpack_from("B", code, offset=0xC5)[0]
encoded_string = struct.unpack_from(f"{length}B", code, offset=0x96)
decoded_string = "".join([chr(c ^ key) for c in encoded_string])
print(f"{key:#x}\t\t{length:#x}\t\t{decoded_string}")

rot = struct.unpack_from("B", code, offset=0xC4)[0]
xor = struct.unpack_from("B", code, offset=0xC3)[0]
length = struct.unpack_from("B", code, offset=0xC7)[
    0
]  # byte again? yes (a6 is for rot key)
encoded_string = struct.unpack_from(f"{length}B", code, offset=0xB1)
decoded_string = "".join([chr((c ^ xor) - rot) for c in encoded_string])
print(f"{rot:#x} && {xor:#x}\t{length:#x}\t\t{decoded_string}")
```

```console
key(s)          length          string                    
===             ======          ======                    
0x2             0xc             ~ Copland OS              
0x12            0x1a            ~ Product By Tachibana Lab
0x4 && 0xd      0x11            _3nTer_7he_wIr3D_         
```

We can now start and send the write the password. To do so, I use a [script](https://github.com/mvidner/sendkeys/blob/master/sendkeys) to send characters using the qemu monitor.

```console
$ qemu-system-i386 -monitor tcp:127.0.0.1:1234,server,nowait -fda os.bin
$ ./sendkeys "_3nTer_7he_wIr3D_" | nc -v 127.0.0.1 1234
Connection to 127.0.0.1 1234 port [tcp/*] succeeded!
QEMU 4.2.1 monitor - type 'help' for more information
(qemu) sendkey shift-minus
(qemu) sendkey 3
(qemu) sendkey n
(qemu) sendkey shift-t
(qemu) sendkey e
(qemu) sendkey r
(qemu) sendkey shift-minus
(qemu) sendkey 7
(qemu) sendkey h
(qemu) sendkey e
(qemu) sendkey shift-minus
(qemu) sendkey w
(qemu) sendkey shift-i
(qemu) sendkey r
(qemu) sendkey 3
(qemu) sendkey shift-d
(qemu) sendkey shift-minus
```