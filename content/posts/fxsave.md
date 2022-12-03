+++ 
draft = false
date = 2022-10-26T00:00:00+02:00
title = "The fxsave and fxrstor instructions"
description = "The fxsave and fxrstor instructions"
slug = ""
authors = []
tags = [
    "x86",
    "asm",
]
categories = [
    "x86"
]
externalLink = ""
series = [ "x86" ]
+++

The IA-32 instruction set has some darn cool instructions.

Instructions such as the `fxsave`/`fxrstor` combo are using a stack to operate:

{{< notice info >}}
The **fxsave** instruction saves the current state of the x87 FPU, MMX technology, XMM, and MXCSR registers to a 512-byte memory location specified in the destination operand.
{{< /notice >}}

{{< notice info >}}
The **fxrstor** instruction reloads the x87 FPU, MMX technology, XMM, and MXCSR registers from the 512-byte memory image specified in the source operand.
The manual also states that "this data *should* have been written to memory previously using the FXSAVE instruction".
{{< /notice >}}

The save and restore instructions allows us to do some cool tricks:

* save "large" amount of data in the stack
* swap registers values (not necessarily like `fxchg`)
* pack data from multiple registers
* unpack data into multiple registers

I will now show how you can save some code on that stack and later restore it into registers for further execution.

We first need some code and data to re-use:

```asm
section .data
  align 64
  regsave times 0x200 db 0x90

  msg db "hello",0xa,0x0

section .text
  global _start

exit_0:
  mov eax, 1    ; b8 01 00 00 00
  mov edi, 1    ; bf 01 00 00 00
  mov rsi, msg  ; 48 be 00 00 00 00|00 00 00 00
  mov edx, 7    ; ba 07 00 00 00
  syscall       ; 0f 05

  xor rdi, rdi  ; 48 31 ff
  mov rax, 60   ; b8 3c|00 00 00
  syscall       ; 0f 05

exit_1:
  mov edi, 1    ; bf 01 00 00 00
  mov eax, 0x3c ; b8 3c 00 00 00
  syscall       ; 0f 05
```

Now we copy the code into the xmm registers and we store them on the `regsave` stack:

```asm
_start:
  ; save some code in regsave sections using 128-bits chunks
  movdqu xmm0, [exit_0 + 0x10 * 0]
  movdqu xmm1, [exit_0 + 0x10 * 1]
  movdqu xmm2, [exit_0 + 0x10 * 2]

  ; copy data to the ordered regsave area
  fxsave [regsave]
```

{{< notice note >}}
The xmm registers are pretty common and frequently replace memcpy during compilation but you might want to copy the `exit_0` code in some other registers than the `xmm0`, `xmm1` and `xmm2` we used previously.
{{< /notice >}}

At that point, `regsave`+`0xa0` contains the exit_0 function across the saved `xmm0`, `xmm1` and `xmm2` registers:

```console
0x4030a0:       0xb8    0x1     0x0     0x0     0x0     0xbf    0x1     0x0
0x4030a8:       0x0     0x0     0x48    0xbe    0x0     0x32    0x40    0x0
0x4030b0:       0x0     0x0     0x0     0x0     0xba    0x7     0x0     0x0
0x4030b8:       0x0     0xf     0x5     0x48    0x31    0xff    0xb8    0x3c
0x4030c0:       0x0     0x0     0x0     0xf     0x5     0xbf    0x1     0x0
0x4030c8:       0x0     0x0     0xb8    0x3c    0x0     0x0     0x0     0xf
```

We now have a copy of the `exit_0` function that you can execute.
If you cannot execute it right away, you can use `fxrstor` to reloads registers and craft an execution from there. Here are some ways to do it:

```asm
  ; restore registers
  fxrstor  [regsave]

  ; exec on the regsave data
  mov rax, regsave
  add rax, 0xa0 ; xmm0 offset
  push rax
  ret
```

or:

```asm
  ; restore registers
  fxrstor  [regsave]

  ; exec on the stack using registers
  sub     rsp, 0x10
  movdqu  [rsp], xmm2
  sub     rsp, 0x10
  movdqu  [rsp], xmm1
  sub     rsp, 0x10
  movdqu  [rsp], xmm0
  jmp rsp
```

{{< notice tip >}}
In x87, the FPU is also using a stack (or barrel). You might find the `fld`/`fstp` instructions useful.
{{< /notice >}}
