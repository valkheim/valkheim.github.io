+++ 
draft = false
date = 2021-10-25T00:00:00+02:00
title = "ECW 2021 - Chest"
description = ""
slug = ""
authors = []
tags = [
    "CTF",
    "ECW",
    "AVR"
]
categories = [
    "CTF"
]
externalLink = ""
series = [ "ECW" ]
+++

**Chest** was one of the reverse-engineering challenge of the [European Cyber Week](https://www.european-cyber-week.eu/) 2021 challenges. I’m the author of that AVR challenge and will detail here my solution.

The provided file `chest.hex` file is in [Intel HEX format](https://www.intel.com/content/www/us/en/support/programmable/articles/000076770.html).

```console
$ cat chest.hex
:100000000C9434000C9449000C9449000C94490061
:100010000C9449000C9449000C9449000C9449003C
:100020000C9449000C9449000C9449000C9449002C
:100030000C9449000C9449000C9449000C9449001C
:100040000C9449000C9449000C9449000C9449000C
:100050000C9449000C9449000C9449000C944900FC
:100060000C9449000C94490011241FBECFEFD8E036
:10007000DEBFCDBF11E0A0E0B1E0E8EAF1E002C0F0
:1000800005900D92A632B107D9F70E94CA000C94D0
:10009000D2000C9400001092C5008093C40088E147
:1000A0008093C10086E08093C20008959091C000C3
:1000B00095FFFCCF8093C60008950F931F93CF93B5
:1000C000DF93EC018C01060F111DC017D10721F041
:1000D00089910E945600F9CFDF91CF911F910F9126
:1000E00008958091C00087FFFCCF8091C6000895DD
:1000F0000F931F93CF93DF93EC018C01060F111D1B
:10010000C017D10721F00E9471008993F9CFDF91C8
:10011000CF911F910F910895CF93DF93CDB7DEB7A5
:100120002B970FB6F894DEBF0FBECDBF8BE0EBE18F
:10013000F1E0DE01119601900D928A95E1F76BE0F6
:10014000CE0101960E945D000E9471002B960FB6B1
:10015000F894DEBF0FBECDBFDF91CF910895FF921F
:100160000F931F93CF93DF93F82EC0E0D1E00CE103
:1001700011E0888184508F250E94560022960C172A
:100180001D07B9F78AE0DF91CF911F910F91FF9082
:100190000C94560087E60E944B000E948C000E943F
:1001A000AF00FBCFF894FFCF4F5551505D62795DA2
:1001B00073546F5770424355717A3E3842454378C5
:0E01C000773300456E746572206B65790A0016
:00000001FF
```

The Intel HEX is a transitional file format for microcontrollers, (E)PROMs or other devices.
The documentation states that HEXs can be converted to binary files and programmed into a configuration device.

```console
$ objcopy -I ihex chest.hex -O binary chest.bin ; xxd chest.bin
00000000: 0c94 3400 0c94 4900 0c94 4900 0c94 4900  ..4...I...I...I.
00000010: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000020: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000030: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000040: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000050: 0c94 4900 0c94 4900 0c94 4900 0c94 4900  ..I...I...I...I.
00000060: 0c94 4900 0c94 4900 1124 1fbe cfef d8e0  ..I...I..$......
00000070: debf cdbf 11e0 a0e0 b1e0 e8ea f1e0 02c0  ................
00000080: 0590 0d92 a632 b107 d9f7 0e94 ca00 0c94  .....2..........
00000090: d200 0c94 0000 1092 c500 8093 c400 88e1  ................
000000a0: 8093 c100 86e0 8093 c200 0895 9091 c000  ................
000000b0: 95ff fccf 8093 c600 0895 0f93 1f93 cf93  ................
000000c0: df93 ec01 8c01 060f 111d c017 d107 21f0  ..............!.
000000d0: 8991 0e94 5600 f9cf df91 cf91 1f91 0f91  ....V...........
000000e0: 0895 8091 c000 87ff fccf 8091 c600 0895  ................
000000f0: 0f93 1f93 cf93 df93 ec01 8c01 060f 111d  ................
00000100: c017 d107 21f0 0e94 7100 8993 f9cf df91  ....!...q.......
00000110: cf91 1f91 0f91 0895 cf93 df93 cdb7 deb7  ................
00000120: 2b97 0fb6 f894 debf 0fbe cdbf 8be0 ebe1  +...............
00000130: f1e0 de01 1196 0190 0d92 8a95 e1f7 6be0  ..............k.
00000140: ce01 0196 0e94 5d00 0e94 7100 2b96 0fb6  ......]...q.+...
00000150: f894 debf 0fbe cdbf df91 cf91 0895 ff92  ................
00000160: 0f93 1f93 cf93 df93 f82e c0e0 d1e0 0ce1  ................
00000170: 11e0 8881 8450 8f25 0e94 5600 2296 0c17  .....P.%..V."...
00000180: 1d07 b9f7 8ae0 df91 cf91 1f91 0f91 ff90  ................
00000190: 0c94 5600 87e6 0e94 4b00 0e94 8c00 0e94  ..V.....K.......
000001a0: af00 fbcf f894 ffcf 4f55 5150 5d62 795d  ........OUQP]by]
000001b0: 7354 6f57 7042 4355 717a 3e38 4245 4378  sToWpBCUqz>8BECx
000001c0: 7733 0045 6e74 6572 206b 6579 0a00       w3.Enter key..
```

Note that we can also use the online tool [matrixstorm](http://matrixstorm.com/avr/hextobin/ihexconverter.html) to do this.

Now that we have our binary, we now need to identify for which architecture it was compiled.

``` console
file chest.bin
chest.bin: data
```

Well, our beloved friend `file` didn't even recognized the file format. At that point, we have several options to discover the architecture:

* compile a sample project for many architectures and clustering the outputs using correlation techniques like binary diffing in the hope of identifying the correct architecture
* try disassembling for many architectures in the hope of discovering the right code.
* googling the HEX

The Googling technique is definetly the fastest and the easiest. It gives us a lot of results concerning **AVR**. Let's give the `avr-objdump` disassembler a try:

```console
$ avr-objdump -m avr -D chest.hex

00000000 <.sec1>:
   0:    0c 94 34 00     jmp    0x68    ;  0x68
   4:    0c 94 49 00     jmp    0x92    ;  0x92
   8:    0c 94 49 00     jmp    0x92    ;  0x92
   c:    0c 94 49 00     jmp    0x92    ;  0x92
  10:    0c 94 49 00     jmp    0x92    ;  0x92
  14:    0c 94 49 00     jmp    0x92    ;  0x92
  18:    0c 94 49 00     jmp    0x92    ;  0x92
  1c:    0c 94 49 00     jmp    0x92    ;  0x92
  20:    0c 94 49 00     jmp    0x92    ;  0x92
  24:    0c 94 49 00     jmp    0x92    ;  0x92
  28:    0c 94 49 00     jmp    0x92    ;  0x92
  2c:    0c 94 49 00     jmp    0x92    ;  0x92
  30:    0c 94 49 00     jmp    0x92    ;  0x92
  34:    0c 94 49 00     jmp    0x92    ;  0x92
  38:    0c 94 49 00     jmp    0x92    ;  0x92
  3c:    0c 94 49 00     jmp    0x92    ;  0x92
  40:    0c 94 49 00     jmp    0x92    ;  0x92
  44:    0c 94 49 00     jmp    0x92    ;  0x92
  48:    0c 94 49 00     jmp    0x92    ;  0x92
  4c:    0c 94 49 00     jmp    0x92    ;  0x92
  50:    0c 94 49 00     jmp    0x92    ;  0x92
  54:    0c 94 49 00     jmp    0x92    ;  0x92
  58:    0c 94 49 00     jmp    0x92    ;  0x92
  5c:    0c 94 49 00     jmp    0x92    ;  0x92
  60:    0c 94 49 00     jmp    0x92    ;  0x92
  64:    0c 94 49 00     jmp    0x92    ;  0x92
  68:    11 24           eor    r1, r1

[...]

  92:    0c 94 00 00     jmp    0    ;  0x0

[...]
```

If we don't pay attention to the last bytes which are encoding the strings, it looks like valid code. At the beginning, we can read a 26-entries vector table.

We know that this code is targeting an Atmel AVR microcontroller, but which one? Here is a [list of the most common ones](https://gcc.gnu.org/onlinedocs/gcc/AVR-Options.html), and here is a [matrix listing some of their available features](https://www-lisic.univ-littoral.fr/~hebert/microcontroleur/fichiers/famille_avr_8_bits.png).

Again, we have multiple options to discover the correct microcontroller:

* compile samples with all the different MCU types supported by (let's say) `avr-gcc` and again, use some correlation techniques against our dump
* searching more infos about what we already know, like the [interrupt vectors](https://ece-classes.usc.edu/ee459/library/documents/avr_intr_vectors/)
* googling the code

Again, the googling technique is the fastest and the less painful. We can quickly find a [dump like ours](https://stackoverflow.com/questions/17323757/going-through-avr-assembler-hello-world-code) that is targeting an ATmega328P.

We can proceed with a static analysis using the [AVR instruction set]() and the [ATMega328P datasheet]():

```console
  __vectors:
     0:    0c 94 34 00     jmp     0x68    ;  0x68        ; RESET     ; __ctors_end
     4:    0c 94 49 00     jmp     0x92    ;  0x92        ; INT0      ; __bad_interrupt
     8:    0c 94 49 00     jmp     0x92    ;  0x92        ; INT1
     c:    0c 94 49 00     jmp     0x92    ;  0x92        ; PCINT0
    10:    0c 94 49 00     jmp     0x92    ;  0x92        ; PCINT1
    14:    0c 94 49 00     jmp     0x92    ;  0x92        ; PCINT2
    18:    0c 94 49 00     jmp     0x92    ;  0x92        ; WDT
    1c:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER2 COMPA
    20:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER2 COMPB
    24:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER2 OVF
    28:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER1 CAPT
    2c:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER1 COMPA
    30:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER1 COMPB
    34:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER1 OVF
    38:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER0 COMPA
    3c:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER0 COMPB
    40:    0c 94 49 00     jmp     0x92    ;  0x92        ; TIMER0 OVF
    44:    0c 94 49 00     jmp     0x92    ;  0x92        ; SPI,STC
    48:    0c 94 49 00     jmp     0x92    ;  0x92        ; USART,RX
    4c:    0c 94 49 00     jmp     0x92    ;  0x92        ; USART,UDRE
    50:    0c 94 49 00     jmp     0x92    ;  0x92        ; USART,TX
    54:    0c 94 49 00     jmp     0x92    ;  0x92        ; ADC
    58:    0c 94 49 00     jmp     0x92    ;  0x92        ; EE READY
    5c:    0c 94 49 00     jmp     0x92    ;  0x92        ; ANALOG COMP
    60:    0c 94 49 00     jmp     0x92    ;  0x92        ; TWI
    64:    0c 94 49 00     jmp     0x92    ;  0x92        ; SPM READY

  __ctors_end:
    68:    11 24           eor    r1, r1        ; r1 = 0
    6a:    1f be           out    0x3f, r1      ; clear 0xf3 (SREG)
                                                ; Initialize stack pointer at 0x08ff
    6c:    cf ef           ldi    r28, 0xFF
    6e:    d8 e0           ldi    r29, 0x08
    70:    de bf           out    0x3e, r29     ; 0x3e is the high portion of the stack pointer
    72:    cd bf           out    0x3d, r28     ; 0x3d is the low  portion of the stack pointer

  __do_copy_data:
    74:    11 e0           ldi    r17, 0x01
    76:    a0 e0           ldi    r26, 0x00
    78:    b1 e0           ldi    r27, 0x01
    7a:    e8 ea           ldi    r30, 0xA8     ; low  portion of the data at 0x01A8
    7c:    f1 e0           ldi    r31, 0x01     ; high portion of the data at 0x01A8
    7e:    02 c0           rjmp   .+4           ; 0x84
    80:    05 90           lpm    r0, Z+
    82:    0d 92           st     X+, r0
    84:    a6 32           cpi    r26, 0x26     ; size of the data section
    86:    b1 07           cpc    r27, r17
    88:    d9 f7           brne   .-10          ; 0x80

    8a:    0e 94 ca 00     call   0x194         ; __main
    8e:    0c 94 d2 00     jmp    0x1a4         ; __exit

  __bad_interrupt:
    92:    0c 94 00 00     jmp    0

  __usart_init:                                 ; from avr/iom328p.h
    96:    10 92 c5 00     sts    0x00C5, r1    ; UBRR0H or _SFR_MEM8(0xC5)
    9a:    80 93 c4 00     sts    0x00C4, r24   ; UBRR0L
    9e:    88 e1           ldi    r24, 0x18     ; 24 or 00011000b
    a0:    80 93 c1 00     sts    0x00C1, r24   ; UCSR0B
    a4:    86 e0           ldi    r24, 0x06     ; 06 or 00000110b
    a6:    80 93 c2 00     sts    0x00C2, r24   ; UCSR0C
    aa:    08 95           ret

  __usart_transmit_byte:                        ; while (!(UCSR0A & (1 << UDRE0));
    ac:    90 91 c0 00     lds    r25, 0x00C0   ; r25 = UCSR0A
    b0:    95 ff           sbrs    r25, 5       ; skip if bit 5 (UDRE0) in r25 is set
    b2:    fc cf           rjmp    .-8          ; loop
    b4:    80 93 c6 00     sts    0x00C6, r24   ; UDR0 = 24
    b8:    08 95           ret

  __usart_transmit_bytes:
    ba:    0f 93           push   r16
    bc:    1f 93           push   r17
    be:    cf 93           push   r28
    c0:    df 93           push   r29
    c2:    ec 01           movw   r28, r24
    c4:    8c 01           movw   r16, r24
    c6:    06 0f           add    r16, r22
    c8:    11 1d           adc    r17, r1
    ca:    c0 17           cp     r28, r16
    cc:    d1 07           cpc    r29, r17
    ce:    21 f0           breq   .+8       ; 0xd8
    d0:    89 91           ld     r24, Y+   ; load indirect from data space using index Y (post inc)
    d2:    0e 94 56 00     call   0xac      ; __usart_transmit_byte(r24)
    d6:    f9 cf           rjmp   .-14      ; 0xca
    d8:    df 91           pop    r29
    da:    cf 91           pop    r28
    dc:    1f 91           pop    r17
    de:    0f 91           pop    r16
    e0:    08 95           ret

  __usart_receive_byte:                         ; while (!(UCSR0A & (1 << RXC0)));
    e2:    80 91 c0 00     lds    r24, 0x00C0   ; r24 = UCSR0A
    e6:    87 ff           sbrs   r24, 7        ; skip if bit 7 (RXC0) in r24 is set
    e8:    fc cf           rjmp   .-8           ; loop
    ea:    80 91 c6 00     lds    r24, 0x00C6   ; UDR0
    ee:    08 95           ret

  __usart_receive_bytes:
    f0:    0f 93           push    r16
    f2:    1f 93           push    r17
    f4:    cf 93           push    r28
    f6:    df 93           push    r29
    f8:    ec 01           movw    r28, r24
    fa:    8c 01           movw    r16, r24
    fc:    06 0f           add     r16, r22
    fe:    11 1d           adc     r17, r1
   100:    c0 17           cp      r28, r16
   102:    d1 07           cpc     r29, r17
   104:    21 f0           breq    .+8
   106:    0e 94 71 00     call    0xe2         ; __usart_receive_byte
   10a:    89 93           st      Y+, r24
   10c:    f9 cf           rjmp    .-14
   10e:    df 91           pop     r29
   110:    cf 91           pop     r28
   112:    1f 91           pop     r17
   114:    0f 91           pop     r16
   116:    08 95           ret

  __display_prompt:
   118:    cf 93           push   r28
   11a:    df 93           push   r29
   11c:    cd b7           in     r28, 0x3d     ; save SP low
   11e:    de b7           in     r29, 0x3e     ; save SP high
   120:    2b 97           sbiw   r28, 0x0b     ; r28 -= strlen(prompt) + 1
   122:    0f b6           in     r0, 0x3f      ; save SREG
   124:    f8 94           cli                  ; clear interrupts
   126:    de bf           out    0x3e, r29     ; restore SP high
   128:    0f be           out    0x3f, r0      ; restore SREG
   12a:    cd bf           out    0x3d, r28     ; restore SP low
   12c:    8b e0           ldi    r24, 0x0B     ; strlen(_prompt) + 1
   12e:    eb e1           ldi    r30, 0x1B
   130:    f1 e0           ldi    r31, 0x01
   132:    de 01           movw   r26, r28
   134:    11 96           adiw   r26, 0x01     ; 1
   136:    01 90           ld     r0, Z+        <----,
   138:    0d 92           st     X+, r0             |
   13a:    8a 95           dec    r24                |
   13c:    e1 f7           brne   .-8           -----'
   13e:    6b e0           ldi    r22, 0x0B     ; strlen(_prompt) + 1
   140:    ce 01           movw   r24, r28
   142:    01 96           adiw   r24, 0x01     ; inc r24 ptr
   144:    0e 94 5d 00     call   0xba          ; __usart_transmit_bytes(r24, r22)
   148:    0e 94 71 00     call   0xe2          ; r24 = __usart_receive_byte()
   14c:    2b 96           adiw   r28, 0x0b     ; move r28 at the end of _prompt
   14e:    0f b6           in     r0, 0x3f      ; save SREG
   150:    f8 94           cli
   152:    de bf           out    0x3e, r29     ; restore SP high (not touched)
   154:    0f be           out    0x3f, r0      ; restore SREG
   156:    cd bf           out    0x3d, r28     ; restore SP low (end of _prompt, beginning of _flag)
   158:    df 91           pop    r29
   15a:    cf 91           pop    r28
   15c:    08 95           ret

  __decode:
   15e:    ff 92           push   r15
   160:    0f 93           push   r16
   162:    1f 93           push   r17
   164:    cf 93           push   r28
   166:    df 93           push   r29
   168:    f8 2e           mov    r15, r24
   16a:    c0 e0           ldi    r28, 0x00
   16c:    d1 e0           ldi    r29, 0x01
   16e:    0c e1           ldi    r16, 0x1C
   170:    11 e0           ldi    r17, 0x01
   172:    88 81           ld     r24, Y
   174:    84 50           subi   r24, 0x04     ; acc -= 4
   176:    8f 25           eor    r24, r15      ; acc ^= user input key
   178:    0e 94 56 00     call   0xac          ; __usart_transmit_byte
   17c:    22 96           adiw   r28, 0x02     ; i += 2
   17e:    0c 17           cp     r16, r28
   180:    1d 07           cpc    r17, r29
   182:    b9 f7           brne   .-18          ; loop
   184:    8a e0           ldi    r24, 0x0A     ; r24 = '\n'
   186:    df 91           pop    r29
   188:    cf 91           pop    r28
   18a:    1f 91           pop    r17
   18c:    0f 91           pop    r16
   18e:    ff 90           pop    r15
   190:    0c 94 56 00     jmp    0xac          ; __usart_transmit_byte('\n')

  __main:
   194:    87 e6           ldi    r24, 0x67     ; UBRR
   196:    0e 94 4b 00     call   0x96          ; __usart_init(UBRR)
   19a:    0e 94 8c 00     call   0x118         ; while __decode(__display_prompt())
   19e:    0e 94 af 00     call   0x15e         ;
   1a2:    fb cf           rjmp   .-10

  __exit:
   1a4:    f8 94           cli

  __stop:
   1a6:    ff cf           rjmp   .-2           ;  0x1a6

  __flag:   ; OUQP]by]sToWpBCUqz>8BECxw3
   1a8:     4f 55 51 50 5d 62 79 5d 73 54 6f 57 70 42 43 55 71 7a 3e 38 42 45 43 78 77 33

  __prompt: ; Enter key
   1c3:     45 6e 74 65 72 20 6b 65 79 0a 00
```

Perfect, there is a decoding routine at `0x15e` for the encoded flag at `0x1a8`. This routine needs a xor key, which is received using a serial line. We can pursue the static analysis by bruteforcing the key. This python script will do the job:

```python
encoded = "OUQP]by]sToWpBCUqz>8BECxw3"
rot_key = 4
for xor_key in range(0xFF):
    decoded = "".join(
        [
            chr((ord(char) - rot_key) ^ xor_key)
            for i, char in enumerate(encoded)
            if not i % 2
        ]
    )
    if decoded.casefold().startswith("ecw{"):
        print(f"{xor_key:#04x}: {decoded}")
```

```console
$ python3 decode.py
0x0e ECW{aeb1c401}
```

Another approach was to emulate the MCU and bruteforce the key like so:

```console
$ qemu-system-avr -S -s -nographic -serial tcp::5678,server=on,wait=off -machine uno -bios chest.bin
$ printf "\x0e" | nc localhost 5678
ECW{aeb1c401}
```

I hope you enjoyed it as much as I do, see you next year!
