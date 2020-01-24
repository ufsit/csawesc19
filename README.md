# CSAW Embedded Security Challenge 2019 (Kernel Sanders)
Kernel Sanders participated in CSAW's 2019 embedded security challenge, which involved exploiting a series of challenges via specially crafted RFID card data (see the [call for submissions repo](https://github.com/TrustworthyComputing/csaw_esc_2019) for a better overview). Effectively, we'd develop attack payloads to target a specific challenge, program it onto a standard blank RFID card, and scan it at a reader, launching the payload.
We approached solving the 18 bite-sized crackme-style challenges using angr instead of manually reversing them using GHIDRA (no paid tools could be used).
Along the way we experienced challenges in performing symbolic execution in an embedded context, which we handled by mocking out I/O specific functions (mainly serial and USB). See our [`solver script`](/final/angresc.py) for the actual code.

One of the cooler things we managed was to achieve _arbitrary code execution_ on the provided board. We leveraged a buffer overflow and crafted an ARM shellcode payload to print message to the screen (see [the video](https://drive.google.com/open?id=1Dxu0LSNhNxHRTTTYGJKsosiagBaUCiCX) for the exploit running).
In the end, we solved 16 out of the 18 challenges (and the on-site live challenge), many of which were automatically solvable using angr. We earned 3rd place! See our final report and presentation for even more details. If you want to replicate our solver scripts, read below.

[Final Presentation [PDF]](/export/esc19-presentation-kernelsanders.pdf?raw=true) | [Demo Video [GDRIVE VIDEO]](https://drive.google.com/open?id=1Dxu0LSNhNxHRTTTYGJKsosiagBaUCiCX) | [Final Report [PDF]](/export/esc19-final-kernelsanders.pdf?raw=true) | [Qual Report [PDF]](/export/esc19-qual-kernelsanders.pdf?raw=true)
:----------:|:---------:|:--------------:|:------------:

## Other CSAW ESC Solutions
* [Shellphish (UCSB)](https://github.com/ucsb-seclab/hal-fuzz) - 1st
* [Arizona State University (ASU)](https://github.com/pwndevils/csaw-esc-19) - 2nd

## Solving the "Stairs" Challenge Using angr
To replicate our results run the following commands (tested on Ubuntu 16.04 + Python 3):

```
git clone https://github.com/ufsit/csawesc19.git
cd csawesc19/final/
# it is highly recommeneded you use a python virtual environment before continuing
pip install -r requirements.txt
./angresc.py A-stairs
```

You should see the following output:

```
Importing angr...
/home/user/.../cparser.py:164: UserWarning: <snip>
WARNING | 2019-11-04 11:39:30,369 | cle.elf | Segment PT_LOAD is empty at 0x1fff8000!
Calling solve_stairs
Function set to challenge_3(packet)
Hooked Print::print(char) (0x00000499)
Hooked Print::print(char const*) (0x000004bd)
Hooked Print::print(unsigned char) (0x000004d9)
Hooked Print::print(int) (0x000004fd)
Hooked Print::println(char) (0x00000519)
Hooked Print::println(char const*) (0x00000545)
Hooked Print::println(unsigned char) (0x0000056d)
Hooked Print::println(int) (0x00000599)
Hooked Print::println() (0x000027f5)
Hooked Print::printf(char const*, ...) (0x00002825)
Hooked Print::printNumber(unsigned long, unsigned char, unsigned char) (0x00002841)
Hooked Print::print(long) (0x000028c1)
WARNING | 2019-11-04 11:39:30,994 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-11-04 11:39:30,994 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-11-04 11:39:30,995 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-11-04 11:39:30,995 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-11-04 11:39:30,995 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-11-04 11:39:30,995 | angr.state_plugins.symbolic_memory | Filling register r4 with 4 unconstrained bytes referenced from 0xe9f (_Z11challenge_36packet+0x2 in TeensyChallengeSetA.ino.elf (0xe9f))
WARNING | 2019-11-04 11:39:30,997 | angr.state_plugins.symbolic_memory | Filling register r5 with 4 unconstrained bytes referenced from 0xe9f (_Z11challenge_36packet+0x2 in TeensyChallengeSetA.ino.elf (0xe9f))
WARNING | 2019-11-04 11:39:30,998 | angr.state_plugins.symbolic_memory | Filling register r7 with 4 unconstrained bytes referenced from 0xe9f (_Z11challenge_36packet+0x2 in TeensyChallengeSetA.ino.elf (0xe9f))
WARNING | 2019-11-04 11:39:31,000 | angr.state_plugins.symbolic_memory | Filling register lr with 4 unconstrained bytes referenced from 0xe9f (_Z11challenge_36packet+0x2 in TeensyChallengeSetA.ino.elf (0xe9f))
WARNING | 2019-11-04 11:39:31,004 | angr.state_plugins.symbolic_memory | Filling register r0 with 4 unconstrained bytes referenced from 0xea9 (_Z11challenge_36packet+0xc in TeensyChallengeSetA.ino.elf (0xea9))
WARNING | 2019-11-04 11:39:31,006 | angr.state_plugins.symbolic_memory | Filling register r1 with 4 unconstrained bytes referenced from 0xea9 (_Z11challenge_36packet+0xc in TeensyChallengeSetA.ino.elf (0xea9))
WARNING | 2019-11-04 11:39:31,008 | angr.state_plugins.symbolic_memory | Filling register r2 with 4 unconstrained bytes referenced from 0xea9 (_Z11challenge_36packet+0xc in TeensyChallengeSetA.ino.elf (0xea9))
WARNING | 2019-11-04 11:39:31,009 | angr.state_plugins.symbolic_memory | Filling register r3 with 4 unconstrained bytes referenced from 0xea9 (_Z11challenge_36packet+0xc in TeensyChallengeSetA.ino.elf (0xea9))
CARD READ: 40 (<BV32 0x7fff0031>)
CARD READ: 41 (<BV32 0x7fff0032>)
CARD READ: 42 (<BV32 0x7fff0033>)
CARD READ: 43 (<BV32 0x7fff0034>)
CARD READ: 44 (<BV32 0x7fff0035>)
CARD READ: 45 (<BV32 0x7fff0036>)
CARD READ: 46 (<BV32 0x7fff0037>)
CARD READ: 47 (<BV32 0x7fff0038>)
CARD READ: 48 (<BV32 0x7fff0039>)
CARD READ: 49 (<BV32 0x7fff003a>)
CARD READ: 4a (<BV32 0x7fff003b>)
CARD READ: 4b (<BV32 0x7fff003c>)
Print::println(char const*) -  b'solved challenge stairs abcdefg\x03'
Print::println(int) -  3
WARNING | 2019-11-04 11:39:33,305 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 reg_lr_3_32{UNINITIALIZED}>
CARD READ: 0 (2147418097)
!!!!!! BUTTON READ !!!!!!
#     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
p = [
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 0
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 1
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 2
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 3
     [0x4a, 0x5c, 0x4c, 0x3e, 0x36, 0x22, 0x7d, 0x60, 0x6c, 0x64, 0x7c, 0x2e, 0, 0, 0, 0], # 4
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 5
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 6
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 7
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 8
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 9
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # a
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # b
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # c
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # d
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # e
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # f
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 10
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 11
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 12
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 13
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 14
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 15
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 16
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 17
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 18
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 19
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 1a
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 1b
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 1c
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 1d
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 1e
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 1f
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 20
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 21
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 22
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 23
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 24
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 25
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 26
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 27
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 28
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 29
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 2a
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 2b
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 2c
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 2d
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 2e
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 2f
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 30
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 31
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 32
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 33
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 34
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 35
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 36
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 37
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 38
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 39
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 3a
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 3b
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 3c
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 3d
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # 3e
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]] # 3f
a = 0x0
b = 0x0
```

What just happened was that angr loaded the challenge binary (`TeensyChallengeSetA.ino.elf`), created an initial blank state starting at the Stair challenge function, set a known memory region to symbolic (the storage for the RFID card data), executed until the win/end condition, and finally concretized the symbolic table into one that can be uploaded on to the provided RFID card to solve the challenge. For more details on specific challenge solutions, check out the [final report](/export/esc19-final-kernelsanders.pdf?raw=true). Also check out the [all-in-one solver](/final/angresc.py) for individual challenge solutions (they are self-contained).
