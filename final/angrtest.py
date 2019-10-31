import angr
import re
import argparse
import sys

from struct import pack
from IPython import embed
from multiprocessing import Pool

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

    def check_cafe_hook(self, state):
        print(state)
        self.check_cafe_solve(state)
        embed()
        state.regs.pc = state.regs.lr

    def check_cafe_solve(self, state):
        fixed = 'solved challenge cafe abcdefg'

        for i in range(len(fixed)):
            state.solver.add(state.memory.load(state.regs.r1+i, 1) == ord(fixed[i]))

        strout = self.read_string(state, state.regs.r1)
        print(repr(strout))

        self.print_table(state)

    def solve_cafe(self):
        self._set_start_symbol("_Z11challenge_26packet")
        addr = self.sym.linked_addr

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::println"):
                self.proj.hook(i.linked_addr, self.check_cafe_hook)
                print("Check Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))
            elif i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))

        st = self.proj.factory.blank_state()
        st.regs.pc = addr
        st.options.add('SYMBOL_FILL_UNCONSTRAINED_MEMORY')
        self.hook_card_read(st)

        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Veritesting())

        mgr.run()

    def solve_closet(self):
        self._set_start_symbol("_Z11challenge_16packet")
        addr = self.sym.linked_addr

        self._hook_prints()
        st = self._get_start_state(addr, ['ZERO_FILL_UNCONSTRAINED_MEMORY', angr.options.LAZY_SOLVES])

        # 5c - 6f, 80 - 83
        key = b"ESC19-rocks!"

        st.memory.store(WHITE_CARD_START_ADDR, b"\x00"*WHITE_CARD_SZ)#st.solver.BVS('select%d' % i, 8))
        for i in range(0xc):
            #sym = st.solver.BVS("first_%d" % i, 1*8)
            #st.memory.store(WHITE_CARD_START_ADDR+0x5c+i, sym)
            #st.solver.add(sym >= 0xc)
            #st.solver.add(sym <= 40)
            if i < 0x8:
                st.memory.store(WHITE_CARD_START_ADDR+0x5c+i, pack("<b", 0x18+i))
            else:
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

        st.memory.store(WHITE_CARD_START_ADDR+0x4c, st.solver.BVS("input", 16))#b"\xff\xff")

        #st.options |= set([angr.options.FAST_MEMORY, angr.options.FAST_REGISTERS])

        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0xc20,0xc21], avoid=[0xc50,0xc51]))

        mgr.run(n=4)

        def gather_results(omgr):
            mgr.active += omgr[0]
            mgr.found += omgr[1]

        import time

        pool = Pool(processes=40)

        while not mgr.found:
            print(mgr)
            #res = pool.map(self.exec_once, mgr.active)

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
            output += ["     " + str(row) + ("%s # %x" % (eol, i))]

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
        st.options |= set(['SYMBOL_FILL_UNCONSTRAINED_MEMORY'])
        st.regs.pc = addr
        self.hook_card_read(st)
        mgr = self.proj.factory.simgr(st)
        mgr.explore(find=[0x1823])
        #mgr.use_technique(angr.exploration_techniques.DFS())

        #st.memory.store(WHITE_CARD_START_ADDR+0x9b, "L")

        #mgr.active[0].solver.eval(mgr.active[0].memory.load(mgr.active[0].regs.r7, 32), cast_to=bytes)
        #Out[54]: b'solved           mobile abcdefg\x00'

        #In [55]: mgr.active[0].regs.r7
        #Out[55]: <BV32 0x7ffeff18>

        # Nothing should be unconstrained as we assign it
        target = bytes("solved challenge mobile abcdefg\x00", "ascii")

        assert len(mgr.found) == 1
        st = mgr.found[0]

        for i in range(len(target)):
            symb = st.solver.BVS('target%d' % i, 8)
            st.memory.store(0x7ffeff18+i, symb)
            st.solver.add(symb == target[i])

        mgr.move('found', 'active')
        mgr.run(n=1)

        def gather_results(omgr):
            mgr.active += omgr[0]
            mgr.found += omgr[1]

        import time

        pool = Pool(processes=40)

        while not mgr.found:
            print(mgr)
            #res = pool.map(self.exec_once, mgr.active)

            if len(mgr.active) == 0:
                time.sleep(10)
                continue

            active_st = mgr.active.copy()
            mgr.drop(stash='active')
            print("Distributing %d states" % len(active_st))
            for a in active_st:
                pool.apply_async(self.exec_once, args=(a,), callback=gather_results)

        embed()

        found = False
        trynumber = 0
        while not found:
            mgr.explore(find=[0x18fe, 0x18ff])

            print("Try %d" % trynumber)
            trynumber += 1

            for s in mgr.found:
                for i in range(len(target)):
                    symb = s.memory.load(0x7ffeff18+i, 1)
                    s.solver.add(symb == target[i])

                if s.solver.satisfiable():
                    print("yes")
                    self.print_table(s)
                    found = True
                    break

            mgr.move('found', 'found_next')

    def solve_break(self):
        self._set_start_symbol("_Z12challenge_106packet")
        addr = self.sym.linked_addr

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))

        st = self.proj.factory.blank_state()
        st.regs.r0 = st.regs.r1 = st.regs.r2 = st.regs.r3 = 0
        st.regs.r4 = st.regs.r5 = st.regs.r6 = st.regs.r7 = 0
        st.regs.r8 = st.regs.r9 = st.regs.r10 = st.regs.r11 = 0
        st.regs.r12 = 0
        st.options |= set(['SYMBOL_FILL_UNCONSTRAINED_MEMORY'])
        st.regs.pc = addr

        self.hook_card_read(st)

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

    def _hook_prints(self):

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))
            elif i.demangled_name.startswith("delay"):
                self.proj.hook(i.linked_addr, ESCAngr.no_op)
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
        st.regs.lr = 0x8d0
        mgr = self.proj.factory.simgr(st)
        #mgr.use_technique(angr.exploration_techniques.Veritesting())
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0x876, 0x877], avoid=[0x874,0x875]))
        st.memory.store(WHITE_CARD_START_ADDR, b"\x00"*WHITE_CARD_SZ)#st.solver.BVS('select%d' % i, 8))

        target_pc = self.obj.symbols_by_name["_Z17fillChallengeHashv"].linked_addr
        print("[+] Exploit target PC %08x" % target_pc)

        payload = b"\x00"*12 + pack("<I", 12) + b"\x00\x00\x00\x00" + pack("<I", target_pc)

        st.memory.store(WHITE_CARD_START_ADDR, b"\x00"*WHITE_CARD_SZ)
        # for each bit that is set, read a byte from the payload
        st.memory.store(WHITE_CARD_START_ADDR+0x100, b"\xff"*3)
        st.memory.store(WHITE_CARD_START_ADDR+0xc0, payload)

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

challenges = {
    "A" : ["stairs", "cafe", "closet", "lounge"],
    "B" : ["dance", "code", "mobile"],
    "C" : ["uno", "break", "recess", "game"],
    "D" : ["bounce"],
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('challenge')

    args = parser.parse_args()
    chalname = args.challenge
    tokens = chalname.split("-")

    chset = tokens[0]
    name = tokens[1]

    if chset in ["A", "B", "C", "D", "E", "F"]:
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
