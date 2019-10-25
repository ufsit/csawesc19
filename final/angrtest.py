import angr
import re
from IPython import embed

class ESCAngr(object):
    def __init__(self, path, function):
        self.proj = angr.Project(path)

        self.obj = self.proj.loader.main_object
        self.sym = self.obj.symbols_by_name[function]

    def solve_stairs(self):
        print("Solving " + self.sym.demangled_name)
        addr = self.sym.linked_addr

        #b = proj.factory.block(addr)
        #b.pp()

        for i in self.obj.symbols:
            if i.demangled_name.startswith("Print::print"):
                self.proj.hook(i.linked_addr, self.print_hook)
                print("Hooked %s (0x%08x)" % (i.demangled_name, i.linked_addr))

        st = self.proj.factory.blank_state()
        st.regs.pc = addr
        st.options.add('SYMBOL_FILL_UNCONSTRAINED_MEMORY')

        mgr = self.proj.factory.simgr(st)
        mgr.use_technique(angr.exploration_techniques.Explorer(find=[0xf60,0xf61], avoid=[0xf84,0xf85,0xf38,0xf39]))

        mgr.run()

        s = mgr.found[0]
        mgr_final = self.proj.factory.simgr(s)
        mgr_final.run()

        table = s.solver.eval(s.memory.load(0x7fff0000-0xf, 0x10*0x64), cast_to=bytes)
        self.print_table(table)

        #embed()

    def print_table(self, table):
        arr = []
        for i in range(64):
            arr += [[c for c in table[i*16:(i+1)*16]]]

        print(arr)
            
    def print_hook(self, state):
        s = self.obj.loader.find_symbol(state.solver.eval(state.regs.pc))
        match = re.search(r':([a-zA-Z]*)\(([^)]*)\)', s.demangled_name)
        fn = match.group(1)
        ty = match.group(2)

        ARG1 = state.regs.r1
        print("print called")

        if fn == "print":
            print("Unhandled", fn, ty)
        elif fn == "println":
            if ty == "char const*":
                val = None
                strout = bytes()
                i = 0
                while True:
                    val = state.mem[ARG1+i].char.concrete
                    i += 1
                    if ord(val) == 0:
                        break
                    strout += val

                print(repr(strout))
            elif ty == "int":
                print(state.solver.eval(ARG1))
            else:
                print("Unhandled", fn, ty)
        else:
            print("Unhandled fn " + fn)

        state.regs.pc = state.regs.lr

def main():
    esc = ESCAngr("A/TeensyChallengeSetA.ino.elf", "_Z11challenge_36packet")
    esc.solve_stairs()

if __name__ == "__main__":
    main()
