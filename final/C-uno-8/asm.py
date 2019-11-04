"""
Grant Hernandez - OISC Assembler
 - Kernel Sanders, CSAW ESC'2019
"""
import argparse

import re
from struct import pack, unpack

class Directive(object):
    def __init__(self):
        self.address = None

class LabelDirective(Directive):
    def __init__(self, name):
        super().__init__()
        self.name = name

class InstructionDirective(Directive):
    def __init__(self, insn):
        super().__init__()
        self.insn = insn

    # size in words
    def getsize(self):
        return 3

class DataDirective(Directive):
    def __init__(self, ty, args):
        super().__init__()
        self.ty = ty
        self.args = args

    # size in words
    def getsize(self):
        return 1

class Assembler(object):
    def __init__(self):
        self.raw_data = ""
        self.label_map = {}
        self.code = None
        self.directives = []

    def assemble(self, raw_data):
        self.directives = []
        self.label_map = {}
        self.code = None
        self.raw_data = raw_data

        # tokenize input
        self._asm_pass_1()
        # resolve label addresses
        self._asm_pass_2()
        # emit machine code
        self._asm_pass_3()

        return self.code

    def _asm_pass_2(self):
        # .origin 0x0
        address = 0

        for directive in self.directives:
            directive.address = address

            if isinstance(directive, LabelDirective):
                pass
            elif isinstance(directive, InstructionDirective):
                address += directive.getsize()
            elif isinstance(directive, DataDirective):
                address += directive.getsize()
            else:
                assert 0

    def _resolve_label(self, label):
        # hex number
        if re.match("[-]?0x[a-fA-F0-9]+", label):
            return int(label, 16)
        # dec number
        elif re.match("[-]?[0-9]+", label):
            return int(label, 10)
        # label
        elif re.match("[_a-zA-Z][_a-zA-Z0-9]*", label):
            if label in self.label_map:
                return self.label_map[label].address
            else:
                print("error: unknown label %s" % label)
                return None
        else:
            print("error: unknown operand %s" % label)
            return None

    def _asm_pass_3(self):
        code = b""

        for directive in self.directives:
            if isinstance(directive, LabelDirective):
                pass
            elif isinstance(directive, InstructionDirective):
                ops = directive.insn
                op1 = self._resolve_label(ops[0])
                op2 = self._resolve_label(ops[1])
                op3 = self._resolve_label(ops[2])

                if op1 is None or op2 is None or op3 is None:
                    return

                code += pack("<b", op2) + pack("<b", op1) + pack("<b", op3)
            elif isinstance(directive, DataDirective):
                op1 = self._resolve_label(directive.args[0])

                if op1 is None:
                    return

                code += pack("<b", op1)
            else:
                assert 0

        self.code = code

    def _asm_pass_1(self):
        lines = self.raw_data.split("\n")
        for line_no, line in enumerate(lines):
            line_no += 1

            tokens = re.split("\s+", line.strip())
            first = tokens[0]

            # blank line or comment
            if (len(tokens) == 1 and first == "") or first == ";":
                continue

            # strip trailing comments
            try:
                found_comment = tokens.index(';')
                tokens = tokens[:found_comment]
            except ValueError:
                pass

            # label
            if re.match('[_a-zA-Z][_a-zA-Z0-9]*:', first):
                label = LabelDirective(first[:-1])

                if label.name in self.label_map:
                    print("error: label %s defined multiple times" % label.name)
                    return

                self.directives += [label]
                self.label_map[label.name] = label
                tokens = tokens[1:]

            # are we done with this line?
            if len(tokens) == 0:
                continue

            if tokens[0] == "subleq":
                operands = [x.strip(",") for x in tokens[1:]]
                insn = InstructionDirective(operands)
                self.directives += [insn]
            elif tokens[0] == "dd":
                operands = [x.strip(",") for x in tokens[1:]]
                data = DataDirective(tokens[0], operands)
                self.directives += [data]
            else:
                print("error: invalid directive %s" % tokens[0])
                return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()

    asm = Assembler()
    print("Assembling " + args.file)
    code = asm.assemble(open(args.file, 'r').read())

    if code is not None:
        stream = ""
        for i in range(len(code)):
            stream += str(unpack("<b", code[i:i+1])[0]) + ", "

        print(stream)
    else:
        print("Error!")

if __name__ == "__main__":
    main()
