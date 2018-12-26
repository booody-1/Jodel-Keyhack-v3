from collections import OrderedDict

import r2pipe
import re

R2_LIST_FUNCTIONS = 'afl'
R2_DISASSEMBLE_INSTRUCTIONS = 's {}; pi 25'

REGEX_EXTRACT_BYTES = r'(?<=[^ ] )\d\w*'
REGEX_FIND_FUNCTIONS = r'sym.\w+Hmac\w+init'

def rev(a):
    new = ""
    for x in range(-1, -len(a), -2):
        new += a[x - 1] + a[x]

    return new

class R2Instance:
    def __init__(self, path):
        self.r2 = r2pipe.open(path)
        self.r2.cmd('aa')
        self.is_correct_binary = False


        method_name = self.get_method_name()
        if method_name is not None:
            print("Correct binary is {}".format(path))
            self.is_correct_binary = True
            self.function_name = method_name

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def __del__(self):
        self.r2.quit()

    def get_method_name(self):
        func = self.r2.cmd(R2_LIST_FUNCTIONS).split('\r\n')
        regexp = re.compile(REGEX_FIND_FUNCTIONS)
        for f in func:
            reg_res = regexp.search(f)
            if reg_res:
                return reg_res.group(0)

        return None

    def extract_bytes(self):
        instr = {}
        # https://memegenerator.net/img/instances/75909642/how-does-this-even-work.jpg
        instructions = [d for d in self.r2.cmd(R2_DISASSEMBLE_INSTRUCTIONS.format(self.function_name)).split('\r') if 'mov' in d and 'eax' in d]
        for i in instructions:
            matches = re.findall(REGEX_EXTRACT_BYTES, i)
            value = matches[1].replace('0x','').strip()
            if len(value) <= 1 or (8 > len(value) > 2): value = '0' + value
            if len(value) > 8 and value.startswith('0'): value = value[1:]
            instr[int(matches[0], 0)] = rev(value)

        return [int(''.join(OrderedDict(sorted(instr.items())).values())[x:x + 2], 16) for x in range(0, decrypt.CLIENT_SECRET_SIZE*2, 2)]

