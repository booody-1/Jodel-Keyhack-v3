import r2pipe
import re


class R2Instance:
    def __init__(self, path):
        self.r2 = r2pipe.open(path, radare2home="C:\\Users\\Admin\\AppData\\Local\\Programs\\radare2")
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
        func = self.r2.cmd('afl').split('\r\n')
        for f in func:
            if 'HmacInterceptor_init' in f:
                return f[f.find('          '):].strip()

        return None

    def extract_instructions(self):
        instr = []
        # https://memegenerator.net/img/instances/75909642/how-does-this-even-work.jpg
        [instr.append(re.search('(?<=, )\w+', ___d).group(0)) for ___d in [__d.replace('0x', '') for __d in
                [_d for _d in [d for d in self.r2.cmd("s {}; pdf".format(self.function_name)).split('\r') if "mov" in d] if 'eax' in _d]]]
        return instr

