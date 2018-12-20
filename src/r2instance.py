import r2pipe


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

    def __del__(self):
        self.r2.quit()

    def get_method_name(self):
        func = self.r2.cmd('afl').split('\r\n')
        for f in func:
            if 'HmacInterceptor_init' in f:
                return f[f.find('          '):].strip()

        return None

    def extract_instructions(self):
        instructions = []

        disasm = [__d.replace('0x', '') for __d in
                    [_d for _d in [d for d in self.r2.cmd("s {}; pdf".format(self.function_name)).split('\r') if "mov" in d] if 'eax' in _d]]
        for d in disasm:
            start_idx = d.find(',') + 2
            end_idx = len(d)
            if d.find(";") != -1:
                end_idx = d.find(";")

            instructions.append(d[start_idx:end_idx].strip())

        return instructions

