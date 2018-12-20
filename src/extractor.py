from ctypes import ARRAY, c_uint8, c_char_p, CDLL
import os

CLIENT_SECRET_SIZE = 40

decrypt = CDLL(os.path.dirname(os.path.abspath(__file__)) + '\decrypt.dll')
decrypt.decrypt.argtypes = [ARRAY(c_uint8, CLIENT_SECRET_SIZE)]
decrypt.decrypt.restype = c_char_p

class Extractor:
    def __init__(self):
        pass

    def extract_key(self, instructions):
        key = self.method1(instructions)
        if str([key[x:x + 2] for x in range(0, len(key), 2)]) == "[]":
            print('Failed, trying to scrape key using method two...')
            key = self.method2(instructions)
            if str([key[x:x + 2] for x in range(0, len(key), 2)]) == "[]":
                print('Failed scraping key, exiting...')

                exit()

        print('Derived key of length {} from library, now decrypting it...'.format(len(key)))

        print('Key: {}'.format([key[x:x + 2] for x in range(0, len(key), 2)]))
        c_array_key = (c_uint8 * len(key))(*key)
        _result = decrypt.decrypt(c_array_key)
        print('Decryption successfull, key: {}'.format(_result))
        return _result

    def method1(self, assembler_code):
        key = ''
        tmp = ''

        for disasm in assembler_code:
            print(disasm)

            value = disasm.replace('0x', '')
            # print 'length of {}: {}'.format(value, len(value))
            print('length of {}: {}'.format(value, len(value)))
            if (len(value) != 2 or len(value) != 8) and value.startswith('0'):
                print('value too long: {} stripping to {}'.format(len(value), value[1:]))
                value = value[1:]
            elif 8 > len(value) > 2:
                value = '0' + value
                print('value too small, appending leading 0: {}'.format(value))
            elif len(value) <= 1:
                value = '0' + str(value)
                print('value too small, appending leading 0: {}'.format(value))

            if tmp == '':
                tmp = value
            else:
                key += self.rev(value.strip()) + tmp.strip()
                tmp = ''

        if len(key) % 2 != 0:
            key = key[:-1]
        keyarray = [int(key[x:x + 2], 16) for x in range(0, len(key), 2)]

        print('Derived key of length {} from library, now decrypting it...'.format(len(keyarray)))
        print('Key: {}'.format([key[x:x + 2] for x in range(0, len(key), 2)]))

        return keyarray

    def method2(self, assembler_code):
        key = ''
        tmp = ''

        for byte in assembler_code:
            print('length of {}: {}'.format(byte, len(byte)))
            if (len(byte) != 2 or len(byte) != 8) and byte.startswith('0'):
                print('value too long: {} stripping to {}'.format(len(byte), byte[1:]))
                byte = byte[1:]
            elif 8 > len(byte) > 2:
                byte = '0' + byte
            print('value too small, appending leading 0: {}'.format(byte))

            if tmp == '':
                tmp = byte
            else:
                key += self.rev(byte.strip()) + tmp.strip()
                tmp = ''

        if len(key) % 2 != 0:
            key = key[:-1]
        keyarray = [int(key[x:x + 2], 16) for x in range(0, len(key), 2)]

        print('Derived key of length {} from library, now decrypting it...'.format(len(keyarray)))
        print('Key: {}'.format([key[x:x + 2] for x in range(0, len(key), 2)]))

        return keyarray

    def rev(self, a):
        new = ""
        for x in range(-1, -len(a), -2):
            new += a[x - 1] + a[x]

        return new