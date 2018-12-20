import os
from ctypes import ARRAY, c_uint8, c_char_p, CDLL

import r2pipe
import tempfile

import time
from flask import Flask, request, flash, redirect
from werkzeug.utils import secure_filename
import zipfile

PATH = "C:\\Users\\Admin\\Downloads\\liba.so"
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk'}
SIGNATURE  = "a4a8d4d7b09736a0f65596a868cc6fd620920fb0"
CRYPTTABLE_SIZE = 256
FUNCTION_PATTERN = 'HmacInterceptor_init'
CLIENT_SECRET_SIZE = 40
INSTRUCTION_PATTERN = 'MOV'

decrypt = CDLL(os.path.dirname(os.path.abspath(__file__)) + '\decrypt.dll')
decrypt.decrypt.argtypes = [ARRAY(c_uint8, CLIENT_SECRET_SIZE)]
decrypt.decrypt.restype = c_char_p

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            library_file = extract_shit(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            instructions = extract_instructions(library_file)
            return extract_kex(instructions)
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

def extract_kex(instructions):
    key = scrapeKey(instructions)
    if str([key[x:x + 2] for x in range(0, len(key), 2)]) == "[]":
        print('Failed, trying to scrape key using method two...')
        key = scrapeKey_2(instructions)
        if str([key[x:x + 2] for x in range(0, len(key), 2)]) == "[]":
            print('Failed scraping key, exiting...')

            exit()

    print('Derived key of length {} from library, now decrypting it...'.format(len(key)))

    print('Key: {}'.format([key[x:x + 2] for x in range(0, len(key), 2)]))
    c_array_key = (c_uint8 * len(key))(*key)
    _result = decrypt.decrypt(c_array_key)
    print('Decryption successfull, key: {}'.format(_result))
    return _result

def extract_shit(path):
    archive = zipfile.ZipFile(path)

    unzip_directory = os.path.join(UPLOAD_FOLDER, str(time.time()))
    for file in archive.namelist():
        if file.startswith('lib/') and file.find('x86') != -1:
            extracted_file = os.path.join(unzip_directory, archive.extract(file, unzip_directory))
            if is_correct_file(extracted_file):
                return extracted_file


def is_correct_file(file):
    r = r2pipe.open(file, radare2home="C:\\Users\\Admin\\AppData\\Local\\Programs\\radare2")
    func = r.cmd("aa; afl").split('\r\n')
    for f in func:
        if 'HmacInterceptor_init' in f:
            return True

    return False

def extract_instructions(path):
    instructions = []
    function_name = ''

    r = r2pipe.open(path, radare2home="C:\\Users\\Admin\\AppData\\Local\\Programs\\radare2")
    func = r.cmd("aa; afl").split('\r\n')
    for f in func:
        if 'HmacInterceptor_init' in f:
            function_name = f[f.find('          '):].strip()

    r.cmd("s {}".format(function_name))
    disasm = [_d for _d in [d for d in r.cmd("pdf").split('\r') if "mov" in d] if 'eax' in _d]
    for d in disasm:
        start_idx = d.find(',') + 2
        end_idx = len(d)
        if d.find(";") != -1:
            end_idx = d.find(";")

        instructions += d[start_idx:end_idx].strip()

    return instructions


def scrapeKey(assembler_code):
    key = ''
    tmp = ''

    for disasm in assembler_code:
        begin_value = disasm.find(',') + 3
        if disasm.find(';') != -1:
            value = disasm[begin_value: disasm.find(';')].replace('h', '').strip()
        else:
            value = disasm[begin_value:].replace('h', '').strip()

        value = value.replace('0x', '')
        # print 'length of {}: {}'.format(value, len(value))
        if (len(value) != 2 or len(value) != 8) and value.startswith('0'):
            # print 'value too long: {} stripping to {}'.format(len(value), value[1:])
            value = value[1:]
        elif 8 > len(value) > 2:
            value = '0' + value
        # print 'value too small, appending leading 0: {}'.format(value)
        elif len(value) == 1:
            value = '0' + value

        if tmp == '':
            tmp = value
        else:
            key += rev(value.strip()) + tmp.strip()
            tmp = ''

    if len(key) % 2 != 0:
        key = key[:-1]
    keyarray = [int(key[x:x + 2], 16) for x in range(0, len(key), 2)]

    # print 'Derived key of length {} from library, now decrypting it...'.format(len(keyarray))
    # print 'Key: {}'.format([key[x:x+2] for x in range(0, len(key),2)])

    return keyarray


def scrapeKey_2(assembler_code):
    key = ''
    tmp = ''

    for disasm in assembler_code:
        begin_value = disasm.find(',') + 1
        if disasm.find(';') != -1:
            value = disasm[begin_value: disasm.find(';')].replace('h', '').strip()
        else:
            value = disasm[begin_value:].replace('h', '').strip()

        # print 'length of {}: {}'.format(value, len(value))
        if (len(value) != 2 or len(value) != 8) and value.startswith('0'):
            # print 'value too long: {} stripping to {}'.format(len(value), value[1:])
            value = value[1:]
        elif 8 > len(value) > 2:
            value = '0' + value
        # print 'value too small, appending leading 0: {}'.format(value)

        if tmp == '':
            tmp = value
        else:
            key += rev(value.strip()) + tmp.strip()
            tmp = ''

    if len(key) % 2 != 0:
        key = key[:-1]
    keyarray = [int(key[x:x + 2], 16) for x in range(0, len(key), 2)]

    # print 'Derived key of length {} from library, now decrypting it...'.format(len(keyarray))
    # print 'Key: {}'.format([key[x:x+2] for x in range(0, len(key),2)])

    return keyarray


def rev(a):
    new = ""
    for x in range(-1, -len(a), -2):
        new += a[x - 1] + a[x]

    return new
#for d in disasm: print(d)

Flask.run(app)