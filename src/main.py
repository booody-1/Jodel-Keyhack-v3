import os
import tempfile

import time

import jodel_api
import shutil
from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
import zipfile
from magic import magic

import decrypt
from aapt import Aapt
from r2instance import R2Instance

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk'}

app = Flask(__name__, static_url_path="/",
            static_folder="../frontend-dist")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('static', filename='static/index.html'))


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return process_file(filepath)
    else:
        return 'File type not allowed, please upload a APK'


def is_file_valid(file_path):
    _magic = magic.Magic(mime=magic.MAGIC_MIME)
    print(_magic.from_file(file_path))
    if _magic.from_file(file_path) != 'application/zip':
        print(_magic.from_file(file_path))
        return False
    if not _magic:
        del _magic

    return True


def process_file(apk_file_path):
    if not is_file_valid(apk_file_path):
        return 'File not valid.'
    r2instance, unzip_directory = extract_zip(apk_file_path)
    jodel_info = Aapt().get_apk_info(apk_file_path)
    clear_up_mess(apk_file_path, unzip_directory)
    if r2instance is None:
        return 'Library file not found, exiting...'
    jodel_info['hmac_key'] = decrypt.decrypt(
        r2instance.extract_bytes()).decode("utf-8")
    jodel_info['key_status'] = is_key_working(
        jodel_info['hmac_key'], jodel_info['version']['name'])
    return jodel_api.json.dumps(jodel_info, sort_keys=True, indent=4)


def clear_up_mess(apk_file_path, extracted_file_path):
    try:
        if apk_file_path and os.path.isfile(apk_file_path):
            os.remove(apk_file_path)
            print('Removed APK file')

        if extracted_file_path and os.path.isdir(extracted_file_path):
            shutil.rmtree(extracted_file_path)
            print('Removed extracted files')
    except:
        print('failed to remove files')


def extract_zip(path):
    with zipfile.ZipFile(path) as archive:
        unzip_directory = os.path.join(UPLOAD_FOLDER, str(time.time()))
        for file in archive.namelist():
            if file.startswith('lib/') and file.find('x86') != -1:
                extracted_file = os.path.join(
                    unzip_directory, archive.extract(file, unzip_directory))
                with R2Instance(extracted_file) as _r2instance:
                    print(magic.from_file(extracted_file, mime=True))
                    if _r2instance.is_correct_binary and magic.from_file(extracted_file, mime=True) == 'application/x-sharedlib':
                        return _r2instance, unzip_directory
                    else:
                        del _r2instance

    return None, unzip_directory


def is_key_working(key, version):
    try:
        lat, lng, city = 48.148435, 11.567866, "Munich"
        j = jodel_api.JodelAccount(
            lat=lat, lng=lng, city=city, _secret=key, _version=version)
        return {'working': True, 'account': j.get_account_data()}
    except:
        return {'working': False}


if __name__ == '__main__':
    Flask.run(app)
