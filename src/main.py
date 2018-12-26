import os
import tempfile

import time

import jodel_api
from flask import Flask, request, flash, redirect
from flask_session import Session
from werkzeug.utils import secure_filename
import zipfile

import decrypt
from aapt import Aapt
from r2instance import R2Instance

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk'}

r2instance = None
aapt = Aapt()
uploaded_file = None
zip_directory = None

app = Flask(__name__)
# Check Configuration section for more details
SESSION_TYPE = 'null'
app.config.from_object(__name__)
sess = Session(app)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload():
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
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return process_file(filepath)
        else:
            flash('File type not allowed, please upload a APK')
            return redirect(request.url)
    return open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files/static/html/page.html'), 'r').read()


def process_file(path):
    retval = aapt.get_apk_info(path)
    retval['hmac_key'] = decrypt.decrypt(extract_zip(path).extract_bytes()).decode("utf-8")
    retval['key_status'] = is_key_working(retval['hmac_key'], retval['version']['name'])
    return jodel_api.json.dumps(retval, sort_keys=True, indent=4)


def extract_zip(path):
    with zipfile.ZipFile(path) as archive:
        unzip_directory = os.path.join(UPLOAD_FOLDER, str(time.time()))
        for file in archive.namelist():
            if file.startswith('lib/') and file.find('x86') != -1:
                extracted_file = os.path.join(unzip_directory, archive.extract(file, unzip_directory))
                with R2Instance(extracted_file) as _r2instance:
                    if _r2instance.is_correct_binary:
                        return _r2instance
                    else: del _r2instance


def is_key_working(key, version):
    try:
        lat, lng, city = 48.148435, 11.567866, "Munich"
        j = jodel_api.JodelAccount(lat=lat, lng=lng, city=city, _secret=key, _version=version)
        return {'working':True, 'account':j.get_account_data()}
    except:
        return {'working':False}


Flask.run(app)