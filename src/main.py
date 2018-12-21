import os
import tempfile

import time
from flask import Flask, request, flash, redirect
from flask_session import Session
from werkzeug.utils import secure_filename
import zipfile

from src.extractor import Extractor
from src.r2instance import R2Instance

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk'}

r2instance = None
extractor = Extractor()
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
    return open('page.html', 'r').read()


def process_file(path):
    r2instance = extract_zip(path)
    values = r2instance.extract_instructions()
    del r2instance
    return extractor.extract_key(values)


def extract_zip(path):
    archive = zipfile.ZipFile(path)

    unzip_directory = os.path.join(UPLOAD_FOLDER, str(time.time()))
    for file in archive.namelist():
        if file.startswith('lib/') and file.find('x86') != -1:
            extracted_file = os.path.join(unzip_directory, archive.extract(file, unzip_directory))
            print(extracted_file)
            with R2Instance(extracted_file) as r2instance:
                if r2instance.is_correct_binary:
                    return r2instance
                else: del r2instance


Flask.run(app)