import os, time
import shutil, zipfile, jodel_api, tempfile

from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
from magic import magic
from r2instance import R2Instance
from decrypt import decrypt
from apkverify import ApkSignature
from pyaxmlparser import APK

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk'}
JODEL_CERTIFICATE = [b'-----BEGIN CERTIFICATE-----\nMIIDYTCCAkmgAwIBAgIEMb0w6zANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJE\nRTEPMA0GA1UECBMGQmVybGluMQ8wDQYDVQQHEwZCZXJsaW4xDjAMBgNVBAoTBXRl\nbGxNMRAwDgYDVQQLEwdBbmRyb2lkMQ4wDAYDVQQDEwV0ZWxsTTAeFw0xNDA0MDMx\nOTAzMjVaFw00MTA4MTkxOTAzMjVaMGExCzAJBgNVBAYTAkRFMQ8wDQYDVQQIEwZC\nZXJsaW4xDzANBgNVBAcTBkJlcmxpbjEOMAwGA1UEChMFdGVsbE0xEDAOBgNVBAsT\nB0FuZHJvaWQxDjAMBgNVBAMTBXRlbGxNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAnE4nlpDzirbpQxzz1m46lSIdyv1HfgpxtsD1jgc6Le24TT7qfase\nGsheUjvpwl680lrR6H2KJT1beR+WIRAgqyUOWT08y9yRU+Gql+kh7zNXRf/H9UfF\n2qamVjq3/piBlQZgYmJuSkVAIFDOPk2f3x8WhID5nN4E+Qa2n/M2kN2GmhDX7j5q\nk1F1/V8lgsz+WdIVj9Z/rNcA5whmDbS3gYmzf2qrpODHf84Ns1fh9ip3WZAzQO3J\nspQB5OZA64w4n15/FjJSl86nHz0OpZ1dGJ4i7arc8ljmH4TzlgktX6GVLgqTtTVR\ncZh7qdMEJtiBNFR2Zav6z05K03RP3C/BUwIDAQABoyEwHzAdBgNVHQ4EFgQU0kzF\ntcTfHGyOuM6xuhVmGcI6AwEwDQYJKoZIhvcNAQELBQADggEBAC91lekfq5MNqlDB\nT/OrDBTHhX6xHtMfTIpO4jmNEyPrnGyKWW/CWP3qodX7RYEZ20l/ydKj0r2zDkW5\nLQaG4kTr7YMDzAZZwyq2txqqxrOj6ssfl0B8JQgiGG38bPQGucy2Q0NJBbkNTVOI\nG496IFaPe1RcjtONvMSdRsBXt+90RFER3pMRYYYqy79SjAZrRF0C5KLwONfhFo7f\ni29Lf0uMFYaE4jOpD8kwLiFpdMbLjGhvdziQVAybChf8H0xw8jKRNED7L/axC1q0\n8HNW5OCI4JuQIvcf6BPxAIepo0mnNZVSYR9MHZrMI3qFDzAAuyuJk5y5ZMVgJqBU\n8DZbptk=\n-----END CERTIFICATE-----\n']

app = Flask(__name__, static_url_path="/static", static_folder="../frontend-dist")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('static', filename='index.html'))

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
        return jodel_api.json.dumps(process_file(filepath))

    else:
        return {'error':True, 'message': 'File type not allowed!'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def gather_apk_information(apk_file_path):
    try:
        apk = APK(apk_file_path)
        sign = ApkSignature(apkpath=apk_file_path)
        is_jodel_signature = False
        verify = False
        if sign.is_sigv2():
            verify = sign.verify(2)
            if sign.get_certs() == JODEL_CERTIFICATE:
                is_jodel_signature = True
        return {'package': apk.package, 'version_name': apk.version_name,
                'version_code': apk.version_code, 'signature_verified': verify,
                'is_jodel_signature': is_jodel_signature, 'certs': str(sign.get_certs())}
    except:
        return 'Failed verifying APK file'

def process_file(apk_file_path):
    apk_information = gather_apk_information(apk_file_path)
    if apk_information and apk_information['is_jodel_signature']:
        r2instance, unzip_directory = extract_zip(apk_file_path)
        clean_up_mess(apk_file_path, unzip_directory)
        if r2instance is None:
            return {'error':True, 'message': 'Library file not found, exiting...'}
        apk_information['hmac_key'] = decrypt(r2instance.extract_bytes()).decode("utf-8")
        apk_information['key_status'] = is_key_working(apk_information['hmac_key'], apk_information['version_name'])
        apk_information['error'] = False
        apk_information['message'] = 'Successfully extracted key!'
        return apk_information
    else:
        return {'error':True, 'message': apk_information}


def clean_up_mess(apk_file_path, extracted_file_path):
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
                _r2instance = R2Instance(extracted_file)
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

