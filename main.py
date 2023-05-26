import os
import json
import time
import base64
import requests

from flask import Flask, redirect, request, render_template, send_from_directory
from aes import AES
from ali import Ali

class cryption():
    def decrypt(self, iv, key, content):
        iv_bit = iv.encode()
        key_bit = key.encode()
        cipher = AES(key_bit)
        content_bit = base64.b64decode(content)
        return cipher.decrypt_cbc(content_bit, iv_bit).decode()

    def encrypt(self, iv, key, content):
        iv_bit = iv.encode()
        key_bit = key.encode()
        cipher = AES(key_bit)
        content_bit = cipher.encrypt_cbc(content.encode(), iv_bit)
        content_str = base64.b64encode(content_bit).decode()
        return content_str

app = Flask(__name__)
@app.route('/')
def web():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'templates'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/token')
def token():
    tokenDict = {}
    iv = request.args.get('iv')
    key = request.args.get('key')
    if not iv:
        iv = ''
    if not key:
        key = ''
    if len(iv) < 16:
        iv = iv.rjust(16, '0')
    else:
        iv = iv[:16]
    if len(key) < 16:
        key = key.rjust(16, '0')
    else:
        key = key[:16]
    try:
        refresh = request.args.get('refresh')
        delFile = request.args.get('delFile')
        if delFile:
            delFile = True
        else:
            delFile = False
        if refresh:
            refresh = True
        else:
            refresh = False
        alicache = requests.get('http://127.0.0.1:8888/cache', params={'key': 'alicache'}).text
        if alicache != '' and not refresh:
            enc_tokenDict = json.loads(alicache)
            if enc_tokenDict['expires_at'] > int(time.time()):
                tokenDict = {}
                for tkey in enc_tokenDict:
                    if tkey == 'expires_at':
                        tokenDict[tkey] = enc_tokenDict[tkey]
                        continue
                    tokenDict[tkey] = cryption().decrypt(iv, key, enc_tokenDict[tkey])
        else:
            with open('content.txt', 'r') as file:
                content = file.read()
            if content == '':
                return redirect('/submit')
            tokenDict = Ali().refresh_token(cryption().decrypt(iv, key, content), delFile)
            if tokenDict == {}:
                return redirect('/submit')
            enc_tokenDict = {}
            for tkey in tokenDict:
                if tkey == 'expires_at':
                    enc_tokenDict[tkey] = tokenDict[tkey]
                    continue
                enc_tokenDict[tkey] = cryption().encrypt(iv, key, tokenDict[tkey])
            value = json.dumps(enc_tokenDict).encode()
            requests.post('http://127.0.0.1:8888/cache', params={'key': 'alicache'}, data=value, headers={'Content-Length': str(len(value))})
        display = request.args.get('display')
        if not display:
            display = 'token'
        if display == 'all':
            return json.dumps(tokenDict)
        elif display not in ['all', 'token', 'authorization', 'opentoken', 'opauthorization', 'user_id', 'drive_id']:
            return tokenDict['token']
        else:
            return tokenDict[display]
    except:
        return redirect('/submit')

@app.route('/process', methods=['POST'])
def process():
    iv = request.form.get('iv')
    key = request.form.get('key')
    if not iv:
        iv = ''
    if not key:
        key = ''
    if len(iv) < 16:
        iv = iv.rjust(16, '0')
    else:
        iv = iv[:16]
    if len(key) < 16:
        key = key.rjust(16, '0')
    else:
        key = key[:16]
    token = request.form.get('token')
    content_str = cryption().encrypt(iv, key, token)
    with open('content.txt', "w") as file:
        file.write(content_str)
    domain = request.host_url[:-1]
    message = '请牢记你的iv与key。'
    show_token = '加密后token为：{}'.format(content_str)
    get_token = '{}/token?iv={}&key={}'.format(domain, request.form.get('iv'), request.form.get('key'))
    get_all = '{}/token?iv={}&key={}&display=all'.format(domain, request.form.get('iv'), request.form.get('key'))
    force_refresh = '{}/token?iv={}&key={}&refresh=True'.format(domain, request.form.get('iv'), request.form.get('key'))
    del_file = '{}/token?iv={}&key={}&delFile=True'.format(domain, request.form.get('iv'), request.form.get('key'))
    return render_template('result.html', message=message, show_token=show_token, get_token=get_token, get_all=get_all, force_refresh=force_refresh, del_file=del_file)


@app.route('/submit')
def submit():
    return render_template('cryption.html')

data = {}
@app.route('/cache', methods=['POST', 'PUT', 'GET', 'DELETE'])
def cache():
    methods = request.method
    key = request.args.get('key')
    if methods in ['POST', 'PUT']:
        body = request.data
        data[key] = body
        return body
    elif methods == 'GET':
        if key in data:
            return data[key]
        else:
            return ''
    else:
        data[key] = ''
        return ''

if __name__ == '__main__':
    app.run(host="0.0.0.0", threaded=True, port=8888)
