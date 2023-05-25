import re
import json
import base64
import requests

from flask import Flask, request, render_template
from aes import AES
from ali import Ali

app = Flask(__name__)
@app.route('/')
def web():
    return render_template('index.html')

@app.route('/token', methods=['POST', 'GET'])
def token():
    iv = request.args.get('iv')
    key = request.args.get('key')
    if not iv:
        iv = 'd4Gf87Ls9KjP2m6q'
    if not key:
        key = 'h8Nt5eR1zXcVb3Wf'
    try:
        if request.method == 'GET':
            token = decrypt(iv, key)
            delFile = request.args.get('delFile')
            if delFile:
                delFile = True
            else:
                delFile = False
            tokenDict = Ali().refresh_token(token, delFile)
            encrypt(iv, key, tokenDict['token'])
            display = request.args.get('display')
            if not display:
                display = 'token'
            if display == 'all':
                return json.dumps(tokenDict)
            elif display not in ['all', 'token', 'authorization', 'opentoken', 'opauthorization', 'user_id', 'drive_id']:
                return json.dumps(tokenDict['token'])
            else:
                return json.dumps(tokenDict[display])
        else:
            token = request.args.get('token')
            return encrypt(iv, key, token)
    except:
        return ''

def decrypt(iv, key):
    iv_bit = iv.encode()
    key_bit = key.encode()
    cipher = AES(key_bit)
    with open('content.txt', 'r') as file:
        content_str = file.read()
    content_bit = base64.b64decode(content_str)
    return cipher.decrypt_cbc(content_bit, iv_bit).decode()

def encrypt(iv, key, token):
    iv_bit = iv.encode()
    key_bit = key.encode()
    cipher = AES(key_bit)
    content_bit = cipher.encrypt_cbc(token.encode(), iv_bit)
    content_str = base64.b64encode(content_bit).decode()
    with open('content.txt', "w") as file:
        file.write(content_str)
    return content_str

if __name__ == '__main__':
    app.run(host="0.0.0.0", threaded=True, port=8888)