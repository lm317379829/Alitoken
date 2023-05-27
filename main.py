import os
import json
import time
import base64

from flask import Flask, redirect, request, render_template, send_from_directory
from aes import AES
from ali import Ali

class cryption():
    def decrypt(self, iv, key, content):
        iv_bit = iv.encode()
        key_bit = key.encode()
        cipher = AES(key_bit)
        content_bit = base64.b64decode(content)
        try:
            content = cipher.decrypt_cbc(content_bit, iv_bit).decode()
        except:
            content = 'Erro'
        return content

    def encrypt(self, iv, key, content):
        iv_bit = iv.encode()
        key_bit = key.encode()
        cipher = AES(key_bit)
        content_bit = cipher.encrypt_cbc(content.encode(), iv_bit)
        content_str = base64.b64encode(content_bit).decode()
        return content_str

app = Flask(__name__)

with open('content.txt', 'r') as file:
    app.config['content'] = file.read()
app.config['alicache'] = {}

@app.route('/')
def web():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'templates'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/token')
def token():
    # 获取相关参数
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
        if delFile and delFile.lower() == 'true':
            delFile = True
        else:
            delFile = False
        if refresh and refresh.lower() == 'true':
            refresh = True
        else:
            refresh = False
        # 缓存app.config['alicache']非空且不强制刷新
        if app.config['alicache'] != {} and not refresh:
            # 缓存app.config['alicache']未过期
            if app.config['alicache']['expires_at'] > int(time.time()):
                tokenDict ={}
                for tkey in app.config['alicache']:
                    if tkey == 'expires_at':
                        tokenDict[tkey] = app.config['alicache'][tkey]
                        continue
                    value = cryption().decrypt(iv, key, app.config['alicache'][tkey])
                    if value == 'Erro':
                        return '密钥错误，请重新输入'
                    tokenDict[tkey] = value
                Ali().check_in(tokenDict)
                # 删除文件delFile为True则
                if delFile:
                    Ali().delFile(tokenDict)
            # 缓存app.config['alicache']过期
            else:
                value = cryption().decrypt(iv, key, app.config['content'])
                if value == 'Erro':
                    return '密钥错误'
                tokenDict = Ali().refresh_token(value, delFile)
                if tokenDict == {}:
                    return redirect('/submit')
                for tkey in tokenDict:
                    if tkey == 'expires_at':
                        app.config['alicache'][tkey] = tokenDict[tkey]
                        continue
                    app.config['alicache'][tkey] = cryption().encrypt(iv, key, tokenDict[tkey])
                app.config['content'] = cryption().encrypt(iv, key, tokenDict['token'])
                if os.access('content.txt', os.W_OK):
                    with open('content.txt', "w") as file:
                        file.write(app.config['content'])
        # 缓存app.config['alicache']为空
        else:
            # 缓存app.config['content']为空
            if app.config['content'] == '':
                return redirect('/submit')

            value = cryption().decrypt(iv, key, app.config['content'])
            if value == 'Erro':
                return '密钥错误'

            tokenDict = Ali().refresh_token(value, delFile)
            # tokenDict为{}，意味着token失效，重新提交token
            if tokenDict == {}:
                return redirect('/submit')
            for tkey in tokenDict:
                if tkey == 'expires_at':
                    app.config['alicache'][tkey] = tokenDict[tkey]
                    continue
                app.config['alicache'][tkey] = cryption().encrypt(iv, key, tokenDict[tkey])
            app.config['content'] = app.config['alicache']['token']
            if os.access('content.txt', os.W_OK):
                with open('content.txt', "w") as file:
                    file.write(app.config['content'])

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
    app.config['content'] = content_str
    if os.access('content.txt', os.W_OK):
        with open('content.txt', "w") as file:
            file.write(app.config['content'])
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

if __name__ == '__main__':
    app.run(host="0.0.0.0", threaded=True, port=8888)
