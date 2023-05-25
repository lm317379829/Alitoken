import re
import json
import base64
import requests

from flask import Flask, request, render_template
from aes import AES

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
            tokenDict = refresh_token(token, delFile)
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

def refresh_token(token, delFile=False):
    tokenDict = {}
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36",
        "Rererer": "https://www.aliyundrive.com/",
        "Content-Type": "application/json"
    }
    #刷新token并获取参数
    r = requests.post(url='https://auth.aliyundrive.com/v2/account/token',
                      json={'grant_type': 'refresh_token', 'refresh_token': token},
                      headers=header,
                      timeout=10)
    if r.status_code != 200:
        return {}
    jo = json.loads(r.text)
    token = jo['refresh_token']
    authorization = '{} {}'.format(jo['token_type'],  jo['access_token'])
    user_id = jo['user_id']
    drive_id = jo['default_drive_id']
    header['authorization'] = authorization
    #获取opentoken
    try:
        r = requests.post(
            url='https://open.aliyundrive.com/oauth/users/authorize?client_id=76917ccccd4441c39457a04f6084fb2f&redirect_uri=https://alist.nn.ci/tool/aliyundrive/callback&scope=user:base,file:all:read,file:all:write&state=',
            json={
                'authorize': 1,
                'scope': 'user:base,file:all:read,file:all:write'
            },
            headers=header)
        code = re.search(r'code=(.*?)\"', r.text).group(1)
        r = requests.post(url='https://api.nn.ci/alist/ali_open/code',
                          json={
                              'code': code,
                              'grant_type': 'authorization_code'
                          },
                          headers=header)
        jo = json.loads(r.text)
        opentoken = jo['refresh_token']
        opauthorization = '{} {}'.format(jo['token_type'], jo['access_token'])
    except:
        opentoken = ''
        opauthorization = ''
    #签到&领取奖励
    r = requests.post(url='https://member.aliyundrive.com/v1/activity/sign_in_list',
                      json={"grant_type": "refresh_token", "refresh_token": token},
                      headers=header,
                      timeout=10)
    for day in r.json()['result']['signInLogs']:
        if day['isReward'] is False and day['status'] == 'normal':
            signInDay = day['day']
            r = requests.post(url='https://member.aliyundrive.com/v1/activity/sign_in_reward',
                              json={"grant_type": "refresh_token", "refresh_token": token, "signInDay": signInDay},
                              headers=header,
                              timeout=10)
    #删除根目录文件
    if delFile:
        r = requests.post(url='https://api.aliyundrive.com/adrive/v3/file/list',
                          json={"drive_id": drive_id, "parent_file_id": "root"},
                          headers=header,
                          timeout=10)
        for item in r.json()['items']:
            if item['type'] == 'file':
                requests.post('https://api.aliyundrive.com/v3/batch',
                              json={"requests":
                                        [{"body": {"drive_id": drive_id, "file_id": item['file_id']},
                                          "headers": {"Content-Type": "application/json"},
                                          "id": item['file_id'],
                                          "method": "POST",
                                          "url": "/file/delete"}],
                                    "resource": "file"},
                              headers=header,
                              timeout=10)
    tokenDict['token'] = token
    tokenDict['authorization'] = authorization
    tokenDict['opentoken'] = opentoken
    tokenDict['opauthorization'] = opauthorization
    tokenDict['user_id'] = user_id
    tokenDict['drive_id'] = drive_id
    return tokenDict

if __name__ == '__main__':
    app.run(host="0.0.0.0", threaded=True, port=8888)
