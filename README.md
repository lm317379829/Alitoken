# 项目介绍

利用Python的Flask库搭建的阿里token相关服务。

## 使用方法：

### 自行部署到replit等平台，或利用docker部署。token经过AES加密，iv与key自行保存，防止token泄露。

访问服务器ip或域名:8888为默认网页。

### 首次使用

post 访问 服务器ip或域名:8888/token?token=你的token&iv=你的初始化向量&key=你的秘钥

将AES加密后的token上传至服务器content.txt文件中。
 
 ### 后续使用
 
 get 访问 服务器ip或域名:8888/token?iv=你的初始化向量&key=你的秘钥
 
 可添加参数：display、delFile、refresh
 
| display参数  | 功能           |
|--------------|---------------|
| all          | 全部          |
| token        | 32位token     |
| authorization| 旧api授权    |
| opentoken    | 280位token    |
| opauthorization|新api授权   |
| user_id      | user_id       |
| drive_id     | drive_id      |
 
| delFile参数  | 功能           |
|--------------|---------------|
| True         | 删除根目录文件 |
| False        |不删除根目录文件|

| refresh参数  | 功能           |
|--------------|---------------|
| True         |    强制刷新    |
| False        |   不强制刷新   |
