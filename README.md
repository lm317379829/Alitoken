# 项目介绍

利用Python的Flask库搭建的阿里token相关服务。

![image](https://dartnode.com/assets/dash/images/brand/favicon.png)

可以搭建于： https://dartnode.com/

## 使用方法：

### 自行部署到replit等平台，或利用docker部署。token经过AES加密，防止token泄露，iv与key自行保存。

访问服务器ip或域名:8888为默认404网页。

访问 服务器ip或域名:8888/token?iv=你的初始化向量&key=你的秘钥
 
 可添加参数：display、delFile、refresh
 
| display参数  | 功能           |
|--------------|---------------|
| all          | 显示全部          |
| token        | 显示32位token     |
| authorization| 显示旧api授权    |
| opentoken    | 显示280位token    |
| opauthorization|显示新api授权   |
| user_id      | 显示user_id       |
| drive_id     | 显示drive_id      |
 
| delFile参数  | 功能           |
|--------------|---------------|
| True         | 删除根目录文件 |
| False        |不删除根目录文件|

| refresh参数  | 功能           |
|--------------|---------------|
| True         |    强制刷新    |
| False        |   不强制刷新   |
