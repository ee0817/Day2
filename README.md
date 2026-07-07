# 安全用户管理平台

一个基于 Flask 的用户管理系统，支持管理员和普通用户双角色。

## 默认账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| user1 | password1 | 普通用户 |

## 功能

- 🔑 登录 / 退出
- 🔑 修改密码
- 👑 管理员面板（查看用户列表）

## 运行

```bash
pip install flask bcrypt
python app.py
```

浏览器访问 http://localhost:5000
