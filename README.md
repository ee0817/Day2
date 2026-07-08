# 🔐 用户信息管理平台 (User Management System)

一个基于 Flask 的用户信息管理平台，支持登录、注册、用户搜索功能。经过完整安全审计与加固。

## ✨ 功能

| 功能 | 说明 |
|:-----|:------|
| 🔑 登录 | 登录后显示用户信息 |
| 📝 注册 | 新用户注册（含输入过滤） |
| 🔍 搜索 | 搜索已注册用户（用户名/邮箱） |
| 🚪 退出 | POST 方式安全退出 |

## 🛡️ 安全修复（13项）

| # | 漏洞 | 修复方案 | 状态 |
|:--|:-----|:---------|:----:|
| 1 | 密码明文存储 | bcrypt 加盐哈希 | ✅ |
| 2 | Secret Key 硬编码 | 环境变量 / secrets 随机 | ✅ |
| 3 | HTML注释泄露账号 | 已删除 | ✅ |
| 4 | 密码前端回显 | 密码永不到达模板 | ✅ |
| 5 | Debug模式暴露 | 环境变量控制，绑定 127.0.0.1 | ✅ |
| 6 | 无CSRF防护 | csrf_required 装饰器 | ✅ |
| 7 | 无登录限流 | 5次/60秒/IP 内存限速 | ✅ |
| 8 | 缺少安全响应头 | XFO·NOSNIFF·Referrer-Policy | ✅ |
| 9 | Cookie属性缺失 | HttpOnly+SameSite+Lax | ✅ |
| 10 | GET方式登出 | 改为POST+CSRF校验 | ✅ |
| 11 | SQL注入（搜索） | 参数化查询 | ✅ |
| 12 | SQL注入（注册） | 参数化查询 + 输入过滤 | ✅ |
| 13 | 无审计日志 | audit_logs 表记录操作 | ✅ |

## 📁 项目结构

```
├── app.py                 # Flask 主应用（安全加固版）
├── requirements.txt       # flask, bcrypt
├── README.md
├── data/
│   └── users.db           # SQLite 数据库（自动创建）
├── templates/
│   ├── base.html          # 基础模板（导航栏）
│   ├── index.html         # 首页（用户信息 + 搜索）
│   ├── login.html         # 登录页
│   ├── register.html      # 注册页
│   └── logout.html        # 退出确认页
└── static/
    └── css/
        └── style.css      # 蓝白简约风格
```

## 🚀 快速开始

```bash
pip install flask bcrypt
python app.py
```

浏览器访问 [http://127.0.0.1:5000](http://127.0.0.1:5000)

> **注意：** 启动时绑定 127.0.0.1（仅本地访问），Secret Key 自动随机生成。

## 👤 默认账号

| 用户名 | 密码 | 邮箱 |
|:-------|:-----|:-----|
| `admin` | `admin123` | admin@example.com |
| `alice` | `alice2025` | alice@example.com |

## 🔄 API 路由

| 方法 | 路径 | 说明 | 权限 | CSRF |
|:----|:-----|:-----|:----:|:----:|
| GET | `/` | 首页（含搜索） | 公开 | - |
| GET/POST | `/login` | 登录（含限流） | 公开 | ✅ |
| POST | `/logout` | 退出 | 登录 | ✅ |
| GET/POST | `/register` | 注册 | 公开 | ✅ |
| GET | `/logout-page` | 退出确认页 | 登录 | - |

## 📝 审计日志说明

系统自动记录以下操作到 `audit_logs` 表：

- `LOGIN` — 登录成功
- `LOGIN_FAILED` — 登录失败
- `LOGOUT` — 安全退出
- `RATE_LIMITED` — 触发登录频率限制
- `REGISTER` — 新用户注册
- `REGISTER_FAILED` — 注册失败

## 🔒 安全配置

### 环境变量

| 变量 | 说明 | 默认值 |
|:-----|:-----|:-------|
| `SECRET_KEY` | Flask session 签名密钥 | `secrets.token_hex(32)` |
| `FLASK_ENV` | `development` 开启 Debug | 未设置（关闭 Debug） |

### 登录限流策略

- 同一 IP：60 秒内最多 5 次登录尝试
- 登录成功自动清除限流记录

## 🔒 SQL 注入防护

搜索和注册功能已从 f-string 拼接改为**参数化查询**：

**修复前（危险）：**
```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"
c.execute(sql)
```

**修复后（安全）：**
```python
sql = "SELECT * FROM users WHERE username LIKE ?"
c.execute(sql, (f"%{keyword}%",))
```
