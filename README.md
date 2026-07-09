# 🔐 用户信息管理平台 (User Management System)

一个基于 Flask 的用户信息管理平台，支持**登录、注册、头像上传、用户搜索**功能。经过完整安全审计与加固，修复了包括 SQL 注入在内的 14 项安全漏洞。

---

## ✨ 功能

| 功能 | 说明 | 权限 |
|:-----|:------|:----:|
| 🔑 登录 | 用户登录（含登录限流） | 公开 |
| 📝 注册 | 新用户注册（含输入过滤与密码强度校验） | 公开 |
| 👤 个人中心 | 查看用户名、邮箱、手机、余额等信息 | 登录 |
| 📷 头像上传 | 上传用户头像（支持 PNG/JPG/GIF/BMP/WebP） | 登录 |
| 🔍 用户搜索 | 按用户名或邮箱搜索已注册用户 | 登录 |
| 🚪 退出 | POST 方式安全退出 | 登录 |

## 🛡️ 安全修复（14项）

| # | 漏洞类型 | 修复方案 | 状态 |
|:-:|:---------|:---------|:----:|
| 1 | 密码明文存储 | bcrypt 加盐哈希 | ✅ |
| 2 | Secret Key 硬编码 | 环境变量 / `secrets.token_hex(32)` 随机 | ✅ |
| 3 | HTML 注释泄露默认账号 | 已删除 | ✅ |
| 4 | 密码前端回显 | 密码字段永不传入模板 | ✅ |
| 5 | Debug 模式暴露 | 环境变量控制，绑定 `127.0.0.1` | ✅ |
| 6 | 无 CSRF 防护 | `@csrf_required` 装饰器 + 隐藏 Token | ✅ |
| 7 | 无登录限流 | 5 次 / 60 秒 / IP 内存限速 | ✅ |
| 8 | 缺少安全响应头 | XFO · NOSNIFF · Referrer-Policy | ✅ |
| 9 | Cookie 属性缺失 | HttpOnly + SameSite=Lax | ✅ |
| 10 | GET 方式登出 | 改为 POST + CSRF 校验 | ✅ |
| 11 | SQL 注入（搜索） | 参数化查询（`LIKE ?`） | ✅ |
| 12 | SQL 注入（注册） | 参数化查询 + 输入过滤 | ✅ |
| 13 | 无审计日志 | `audit_logs` 表记录关键操作 | ✅ |
| 14 | 文件上传漏洞 | 扩展名校验 + 魔术字节验证 + UUID 重命名 + 大小限制 | ✅ |

## 📁 项目结构

```
├── app.py                    # Flask 主应用（安全加固版）
├── requirements.txt          # flask, bcrypt
├── README.md
├── data/
│   └── users.db              # SQLite 数据库（自动创建）
├── static/
│   ├── css/
│   │   └── style.css         # 蓝白简约风格样式
│   └── uploads/              # 用户上传文件存储目录
└── templates/
    ├── base.html             # 基础模板（导航栏）
    ├── index.html            # 首页（用户信息 + 搜索）
    ├── login.html            # 登录页
    ├── register.html         # 注册页
    ├── upload.html           # 头像上传页
    └── logout.html           # 退出确认页
```

## 🚀 快速开始

```bash
# 1. 安装依赖
pip install flask bcrypt

# 2. 运行
python app.py
```

浏览器访问 **http://127.0.0.1:5000**

> 启动时自动绑定 127.0.0.1（仅本地访问），Secret Key 自动随机生成。

## 👤 默认账号

| 用户名 | 密码 | 角色 | 邮箱 |
|:-------|:-----|:----|:-----|
| `admin` | `admin123` | 管理员 | admin@example.com |
| `alice` | `alice2025` | 普通用户 | alice@example.com |

## 🔄 API 路由

| 方法 | 路径 | 说明 | 权限 | CSRF |
|:----|:-----|:-----|:----:|:----:|
| GET | `/` | 首页（含搜索） | 公开 | - |
| GET/POST | `/login` | 登录（含限流） | 公开 | ✅ |
| POST | `/logout` | 退出 | 登录 | ✅ |
| GET | `/logout-page` | 退出确认页 | 登录 | - |
| GET/POST | `/register` | 注册 | 公开 | ✅ |
| GET/POST | `/upload` | 上传头像 | 登录 | ✅ |

## 📝 审计日志说明

系统自动记录以下操作到 `audit_logs` 表：

| 操作 | 说明 |
|:-----|:------|
| `LOGIN` | 登录成功 |
| `LOGIN_FAILED` | 登录失败 |
| `LOGOUT` | 安全退出 |
| `RATE_LIMITED` | 触发登录频率限制 |
| `REGISTER` | 新用户注册 |
| `UPLOAD` | 文件上传 |

## 🔒 安全配置

### 环境变量

| 变量 | 说明 | 默认值 |
|:-----|:-----|:-------|
| `SECRET_KEY` | Flask session 签名密钥 | `secrets.token_hex(32)` |
| `FLASK_ENV` | `development` 开启 Debug | 未设置（关闭 Debug） |

### 登录限流策略

- 同一 IP：60 秒内最多 5 次登录尝试
- 超出限制返回友好提示并记录日志
- 登录成功自动清除限流记录

### 头像上传安全策略

- ✅ **扩展名白名单**：仅允许 `png / jpg / jpeg / gif / bmp / webp`
- ✅ **魔术字节验证**：检查文件头真实格式，拦截图片马
- ✅ **UUID 重命名**：防止文件名冲突与路径穿越
- ✅ **大小限制**：最大 2MB
- ✅ **CSRF 防护**：上传请求需携带 CSRF Token

## 🔒 SQL 注入防护

搜索和注册功能使用**参数化查询**（Prepared Statement）替代字符串拼接：

```python
# 安全写法
sql = "SELECT * FROM users WHERE username LIKE ?"
c.execute(sql, (f"%{keyword}%",))
```

## 📦 运行环境

- Python 3.8+
- Flask 2.x
- bcrypt 4.x
