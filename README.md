# 🔐 安全用户管理平台 (User Management System)

一个基于 Flask 的安全用户管理系统，支持管理员和普通用户双角色，内置审计日志和安全响应头防护。

## ✨ 功能

| 功能 | 角色 | 说明 |
|------|------|------|
| 🔑 登录/退出 | 全部用户 | 密码使用 bcrypt 加盐存储，登录成功有 Flash 提示 |
| 🔑 修改密码 | 全部用户 | 6位长度校验 + 新旧密码重复检测 |
| 👑 管理面板 | 管理员 | 查看所有用户列表（用户名/角色/注册时间） |
| 📋 审计日志 | 管理员 | 记录登录、退出、改密码等操作（时间/用户/IP/详情） |

## 🛡️ 安全措施

- **bcrypt 密码哈希** — 不存储明文密码
- **安全响应头** — `X-Content-Type-Options: nosniff` 防 MIME 嗅探、`X-Frame-Options: DENY` 防点击劫持
- **Session 过期** — 30 分钟自动过期
- **角色鉴权** — 非管理员无法访问管理面板和审计日志
- **统一错误提示** — 不暴露用户是否存在

## 📁 项目结构

```
user_management/
├── app.py                 # Flask 主应用 (~140行)
├── database.db            # SQLite 数据库（自动创建）
├── requirements.txt       # 依赖列表
├── README.md              # 本文档
├── .gitignore
├── templates/
│   ├── base.html          # 基础模板（Flash 消息区域）
│   ├── index.html         # 首页（登录/未登录两种状态）
│   ├── login.html         # 登录页面
│   ├── change_password.html # 修改密码页面
│   ├── admin.html         # 管理面板（用户列表 + 日志入口）
│   └── admin_logs.html    # 审计日志页面
└── static/
    └── style.css          # 样式文件
```

## 🚀 快速开始

```bash
pip install flask bcrypt
python app.py
```

浏览器访问 [http://localhost:5000](http://localhost:5000)

## 👤 默认账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| `admin` | `admin123` | 管理员 |
| `user1` | `password1` | 普通用户 |

## 🧪 功能验证

```bash
# 登录
curl -X POST http://localhost:5000/login -d "username=admin&password=***"

# 查看管理面板（需先登录）
curl -c cookies.txt -b cookies.txt http://localhost:5000/admin

# 查看审计日志
curl -c cookies.txt -b cookies.txt http://localhost:5000/admin/logs

# 退出
curl -c cookies.txt -b cookies.txt http://localhost:5000/logout
```

## 🔄 API 路由

| 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|
| GET | `/` | 首页 | 公开 |
| GET/POST | `/login` | 登录 | 公开 |
| GET | `/logout` | 退出 | 公开 |
| GET/POST | `/change-password` | 修改密码 | 登录用户 |
| GET | `/admin` | 管理面板 | 管理员 |
| GET | `/admin/logs` | 审计日志 | 管理员 |

## 📝 审计日志说明

系统自动记录以下操作到 `audit_logs` 表：

- `LOGIN` — 登录成功
- `LOGIN_FAILED` — 登录失败（记录尝试的用户名）
- `LOGOUT` — 安全退出
- `PWD_CHANGED` — 修改密码成功
- `PWD_FAILED` — 修改密码失败（原密码错误）

每条记录包含：操作时间、操作用户、操作类型、详情、IP 地址。

管理员可在管理面板 > 审计日志中查看最近 50 条记录。
