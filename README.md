# 🔐 安全用户管理平台 (User Management System) — Day2

一个基于 Flask 的安全用户管理系统，经过完整安全审计与加固，支持管理员和普通用户双角色，内置审计日志、CSRF 防护、登录限流、安全响应头等多层防护。

## ✨ 功能

| 功能 | 角色 | 说明 |
|------|------|------|
| 🔑 登录/退出 | 全部用户 | bcrypt 密码加密，POST 方式登出 |
| 📝 用户注册 | 全部用户 | 用户名/密码强度/邮箱三重校验 |
| 👤 个人中心 | 全部用户 | 查看邮箱/手机/余额/注册时间 |
| ✏️ 编辑个人信息 | 全部用户 | 更新邮箱、手机号 |
| 🔑 修改密码 | 全部用户 | 6位校验+防重复+CSRF保护 |
| 👑 管理面板 | 管理员 | 用户列表+角色badge+注册时间 |
| ✏️ 管理员编辑用户 | 管理员 | 修改邮箱/手机/余额/角色 |
| 📋 审计日志 | 管理员 | 最近100条操作记录 |

## 🛡️ 安全措施（11项修复）

| # | 漏洞 | 修复方案 | 状态 |
|:--|:-----|:---------|:----:|
| 1 | 密码明文存储 | bcrypt 加盐哈希 | ✅ |
| 2 | Secret Key 硬编码 | 环境变量 / secrets 随机 | ✅ |
| 3 | HTML注释泄露默认账号 | 已删除 | ✅ |
| 4 | 密码在前端回显 | 密码永不到达模板 | ✅ |
| 5 | Debug模式暴露 | 环境变量控制，绑定 127.0.0.1 | ✅ |
| 6 | 无CSRF防护 | csrf_required 装饰器，POST登出 | ✅ |
| 7 | 无登录限流 | 5次/60秒/IP 内存限速 | ✅ |
| 8 | 缺少安全响应头 | XFO·NOSNIFF·Referrer-Policy | ✅ |
| 9 | Cookie属性缺失 | HttpOnly+SameSite+Lax | ✅ |
| 10 | GET方式登出 | 改为POST+CSRF校验 | ✅ |
| 11 | 输入数据未过滤 | 4项 sanitize 过滤函数 | ✅ |

## 📁 项目结构

```
user_management/
├── app.py                 # Flask 主应用（~160行，安全加固版）
├── database.db            # SQLite 数据库（自动创建）
├── requirements.txt       # flask, bcrypt
├── README.md              # 本文档
├── Day2安全审计与修复报告.docx  # 安全审计报告（Word版）
├── .gitignore
├── templates/
│   ├── base.html          # 基础模板（Flash消息区域）
│   ├── index.html         # 首页（登录/未登录+POST登出表单）
│   ├── login.html         # 登录页（含CSRF Token）
│   ├── register.html      # 注册页（含输入校验）
│   ├── profile.html       # 个人中心
│   ├── profile_edit.html  # 编辑个人信息
│   ├── change_password.html # 修改密码
│   ├── admin.html         # 管理面板（用户列表+日志入口）
│   ├── admin_logs.html    # 审计日志
│   └── admin_user_edit.html # 管理员编辑用户
└── static/
    └── style.css          # 蓝白简约风格
```

## 🚀 快速开始

```bash
pip install flask bcrypt
python app.py
```

浏览器访问 [http://localhost:5000](http://localhost:5000)

> **注意：** 启动时绑定 127.0.0.1（仅本地访问），Secret Key 自动随机生成。

## 👤 默认账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| `admin` | `admin123` | 管理员（admin@example.com） |
| `user1` | `password1` | 普通用户（user1@example.com） |
| `test` | `Test@12345` | 普通用户（test@example.com） |

## 🔄 API 路由

| 方法 | 路径 | 说明 | 权限 | CSRF |
|------|------|------|------|:----:|
| GET | `/` | 首页 | 公开 | - |
| GET/POST | `/login` | 登录（含限流） | 公开 | ✅ |
| POST | `/logout` | 退出（POST方式） | 公开 | ✅ |
| GET/POST | `/register` | 注册 | 公开 | ✅ |
| GET | `/profile` | 个人中心 | 登录 | - |
| GET/POST | `/profile/edit` | 编辑信息 | 登录 | ✅ |
| GET/POST | `/change-password` | 修改密码 | 登录 | ✅ |
| GET | `/admin` | 管理面板 | 管理员 | - |
| GET/POST | `/admin/user/<id>/edit` | 编辑用户 | 管理员 | ✅ |
| GET | `/admin/logs` | 审计日志 | 管理员 | - |

## 📝 审计日志说明

系统自动记录以下操作到 `audit_logs` 表：

- `LOGIN` — 登录成功
- `LOGIN_FAILED` — 登录失败
- `LOGOUT` — 安全退出
- `PWD_CHANGED` — 修改密码成功
- `PWD_FAILED` — 修改密码失败
- `RATE_LIMITED` — 触发登录频率限制
- `REGISTER` — 新用户注册
- `PROFILE_UPDATE` — 更新个人信息
- `ADMIN_EDIT_USER` — 管理员编辑用户

管理员可在管理面板 > 审计日志中查看最近 100 条记录。

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

## 📋 安全审计

完整的审计报告见 `Day2安全审计与修复报告.docx`，覆盖：
- 三位安全审计人员的独立审计结果
- 11 项漏洞详情与修复方案
- 修复前后代码对比
- 15 项安全验证结果
