# 🔐 用户信息管理平台 (User Management System)

一个基于 Flask 的全功能用户信息管理平台，支持**登录、注册、个人中心、余额充值、头像上传、用户搜索、修改密码、URL 抓取、Ping 网络诊断、动态页面加载**等 **10 项功能**。项目经过**完整安全审计与加固**，修复了包括命令注入、SSRF、SQL 注入、路径遍历、越权访问在内的 **21 项安全漏洞**，修复率 **100%**。

---

## 📋 功能清单

| 功能 | 路由 | 说明 | 权限 |
|:-----|:------|:------|:----:|
| 🔑 登录 | `GET/POST /login` | 用户登录（含登录限流 5次/60秒/IP、CSRF 保护） | 公开 |
| 📝 注册 | `GET/POST /register` | 新用户注册（含输入过滤与密码强度校验） | 公开 |
| 👤 个人中心 | `GET /profile` | 查看本人资料（ID、用户名、邮箱、手机、余额） | 登录 |
| 💰 余额充值 | `POST /recharge` | 为当前登录账号充值（仅正数、仅限本人） | 登录 |
| 🔑 修改密码 | `POST /change-password` | 修改当前登录用户密码（需验证原密码 + CSRF） | 登录 |
| 📷 头像上传 | `GET/POST /upload` | 上传用户头像 | 登录 |
| 🔍 用户搜索 | `GET /` | 按用户名或邮箱搜索已注册用户 | 登录 |
| 🌐 URL 抓取 | `POST /fetch-url` | 抓取远程 URL 内容（限 http/https，禁内网） | 登录 |
| 📡 Ping 诊断 | `GET/POST /ping` | Ping 网络连通性测试 | 登录 |
| 📖 帮助中心 | `GET /page?name=help` | 动态页面加载，显示帮助文档 | 公开 |
| 🚪 退出 | `POST /logout` | POST 方式安全退出（含 CSRF 校验） | 登录 |

---

## 🛡️ 安全修复清单（21项）

| # | 漏洞类型 | 严重等级 | 修复方案 | 状态 |
|:-:|:---------|:--------:|:---------|:----:|
| 1 | 密码明文存储 | 🔴 严重 | bcrypt 加盐哈希 | ✅ |
| 2 | Secret Key 硬编码 | 🔴 严重 | 环境变量 / `secrets.token_hex(32)` 随机生成 | ✅ |
| 3 | HTML 注释泄露默认账号 | 🟠 高 | 已删除调试注释 | ✅ |
| 4 | 密码前端回显 | 🟠 高 | 密码字段永不传入模板 | ✅ |
| 5 | Debug 模式暴露 | 🟠 高 | 环境变量控制，绑定 `127.0.0.1` | ✅ |
| 6 | SQL 注入（搜索功能） | 🔴 严重 | 参数化查询（`LIKE ?`） | ✅ |
| 7 | SQL 注入（注册功能） | 🔴 严重 | 参数化查询 + 输入过滤 | ✅ |
| 8 | 无 CSRF 防护 | 🟡 中 | `@csrf_required` 装饰器 + 隐藏 Token | ✅ |
| 9 | 无登录限流 | 🟡 中 | 5 次 / 60 秒 / IP 内存限速 | ✅ |
| 10 | 缺少安全响应头 | 🟡 中 | XFO · NOSNIFF · Referrer-Policy | ✅ |
| 11 | Cookie 属性缺失 | 🟡 中 | HttpOnly + SameSite=Lax | ✅ |
| 12 | GET 方式登出 | 🟡 中 | 改为 POST + CSRF 校验 | ✅ |
| 13 | 无审计日志 | 🟢 低 | `audit_logs` 表记录关键操作 | ✅ |
| 14 | 文件上传无校验 | 🔴 严重 | 扩展名白名单 + 魔术字节验证 + UUID 重命名 + 大小限制 | ✅ |
| 15 | 越权访问个人中心 | 🟠 高 | 登录检查 + `user_id` 与 session 比对 | ✅ |
| 16 | 越权充值 / 负值充值 | 🔴 严重 | 所有权验证 + 金额必须为正数 | ✅ |
| 17 | 动态页面路径遍历 | 🔴 严重 | `os.path.abspath()` 规范化 + 目录约束检查 | ✅ |
| 18 | 越权修改密码 | 🔴 严重 | 只允许修改当前登录用户密码 + 需验证原密码 | ✅ |
| 19 | 修改密码无 CSRF | 🟡 中 | `@csrf_required` 装饰器防护 | ✅ |
| 20 | URL 抓取 SSRF / file 协议 | 🔴 严重 | 协议白名单 + IP 地址校验（禁内网/回环） | ✅ |
| 21 | Ping 命令注入 | 🔴 严重 | `shlex.quote()` 转义用户输入 | ✅ |

---

## 📁 项目结构

```
├── app.py                        # Flask 主应用（安全加固版，~540行）
├── requirements.txt              # flask, bcrypt
├── README.md
├── pages/                        # 动态页面目录
│   └── help.html                 # 帮助中心页面
├── data/
│   └── users.db                  # SQLite 数据库（自动创建）
├── static/
│   ├── css/
│   │   └── style.css             # 蓝白简约风格样式
│   └── uploads/                  # 用户上传文件存储目录
└── templates/
    ├── base.html                 # 基础模板（导航栏 + Flash 消息）
    ├── index.html                # 首页（用户信息 + 搜索 + URL 抓取 + 动态页面）
    ├── login.html                # 登录页
    ├── register.html             # 注册页
    ├── profile.html              # 个人中心 / 充值 / 修改密码
    ├── upload.html               # 头像上传页
    ├── ping.html                 # Ping 网络诊断页
    └── logout.html               # 退出确认页
```

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- Flask 2.x
- bcrypt 4.x

### 安装与运行

```bash
# 1. 克隆项目
git clone https://github.com/ee0817/Day2.git
cd Day2

# 2. 安装依赖
pip install flask bcrypt

# 3. 运行
python app.py
```

浏览器访问 **http://127.0.0.1:5000**

> 启动时自动绑定 `127.0.0.1`（仅本地访问），Secret Key 自动随机生成。

---

## 👤 默认账号

| 用户名 | 密码 | 角色 | 邮箱 | 初始余额 |
|:-------|:-----|:----|:-----|:--------:|
| `admin` | `admin123` | 管理员 | admin@example.com | ¥99,999.00 |
| `alice` | `alice2025` | 普通用户 | alice@example.com | ¥100.00 |

---

## 🔄 API 路由一览

| 方法 | 路径 | 说明 | 登录 | CSRF | 备注 |
|:----|:------|:------|:----:|:----:|:-----|
| `GET` | `/` | 首页 | - | - | 已登录/未登录双状态 |
| `GET/POST` | `/login` | 登录 | ❌ | ✅ | 5次/60秒限流 |
| `POST` | `/logout` | 退出登录 | ✅ | ✅ | |
| `GET` | `/logout-page` | 退出确认页 | - | - | |
| `GET/POST` | `/register` | 注册 | ❌ | ✅ | 密码强度校验 |
| `GET` | `/profile` | 个人中心 | ✅ | - | 仅限本人 |
| `POST` | `/recharge` | 充值 | ✅ | - | 仅正数/本人 |
| `POST` | `/change-password` | 修改密码 | ✅ | ✅ | 需原密码 |
| `GET/POST` | `/upload` | 上传头像 | ✅ | ✅ | 图片类型校验 |
| `POST` | `/fetch-url` | URL 抓取 | ✅ | - | 禁 file/内网 |
| `GET/POST` | `/ping` | Ping 诊断 | ✅ | - | `shlex` 防注入 |
| `GET` | `/page` | 动态页面 | - | - | 路径约束 |

---

## 📝 审计日志说明

系统自动记录以下操作到 `audit_logs` 表：

| 操作 | 触发条件 |
|:-----|:---------|
| `LOGIN` | 用户登录成功 |
| `LOGIN_FAILED` | 登录失败（用户名或密码错误） |
| `LOGOUT` | 用户点击退出 |
| `RATE_LIMITED` | 同一 IP 登录尝试超过 5 次/60 秒 |
| `REGISTER` | 新用户注册成功 |
| `UPLOAD` | 用户上传文件 |
| `RECHARGE` | 充值操作 |
| `PWD_CHANGED` | 修改密码成功 |
| `FETCH_URL` | URL 抓取操作 |
| `PING` | Ping 诊断操作 |

---

## 🔒 安全策略详解

### 密码策略

- 使用 **bcrypt** 加盐哈希存储密码，即使数据库泄露也无法还原
- 密码强度要求：至少 8 位，包含大小写字母和数字
- 修改密码必须验证原密码
- Secret Key 使用 `secrets.token_hex(32)` 随机生成

### 登录限流策略

- 同一 IP：60 秒内最多 5 次登录尝试
- 超出限制返回友好提示并记录日志
- 登录成功自动清除限流记录

### 权限控制策略

| 功能 | 策略 |
|:-----|:------|
| 个人中心 | 必须登录，`user_id` 与 session 匹配 |
| 充值 | 必须登录，仅本人 + 正数 |
| 修改密码 | 必须登录 + CSRF + 原密码，仅本人 |
| 头像上传 | 必须登录 |
| URL 抓取 | 必须登录，禁 file 协议 + 禁内网 |
| Ping 诊断 | 必须登录，`shlex.quote()` 防注入 |

### 命令注入防护

Ping 功能使用 `shlex.quote()` 转义用户输入，防止命令注入：

```python
# 修复前（危险）：
cmd = f"ping -c 3 {ip}"           # 输入 127.0.0.1 && whoami → 命令被执行

# 修复后（安全）：
safe_ip = shlex.quote(ip.strip())
cmd = f"ping -c 3 {safe_ip}"       # 输入被转义为 '127.0.0.1 && whoami'
```

### URL 抓取安全策略

- **协议白名单**：仅允许 `http://` 和 `https://`
- **IP 黑名单**：禁止内网 IP（`127.0.0.1`、`10.x.x.x`、`192.168.x.x`）
- **禁止回环地址**：`localhost`、`127.0.0.1` 等
- **超时限制**：10 秒超时

### 头像上传安全策略

- **扩展名白名单**：仅允许 `png / jpg / jpeg / gif / bmp / webp`
- **魔术字节验证**：检查文件头真实格式，拦截图片马
- **UUID 重命名**：防止文件名冲突与路径穿越
- **大小限制**：最大 2MB
- **CSRF 防护**：上传请求需携带 CSRF Token

### SQL 注入防护

所有 SQL 查询使用**参数化查询**（Prepared Statement）：

```python
# 安全写法
sql = "SELECT * FROM users WHERE username LIKE ?"
c.execute(sql, (f"%{keyword}%",))

# 危险写法（禁止使用）
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"
c.execute(sql)
```

### 会话安全

- `SESSION_COOKIE_HTTPONLY = True` — 禁止 JavaScript 读取 Cookie
- `SESSION_COOKIE_SAMESITE = 'Lax'` — 限制跨站请求发送 Cookie
- `PERMANENT_SESSION_LIFETIME = 1800` — 30 分钟自动过期

### HTTP 安全响应头

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
```

---

## 🧪 功能测试示例

```bash
# 1. 注册新用户
curl -X POST http://127.0.0.1:5000/register \
  -d "username=test&password=Test12345&email=test@test.com"

# 2. 登录
curl -X POST http://127.0.0.1:5000/login \
  -d "username=admin&password=admin123" -c cookies.txt

# 3. 查看个人中心
curl -b cookies.txt http://127.0.0.1:5000/profile?user_id=1

# 4. 充值
curl -b cookies.txt -X POST http://127.0.0.1:5000/recharge -d "user_id=1&amount=100"

# 5. 修改密码（需 CSRF Token）
CSRF=$(curl -b cookies.txt http://127.0.0.1:5000/profile?user_id=1 | grep -oP 'value="\K[^"]+' | head -1)
curl -b cookies.txt -X POST http://127.0.0.1:5000/change-password \
  -d "csrf_token=$CSRF&old_password=admin123&new_password=newadmin123"

# 6. URL 抓取
curl -b cookies.txt -X POST http://127.0.0.1:5000/fetch-url -d "url=http://example.com"

# 7. Ping 测试
curl -b cookies.txt -X POST http://127.0.0.1:5000/ping -d "ip=127.0.0.1"

# 8. 命令注入测试（应被拦截）
curl -b cookies.txt -X POST http://127.0.0.1:5000/ping -d "ip=127.0.0.1 && whoami"

# 9. 查看帮助中心
curl http://127.0.0.1:5000/page?name=help

# 10. 搜索用户
curl -b cookies.txt "http://127.0.0.1:5000/?keyword=admin"
```

---

## ⚙️ 环境变量

| 变量 | 说明 | 默认值 |
|:-----|:------|:-------|
| `SECRET_KEY` | Flask session 签名密钥 | `secrets.token_hex(32)` 自动生成 |
| `FLASK_ENV` | 设为 `development` 开启 Debug 模式 | 未设置（Debug 关闭） |

---

## 📄 运行环境

- Python 3.8+
- Flask 2.x
- bcrypt 4.x
