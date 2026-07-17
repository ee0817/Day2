"""用户信息管理平台 - 安全加固版（含上传功能）"""
import os
import re
import json
import time
import secrets
import socket
import ipaddress
import shlex
import subprocess
import platform
import sqlite3
import urllib.request
import urllib.error
import urllib.parse
from functools import wraps

import bcrypt
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)

# ── 应用初始化 ──────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=1800,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
)


# ── 数据库 ───────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect('data/users.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs("data", exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            balance REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        pw = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES (?, ?, ?, ?, ?, ?)",
                  ('admin', pw, 'admin', 'admin@example.com', '13800138000', 99999))
        pw = bcrypt.hashpw(b'alice2025', bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES (?, ?, ?, ?, ?, ?)",
                  ('alice', pw, 'user', 'alice@example.com', '13900139001', 100))
        conn.commit()
    conn.close()


init_db()


# ── 工具函数 ────────────────────────────────────────────
def sanitize_username(username):
    username = (username or '').strip()
    if not re.match(r'^[a-zA-Z0-9_\-]{2,20}$', username):
        return ''
    return username


def sanitize_email(email):
    email = (email or '').strip().lower()
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return ''
    if len(email) > 100:
        return ''
    return email


def sanitize_phone(phone):
    phone = (phone or '').strip()
    if not re.match(r'^1[3-9]\d{9}$', phone):
        return ''
    return phone


def validate_password(password):
    if len(password) < 8 or len(password) > 64:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True


# ── 登录频率限制 ────────────────────────────────────────
LOGIN_ATTEMPTS = {}

def is_rate_limited(ip, max_attempts=5, window=60):
    now = time.time()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < window]
    if len(LOGIN_ATTEMPTS[ip]) >= max_attempts:
        return True
    LOGIN_ATTEMPTS[ip].append(now)
    return False


# ── CSRF 防护 ──────────────────────────────────────────
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                abort(403, description='CSRF 验证失败')
        return f(*args, **kwargs)
    return decorated


app.jinja_env.globals['csrf_token'] = generate_csrf_token


# ── 安全响应头 ──────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# ── 审计日志 ────────────────────────────────────────────
def log_action(action, detail=''):
    username = session.get('username', '')
    ip = request.remote_addr or ''
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_logs (username, action, detail, ip) VALUES (?, ?, ?, ?)",
        (username, action, detail, ip)
    )
    conn.commit()
    conn.close()


# ── 装饰器 ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def get_user_info(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, email, phone, balance, created_at FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None


# ── 首页 ──────────────────────────────────────────────
@app.route('/')
def index():
    if 'username' in session:
        user = get_user_info(session['username'])
        if not user:
            session.clear()
            return redirect(url_for('login'))

        keyword = request.args.get('keyword', '')
        results = None
        if keyword:
            conn = get_db()
            c = conn.cursor()
            sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
            print(f"[SQL] {sql} | keyword=%{keyword}%")
            c.execute(sql, (f'%{keyword}%', f'%{keyword}%'))
            results = c.fetchall()
            conn.close()

        return render_template('index.html', user=user, results=results, keyword=keyword)
    return render_template('index.html')


# ── 登录 ─────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if is_rate_limited(ip):
            log_action('RATE_LIMITED', f'IP {ip} 触发登录频率限制')
            flash('登录尝试过于频繁，请 60 秒后再试', 'error')
            return render_template('login.html')

        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            LOGIN_ATTEMPTS.pop(ip, None)
            log_action('LOGIN', f'用户 {username} 登录成功')
            flash(f'欢迎回来，{user["username"]}！', 'success')
            return redirect(url_for('index'))
        else:
            log_action('LOGIN_FAILED', f'登录失败: {username}')
            flash('用户名或密码错误！', 'error')

    return render_template('login.html')


# ── 退出（POST 方式防 CSRF 强制登出）─
@app.route('/logout', methods=['POST'])
@csrf_required
def logout():
    username = session.get('username', '')
    if username:
        log_action('LOGOUT', f'用户 {username} 退出登录')
    session.clear()
    if username:
        flash(f'{username} 已安全退出', 'info')
    return redirect(url_for('login'))


# ── 注册 ─────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = sanitize_username(request.form.get('username', ''))
        password = request.form.get('password', '')
        email = sanitize_email(request.form.get('email', ''))

        errors = []
        if not username:
            errors.append('用户名格式无效（2~20位字母/数字/下划线/短横）')
        if not validate_password(password):
            errors.append('密码强度不足（至少8位，包含大小写字母和数字）')
        if not email:
            errors.append('邮箱格式无效')

        if errors:
            return render_template('register.html', errors=errors)

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            log_action('REGISTER_FAILED', f'注册失败-用户名已存在: {username}')
            return render_template('register.html', errors=['用户名已存在'])

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                  (username, pw_hash, email))
        conn.commit()
        conn.close()
        log_action('REGISTER', f'新用户注册: {username}')
        flash('注册成功，请登录！', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ── 上传头像 ─────────────────────────────────────────────
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('请选择要上传的文件', 'error')
            return render_template('upload.html')

        # 使用用户上传的原始文件名保存（不做任何检查）
        filename = file.filename
        upload_path = os.path.join('static/uploads', filename)
        file.save(upload_path)

        file_url = url_for('static', filename=f'uploads/{filename}')
        log_action('UPLOAD', f'用户上传文件: {filename}')
        flash('文件上传成功！', 'success')
        return render_template('upload.html', uploaded=True, file_url=file_url, filename=filename)

    return render_template('upload.html')


# ── 个人中心 ─────────────────────────────────────────────
@app.route('/profile')
def profile():
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        flash('请指定用户ID', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('index'))

    return render_template('profile.html', user=dict(user))


# ── 充值 ─────────────────────────────────────────────────
@app.route('/recharge', methods=['POST'])
def recharge():
    user_id = request.form.get('user_id', type=int)
    amount = request.form.get('amount', type=float)

    if not user_id or amount is None:
        flash('参数错误', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
    conn.commit()
    conn.close()

    log_action('RECHARGE', f'用户ID {user_id} 充值 {amount}')
    flash(f'充值成功！变动金额：{amount}', 'success')
    return redirect(url_for('profile', user_id=user_id))


# ── 修改密码 ─────────────────────────────────────────────
@app.route('/change-password', methods=['POST'])
def change_password():
    if 'username' not in session:
        flash('请先登录', 'warning')
        return redirect(url_for('login'))

    username = request.form.get('username', '')
    new_password = request.form.get('new_password', '')

    if not username or not new_password:
        flash('参数错误', 'error')
        return redirect(url_for('profile', user_id=session.get('user_id')))

    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE username = ?", (pw_hash, username))
    conn.commit()
    conn.close()

    log_action('PWD_CHANGED', f'用户 {username} 密码被修改')
    flash(f'用户 {username} 密码修改成功！', 'success')
    return redirect(url_for('profile', user_id=session.get('user_id')))


# ── 动态页面加载 ─────────────────────────────────────────
@app.route('/page')
def dynamic_page():
    name = request.args.get('name', '')
    if not name:
        page_content = '请指定页面名称'
    else:
        file_path = os.path.join('pages', name)
        if os.path.isfile(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                page_content = f.read()
        else:
            file_path_html = os.path.join('pages', name + '.html')
            if os.path.isfile(file_path_html):
                with open(file_path_html, 'r', encoding='utf-8') as f:
                    page_content = f.read()
            else:
                page_content = '页面不存在'

    if 'username' in session:
        user = get_user_info(session['username'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        return render_template('index.html', user=user, page_content=page_content)

    return render_template('index.html', page_content=page_content)


# ── URL 抓取（安全加固版）────────────────────────────────
def is_safe_url(url):
    """检查 URL 是否安全：仅允许 http/https，禁止内网地址"""
    try:
        parsed = urllib.parse.urlparse(url)
        # 只允许 http 和 https 协议
        if parsed.scheme not in ('http', 'https'):
            return False, '仅支持 http 和 https 协议'

        # 解析目标主机名
        hostname = parsed.hostname
        if not hostname:
            return False, '无效的 URL'

        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return False, '无法解析域名'

        # 判断是否为内网/私有 IP
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return False, '不允许访问内网地址'
        if ip_obj.is_loopback:
            return False, '不允许访问回环地址'
        if ip_obj.is_link_local:
            return False, '不允许访问链路本地地址'

        return True, None

    except Exception:
        return False, 'URL 格式无效'


@app.route('/fetch-url', methods=['POST'])
def fetch_url():
    if 'username' not in session:
        flash('请先登录', 'warning')
        return redirect(url_for('login'))

    target_url = request.form.get('url', '').strip()
    if not target_url:
        flash('请输入 URL', 'error')
        return render_template('index.html', user=get_user_info(session['username']))

    # URL 安全检查
    safe, msg = is_safe_url(target_url)
    if not safe:
        flash(f'URL 被拒绝：{msg}', 'error')
        user = get_user_info(session['username'])
        return render_template('index.html', user=user)

    try:
        req = urllib.request.Request(target_url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            status_code = response.getcode()
            content = response.read().decode('utf-8', errors='replace')
            if len(content) > 5000:
                content = content[:5000] + '\n\n... (truncated to 5000 chars)'

        log_action('FETCH_URL', f'抓取 URL: {target_url} 状态码: {status_code}')
        result = {'url': target_url, 'status_code': status_code, 'content': content}
    except urllib.error.HTTPError as e:
        result = {'url': target_url, 'status_code': e.code, 'content': f'HTTP 错误: {e.code} {e.reason}'}
    except urllib.error.URLError as e:
        result = {'url': target_url, 'status_code': 'N/A', 'content': f'URL 错误: {str(e.reason)}'}
    except Exception as e:
        result = {'url': target_url, 'status_code': 'N/A', 'content': f'错误: {str(e)}'}

    user = get_user_info(session['username'])
    return render_template('index.html', user=user, fetch_result=result)


# ── Ping 网络诊断 ───────────────────────────────────────
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if 'username' not in session:
        flash('请先登录', 'warning')
        return redirect(url_for('login'))

    result = None
    if request.method == 'POST':
        ip = request.form.get('ip', '')
        if ip:
            try:
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                safe_ip = shlex.quote(ip.strip())
                cmd = f"ping {param} 3 {safe_ip}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
                result = output.decode('utf-8', errors='replace')
                log_action('PING', f'Ping: {ip}')
            except subprocess.CalledProcessError as e:
                result = f'命令执行失败（返回码: {e.returncode}）:\n{e.output.decode("utf-8", errors="replace")}'
            except subprocess.TimeoutExpired:
                result = 'Ping 超时（30秒）'
            except Exception as e:
                result = f'错误: {str(e)}'

    return render_template('ping.html', result=result)


# ── XML 数据导入 ───────────────────────────────────────
@app.route('/xml-import', methods=['GET', 'POST'])
def xml_import():
    if 'username' not in session:
        flash('请先登录', 'warning')
        return redirect(url_for('login'))

    result = None
    error = None

    if request.method == 'POST':
        xml_data = request.form.get('xml_data', '').strip()
        if not xml_data:
            error = '请输入 XML 数据'
        else:
            try:
                # 安全处理：移除 DOCTYPE 声明（防止 XXE 攻击）
                safe_xml = re.sub(r'<!DOCTYPE\s+\w+\s*\[.*?\]\s*>', '', xml_data, flags=re.DOTALL)
                safe_xml = safe_xml.replace('<?xml version="1.0"?>', '').replace('<?xml version="1.0" encoding="UTF-8"?>', '')
                safe_xml = safe_xml.replace('<?xml version="1.0" encoding="utf-8"?>', '')

                # 检查是否包含实体引用（说明可能是 XXE 攻击）
                if re.search(r'&[a-z]+;', safe_xml):
                    error = 'XML 中包含不支持的实体引用'
                else:
                    # 解析 XML 提取用户数据
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(safe_xml)
                    users = []
                    for user_elem in root.findall('.//user'):
                        name = user_elem.findtext('name', '')
                        email = user_elem.findtext('email', '')
                        users.append({'name': name, 'email': email})

                    result = json.dumps({'users': users, 'total': len(users)}, ensure_ascii=False, indent=2)
                    log_action('XML_IMPORT', f'导入 {len(users)} 个用户')

            except ET.ParseError as e:
                error = f'XML 解析错误: {str(e)}'
            except Exception as e:
                error = f'处理失败: {str(e)}'

    return render_template('xml_import.html', result=result, error=error)


# ── 登出确认页 ──────────────────────────────────────────
@app.route('/logout-page')
def logout_page():
    return render_template('logout.html')


if __name__ == '__main__':
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, host='127.0.0.1', port=5000)
