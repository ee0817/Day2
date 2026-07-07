"""🔐 安全用户管理平台 - Flask 全功能版"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
from functools import wraps
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'benben-secret-key-2026!!'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800


# ── 数据库 ───────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
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
        c.execute("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
                  ('admin', pw, 'admin', 'admin@example.com'))
        c.execute("INSERT INTO users (username, password_hash, role, email, balance) VALUES (?, ?, ?, ?, ?)",
                  ('user1', bcrypt.hashpw(b'password1', bcrypt.gensalt()).decode(), 'user', 'user1@example.com', 100.0))
        c.execute("INSERT INTO users (username, password_hash, role, email, balance) VALUES (?, ?, ?, ?, ?)",
                  ('test', bcrypt.hashpw(b'Test@12345', bcrypt.gensalt()).decode(), 'user', 'test@example.com', 50.0))
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


# ── 安全响应头 ──────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
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


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return render_template('index.html', username=session['username'], role=session['role'],
                                   flash_error='⚠️ 权限不足，仅管理员可访问'), 403
        return f(*args, **kwargs)
    return decorated


def get_user_info(username):
    """获取用户公开信息"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, email, phone, balance, created_at FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None


# ── 路由 ─────────────────────────────────────────────────
@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'], role=session['role'])
    return render_template('index.html')


# ── 登录 ─────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
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
            log_action('LOGIN', f'用户 {username} 登录成功')
            flash(f'👋 欢迎回来，{user["username"]}！', 'success')
            return redirect(url_for('index'))
        else:
            log_action('LOGIN_FAILED', f'登录失败: {username}')
            flash('❌ 用户名或密码错误！', 'error')

    return render_template('login.html')


# ── 退出 ─────────────────────────────────────────────────
@app.route('/logout')
def logout():
    username = session.get('username', '')
    if username:
        log_action('LOGOUT', f'用户 {username} 退出登录')
    session.clear()
    if username:
        flash(f'👋 {username} 已安全退出', 'info')
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
        flash(f'✅ 注册成功，请登录！', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ── 个人中心 ─────────────────────────────────────────────
@app.route('/profile')
@login_required
def profile():
    user = get_user_info(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit():
    if request.method == 'POST':
        email = sanitize_email(request.form.get('email', ''))
        phone = sanitize_phone(request.form.get('phone', ''))

        errors = []
        if not email:
            errors.append('邮箱格式无效')
        if not phone:
            errors.append('手机号格式无效（11位大陆手机号）')

        if errors:
            user = get_user_info(session['username'])
            return render_template('profile_edit.html', user=user, errors=errors)

        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET email = ?, phone = ? WHERE id = ?",
                  (email, phone, session['user_id']))
        conn.commit()
        conn.close()
        log_action('PROFILE_UPDATE', f'{session["username"]} 更新个人信息')
        flash('✅ 个人信息已更新', 'success')
        return redirect(url_for('profile'))

    user = get_user_info(session['username'])
    return render_template('profile_edit.html', user=user)


# ── 修改密码 ─────────────────────────────────────────────
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_pw = request.form['old_password']
        new_pw = request.form['new_password']

        if len(new_pw) < 6:
            flash('❌ 新密码至少6位', 'error')
            return render_template('change_password.html')

        if old_pw == new_pw:
            flash('❌ 新密码不能与原密码相同', 'error')
            return render_template('change_password.html')

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()

        if not user or not bcrypt.checkpw(old_pw.encode(), user['password_hash'].encode()):
            conn.close()
            log_action('PWD_FAILED', f'{session["username"]} 修改密码-原密码错误')
            flash('❌ 原密码错误', 'error')
            return render_template('change_password.html')

        new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, session['user_id']))
        conn.commit()
        conn.close()
        log_action('PWD_CHANGED', f'{session["username"]} 修改密码成功')
        flash('✅ 密码修改成功', 'success')

    return render_template('change_password.html')


# ── 管理面板 ─────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, email, phone, balance, created_at FROM users ORDER BY id")
    users = c.fetchall()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM audit_logs")
    log_count = c.fetchone()[0]
    conn.close()
    return render_template('admin.html', users=[dict(u) for u in users],
                           total=total_users, log_count=log_count)


@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_user_edit(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()

    if not user:
        conn.close()
        flash('❌ 用户不存在', 'error')
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        email = sanitize_email(request.form.get('email', ''))
        phone = sanitize_phone(request.form.get('phone', ''))
        try:
            balance = float(request.form.get('balance', 0))
        except ValueError:
            balance = 0.0
        role = request.form.get('role', 'user')

        if role not in ('admin', 'user'):
            role = 'user'
        if not email:
            flash('❌ 邮箱格式无效', 'error')
            return render_template('admin_user_edit.html', user=dict(user))

        c.execute("UPDATE users SET email = ?, phone = ?, balance = ?, role = ? WHERE id = ?",
                  (email, phone, balance, role, user_id))
        conn.commit()
        log_action('ADMIN_EDIT_USER', f'管理员 {session["username"]} 编辑用户 {user["username"]}')
        conn.close()
        flash(f'✅ 已更新用户 {user["username"]} 的信息', 'success')
        return redirect(url_for('admin_panel'))

    conn.close()
    return render_template('admin_user_edit.html', user=dict(user))


# ── 审计日志 ─────────────────────────────────────────────
@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, action, detail, ip, created_at FROM audit_logs ORDER BY id DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
