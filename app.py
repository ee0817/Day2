from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
from functools import wraps
from datetime import datetime

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
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ('admin', pw, 'admin'))
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ('user1', bcrypt.hashpw(b'password1', bcrypt.gensalt()).decode(), 'user'))
        conn.commit()
    conn.close()


init_db()


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
            return render_template('index.html', username=session['username'], role=session['role'], flash_error='⚠️ 权限不足，仅管理员可访问'), 403
        return f(*args, **kwargs)
    return decorated


# ── 路由 ─────────────────────────────────────────────────
@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'], role=session['role'])
    return render_template('index.html')


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


@app.route('/logout')
def logout():
    username = session.get('username', '')
    if username:
        log_action('LOGOUT', f'用户 {username} 退出登录')
    session.clear()
    if username:
        flash(f'👋 {username} 已安全退出', 'info')
    return redirect(url_for('login'))


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


@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at FROM users ORDER BY id")
    users = c.fetchall()
    c.execute("SELECT COUNT(*) FROM audit_logs")
    log_count = c.fetchone()[0]
    conn.close()
    return render_template('admin.html', users=users, total=len(users), log_count=log_count)


@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, action, detail, ip, created_at FROM audit_logs ORDER BY id DESC LIMIT 50")
    logs = c.fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
