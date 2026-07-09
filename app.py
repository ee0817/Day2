"""用户信息管理平台 - 安全加固版（含上传功能）"""
import os, re, time, secrets, sqlite3
from functools import wraps
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ── 数据库 ──
def get_db():
    conn = sqlite3.connect('data/users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs("data", exist_ok=True)
    os.makedirs("static/uploads", exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        email TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        balance REAL DEFAULT 0.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, action TEXT NOT NULL,
        detail TEXT DEFAULT '', ip TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for u, p, r, e, ph, b in [
            ('admin','admin123','admin','admin@example.com','13800138000',99999),
            ('alice','alice2025','user','alice@example.com','13900139001',100)]:
            h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
            c.execute("INSERT INTO users (username,password_hash,role,email,phone,balance) VALUES (?,?,?,?,?,?)",(u,h,r,e,ph,b))
        conn.commit()
    conn.close()
init_db()

# ── 工具函数 ──
def sanitize_username(u):
    u = (u or '').strip()
    return u if re.match(r'^[a-zA-Z0-9_\-]{2,20}$', u) else ''
def sanitize_email(e):
    e = (e or '').strip().lower()
    return e if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', e) and len(e)<=100 else ''
def sanitize_phone(p):
    p = (p or '').strip()
    return p if re.match(r'^1[3-9]\d{9}$', p) else ''
def validate_password(p):
    return bool(len(p)>=8 and len(p)<=64 and re.search(r'[A-Z]',p) and re.search(r'[a-z]',p) and re.search(r'\d',p))

# ── 登录限流 ──
LOGIN_ATTEMPTS = {}
def is_rate_limited(ip, max_a=5, window=60):
    now = time.time()
    if ip not in LOGIN_ATTEMPTS: LOGIN_ATTEMPTS[ip]=[]
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now-t<window]
    if len(LOGIN_ATTEMPTS[ip])>=max_a: return True
    LOGIN_ATTEMPTS[ip].append(now)
    return False

# ── CSRF ──
def generate_csrf_token():
    if 'csrf_token' not in session: session['csrf_token']=secrets.token_hex(16)
    return session['csrf_token']
def csrf_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if request.method=='POST':
            token=request.form.get('csrf_token')
            if not token or token!=session.get('csrf_token'): abort(403)
        return f(*a,**kw)
    return wrapper
app.jinja_env.globals['csrf_token']=generate_csrf_token

@app.after_request
def add_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    return response

def log_action(action, detail=''):
    u=session.get('username',''); ip=request.remote_addr or ''
    conn=get_db(); conn.execute("INSERT INTO audit_logs(username,action,detail,ip) VALUES(?,?,?,?)",(u,action,detail,ip))
    conn.commit(); conn.close()

def login_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if 'username' not in session:
            flash('请先登录','warning')
            return redirect(url_for('login'))
        return f(*a,**kw)
    wrapper.__name__ = f.__name__
    return wrapper

def get_user_info(username):
    conn=get_db()
    u=conn.execute("SELECT id,username,role,email,phone,balance,created_at FROM users WHERE username=?",(username,)).fetchone()
    conn.close()
    return dict(u) if u else None

# ── 首页 ──
@app.route('/')
def index():
    if 'username' in session:
        user=get_user_info(session['username'])
        if not user: session.clear(); return redirect(url_for('login'))
        keyword=request.args.get('keyword','')
        results=None
        if keyword:
            conn=get_db()
            conn.execute("SELECT id,username,email,phone FROM users WHERE username LIKE ? OR email LIKE ?",(f'%{keyword}%',f'%{keyword}%'))
            results=conn.fetchall(); conn.close()
        return render_template('index.html',user=user,results=results,keyword=keyword)
    return render_template('index.html')

# ── 登录 ──
@app.route('/login',methods=['GET','POST'])
def login():
    if 'username' in session: return redirect(url_for('index'))
    if request.method=='POST':
        ip=request.remote_addr or 'unknown'
        if is_rate_limited(ip):
            log_action('RATE_LIMITED',f'IP {ip}'); flash('过于频繁，请稍后再试','error')
            return render_template('login.html')
        username=request.form['username']; password=request.form['password']
        conn=get_db(); u=conn.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone(); conn.close()
        if u and bcrypt.checkpw(password.encode(),u['password_hash'].encode()):
            session.permanent=True; session['user_id']=u['id']; session['username']=u['username']; session['role']=u['role']
            LOGIN_ATTEMPTS.pop(ip,None); log_action('LOGIN',f'{username} 登录成功')
            flash(f'欢迎回来，{username}！','success'); return redirect(url_for('index'))
        else:
            log_action('LOGIN_FAILED',f'{username}'); flash('用户名或密码错误！','error')
    return render_template('login.html')

# ── 退出 ──
@app.route('/logout',methods=['POST'])
@csrf_required
def logout():
    u=session.get('username','')
    if u: log_action('LOGOUT',f'{u} 退出')
    session.clear()
    if u: flash(f'{u} 已安全退出','info')
    return redirect(url_for('login'))

@app.route('/logout-page')
def logout_page():
    return render_template('logout.html')

# ── 上传头像（安全加固）──
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

def is_valid_image(stream):
    header = stream.read(20)
    stream.seek(0)
    if header[:2] == b'\xff\xd8': return 'jpg'
    if header[:8] == b'\x89PNG\r\n\x1a\n': return 'png'
    if header[:6] in (b'GIF87a', b'GIF89a'): return 'gif'
    if header[:2] == b'BM': return 'bmp'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP': return 'webp'
    return None

def upload_func():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or f.filename == '':
            flash('请选择要上传的文件', 'error'); return render_template('upload.html')

        original_name = f.filename
        ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
        if ext not in ALLOWED_EXTENSIONS:
            flash('仅允许图片格式：png/jpg/gif/bmp/webp', 'error'); return render_template('upload.html')

        detected = is_valid_image(f)
        if not detected:
            flash('文件内容不是有效的图片格式', 'error'); return render_template('upload.html')

        safe_name = f"{secrets.token_hex(16)}.{detected}"
        upload_path = os.path.join('static/uploads', safe_name)
        f.save(upload_path)

        file_size = os.path.getsize(upload_path)
        if file_size > 2 * 1024 * 1024:
            os.remove(upload_path); flash('文件过大，请上传2MB以内的图片', 'error'); return render_template('upload.html')

        file_url = url_for('static', filename=f'uploads/{safe_name}')
        log_action('UPLOAD', f'{original_name} -> {safe_name}')
        flash('头像上传成功！', 'success')
        return render_template('upload.html', uploaded=True, file_url=file_url, filename=original_name)

    return render_template('upload.html')

app.add_url_rule('/upload', 'upload', login_required(upload_func), methods=['GET','POST'])

# ── 注册 ──
@app.route('/register',methods=['GET','POST'])
def register():
    if 'username' in session: return redirect(url_for('index'))
    if request.method=='POST':
        username=sanitize_username(request.form.get('username',''))
        password=request.form.get('password','')
        email=sanitize_email(request.form.get('email',''))
        errors=[]
        if not username: errors.append('用户名格式无效')
        if not validate_password(password): errors.append('密码强度不足')
        if not email: errors.append('邮箱格式无效')
        if errors: return render_template('register.html',errors=errors)
        conn=get_db()
        if conn.execute("SELECT id FROM users WHERE username=?",(username,)).fetchone():
            conn.close(); return render_template('register.html',errors=['用户名已存在'])
        pw_hash=bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()
        conn.execute("INSERT INTO users(username,password_hash,email) VALUES(?,?,?)",(username,pw_hash,email))
        conn.commit(); conn.close()
        log_action('REGISTER',f'{username} 注册'); flash('注册成功，请登录！','success')
        return redirect(url_for('login'))
    return render_template('register.html')

if __name__=='__main__':
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, host='127.0.0.1', port=5000)
