import json
import logging
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
import html
from flask import Flask, request, jsonify, make_response, g, send_file, render_template
import secrets
import bcrypt
import time
import os
import re
import mimetypes
from cryptography.fernet import Fernet
import io

app = Flask(__name__)

# Configure the Security Event Logger to output structured JSON 
logging.basicConfig(
    filename='logs/security.log',
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger("SecurityLogger")

# --- CONSTANTS & DIRECTORY SETUP ---
DATA_DIR = 'data'
DOCUMENTS_DIR = os.path.join(DATA_DIR, 'documents')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
SESSIONS_FILE = os.path.join(DATA_DIR, 'sessions.json')
DOCS_METADATA_FILE = os.path.join(DATA_DIR, 'documents_meta.json') 
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv'}

for directory in [DATA_DIR, DOCUMENTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# In-memory store for rate limiting (IP -> list of timestamps)
login_attempts_log = {}

# --- DATABASE HELPERS ---
def load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, 'r') as f:
        return json.load(f)

def save_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

# --- VALIDATORS ---
def validate_username(username):
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username)) 

def validate_email(email):
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))

def validate_password_strength(password):
    if len(password) < 12: return False 
    if not re.search(r'[A-Z]', password): return False 
    if not re.search(r'[a-z]', password): return False 
    if not re.search(r'[0-9]', password): return False 
    if not re.search(r'[!@#$%^&*]', password): return False 
    return True

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def has_doc_access(doc_metadata, username, required_level):
    if doc_metadata['owner'] == username:
        return True
    if required_level == 'view' and username in (doc_metadata.get('viewers', []) + doc_metadata.get('editors', [])):
        return True
    if required_level == 'edit' and username in doc_metadata.get('editors', []):
        return True
    return False

# --- LOGGING MANAGEMENT ---
class SecurityLogger:
    def __init__(self, log_file='logs/security.log'):
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity='INFO'):
        log_entry = {
            'event_type': event_type,
            'user_id': user_id,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'details': details
        }
        if severity == 'WARNING':
            self.logger.warning(json.dumps(log_entry))
        elif severity == 'ERROR':
            self.logger.error(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))

security_log = SecurityLogger()

# --- SESSION MANAGEMENT ---
class SessionManager:
    def __init__(self, timeout=1800): 
        self.timeout = timeout
        if not os.path.exists(SESSIONS_FILE):
            save_json(SESSIONS_FILE, {})

    def create_session(self, username):
        token = secrets.token_urlsafe(32)
        session = {
            'token': token,
            'username': username,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        sessions = load_json(SESSIONS_FILE)
        sessions[token] = session
        save_json(SESSIONS_FILE, sessions)
        security_log.log_event('SESSION_CREATED', username, 'New session token generated')
        return token

    def validate_session(self, token):
        sessions = load_json(SESSIONS_FILE)
        if token not in sessions:
            return None
        session = sessions[token]
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy_session(token)
            return None
        
        session['last_activity'] = time.time()
        sessions[token] = session
        save_json(SESSIONS_FILE, sessions)
        return session

    def destroy_session(self, token):
        sessions = load_json(SESSIONS_FILE)
        if token in sessions:
            username = sessions[token].get('username')
            del sessions[token]
            save_json(SESSIONS_FILE, sessions)
            security_log.log_event('SESSION_DESTROYED', username, 'Session token invalidated')

session_manager = SessionManager()

# --- ENCRYPTION MANAGEMENT ---
class EncryptedStorage:
    def __init__(self, key_file='data/secret.key'):
        try:
            with open(key_file, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def encrypt_file_data(self, data_bytes):
        return self.cipher.encrypt(data_bytes)

    def decrypt_file_data(self, encrypted_bytes):
        return self.cipher.decrypt(encrypted_bytes)

crypto_manager = EncryptedStorage()

# --- ACCESS CONTROL DECORATORS ---
@app.before_request
def load_user_session():
    token = request.cookies.get('session_token')
    if token:
        session_data = session_manager.validate_session(token)
        if session_data:
            g.user = session_data['username']
            users = load_json(USERS_FILE)
            g.role = users.get(g.user, {}).get('role', 'guest')
        else:
            g.user, g.role = None, None
    else:
        g.user, g.role = None, None

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if getattr(g, 'user', None) is None:
            security_log.log_event('AUTH_FAILURE', None, 'Unauthorized access attempt', 'WARNING')
            return jsonify({"error": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if getattr(g, 'role', None) != role:
                security_log.log_event('AUTH_FAILURE', getattr(g, 'user', 'Unknown'), f'Insufficient permissions for role {role}', 'WARNING')
                return jsonify({"error": "Forbidden. Insufficient permissions."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def audit_log(action_type):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            file_id = kwargs.get('filename') or request.args.get('file') or "N/A"
            user_id = getattr(g, 'user', 'anonymous')
            
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "user": user_id,
                "ip_address": request.remote_addr,
                "action": action_type,
                "resource": file_id,
                "status": "ATTEMPTED"
            }

            try:
                response = f(*args, **kwargs)
                # Correct non-repudiation status check [cite: 42, 216, 311]
                log_entry["status"] = "SUCCESS" if response.status_code < 400 else "FAILED"
                return response
            except Exception as e:
                log_entry["status"] = "ERROR"
                log_entry["error_msg"] = str(e)
                raise e
            finally:
                logger.info(json.dumps(log_entry))
                
        return decorated_function
    return decorator

# --- ROUTES: AUTHENTICATION ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    password_confirm = data.get('password_confirm', '')

    if password != password_confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if not validate_username(username):
        return jsonify({"error": "Invalid username"}), 400
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not validate_password_strength(password):
        return jsonify({"error": "Password does not meet requirements"}), 400

    users = load_json(USERS_FILE)
    if username in users or any(u.get('email') == email for u in users.values()):
        return jsonify({"error": "Username or email already exists"}), 400

    salt = bcrypt.gensalt(rounds=12) 
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    role = "admin" if len(users) == 0 else "user"

    users[username] = {
        "username": username, "email": email, "password_hash": hashed.decode('utf-8'),
        "created_at": time.time(), "role": role, "failed_attempts": 0, "locked_until": None
    }
    save_json(USERS_FILE, users)
    security_log.log_event('USER_REGISTERED', username, f'New account created with role: {role}')
    return jsonify({"success": True}), 201

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    now = time.time()
    
    global login_attempts_log
    login_attempts_log[ip] = [t for t in login_attempts_log.get(ip, []) if now - t < 60]
    if len(login_attempts_log[ip]) >= 10:
        security_log.log_event('RATE_LIMIT_EXCEEDED', None, f'Too many login attempts from {ip}', 'WARNING')
        return jsonify({"error": "Too many login attempts. Try again in a minute."}), 429
    login_attempts_log[ip].append(now)

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_json(USERS_FILE)
    user = users.get(username)

    if not user:
        security_log.log_event('LOGIN_FAILED', username, 'Invalid username attempted', 'WARNING')
        return jsonify({"error": "Invalid credentials"}), 401

    if user.get("locked_until"):
        if time.time() < user["locked_until"]:
            return jsonify({"error": "Account locked. Try again later."}), 403
        else:
            user["failed_attempts"] = 0
            user["locked_until"] = None

    if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        user["failed_attempts"] = 0
        save_json(USERS_FILE, users)
        token = session_manager.create_session(username)
        security_log.log_event('LOGIN_SUCCESS', username, 'User authenticated successfully')
        
        response = make_response(jsonify({"success": True, "message": "Logged in!"}))
        response.set_cookie('session_token', token, httponly=True, secure=True, samesite='Strict', max_age=1800)
        return response
    else:
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        if user["failed_attempts"] >= 5:
            user["locked_until"] = time.time() + (15 * 60)
            security_log.log_event('ACCOUNT_LOCKED', username, '5 failed login attempts', 'ERROR')
        else:
            security_log.log_event('LOGIN_FAILED', username, 'Invalid password attempted', 'WARNING')
        save_json(USERS_FILE, users)
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
@require_auth
@audit_log("USER_LOGOUT")
def logout():
    token = request.cookies.get('session_token')
    if token:
        session_manager.destroy_session(token)
    response = make_response(jsonify({"success": True, "message": "Logged out"}))
    response.set_cookie('session_token', '', expires=0)
    return response

# --- FILE HANDLING & VERSIONING ---
def safe_file_path(user_path, base_dir, version=None):
    filename = secure_filename(user_path)
    if not filename: raise ValueError("Invalid filename")
    
    if version:
        name, ext = os.path.splitext(filename)
        filename = f"{name}_v{version}{ext}"

    full_path = os.path.abspath(os.path.join(base_dir, filename))
    if not full_path.startswith(os.path.abspath(base_dir)):
        raise ValueError("Path traversal detected")
    return full_path, filename

@app.route('/upload', methods=['POST'])
@require_auth
@audit_log("FILE_UPLOAD")
def upload_file():
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400

    if not allowed_file(file.filename):
        security_log.log_event('UPLOAD_FAILED', g.user, f'Invalid file extension: {file.filename}', 'WARNING')
        return jsonify({"error": "File type not allowed"}), 400

    mime_type, _ = mimetypes.guess_type(file.filename)
    if mime_type in ['application/x-sh', 'application/x-executable', 'text/x-python']:
         return jsonify({"error": "Dangerous file type rejected"}), 400

    docs = load_json(DOCS_METADATA_FILE)
    safe_base_name = secure_filename(file.filename)
    
    if safe_base_name in docs:
        return jsonify({"error": "File already exists. Use /update to add a new version."}), 400

    try:
        safe_path, versioned_name = safe_file_path(file.filename, DOCUMENTS_DIR, version=1)
        encrypted_bytes = crypto_manager.encrypt_file_data(file.read())
        with open(safe_path, 'wb') as f:
            f.write(encrypted_bytes)
        
        docs[safe_base_name] = {'owner': g.user, 'versions': [versioned_name], 'editors': [], 'viewers': []}
        save_json(DOCS_METADATA_FILE, docs)
        security_log.log_event('FILE_UPLOADED', g.user, f'Saved new document: {safe_base_name} (v1)')
        return jsonify({"success": True, "message": f"File {html.escape(safe_base_name)} uploaded securely."}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/update', methods=['POST'])
@require_auth
@audit_log("FILE_UPDATE")
def update_file():
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    docs = load_json(DOCS_METADATA_FILE)
    safe_base_name = secure_filename(file.filename)

    if safe_base_name not in docs: return jsonify({"error": "Document does not exist."}), 404

    if not has_doc_access(docs[safe_base_name], g.user, 'edit'):
        security_log.log_event('AUTH_FAILURE', g.user, f'Attempted to edit without permissions: {safe_base_name}', 'WARNING')
        return jsonify({"error": "Forbidden. You do not have edit access to this document."}), 403

    try:
        new_version_num = len(docs[safe_base_name]['versions']) + 1
        safe_path, versioned_name = safe_file_path(file.filename, DOCUMENTS_DIR, version=new_version_num)
        encrypted_bytes = crypto_manager.encrypt_file_data(file.read())
        with open(safe_path, 'wb') as f:
            f.write(encrypted_bytes)

        docs[safe_base_name]['versions'].append(versioned_name)
        save_json(DOCS_METADATA_FILE, docs)
        security_log.log_event('FILE_UPDATED', g.user, f'Updated document: {safe_base_name} to v{new_version_num}')
        return jsonify({"success": True, "message": f"Document updated to version {new_version_num}"}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/download/<filename>', methods=['GET'])
@require_auth
@audit_log("FILE_DOWNLOAD")
def download_file(filename):
    docs = load_json(DOCS_METADATA_FILE)
    safe_base_name = secure_filename(filename)

    if safe_base_name not in docs: return jsonify({"error": "File not found"}), 404
    if not has_doc_access(docs[safe_base_name], g.user, 'view'):
        security_log.log_event('AUTH_FAILURE', g.user, f'Attempted to download without permissions: {safe_base_name}', 'WARNING')
        return jsonify({"error": "Forbidden. You do not have view access."}), 403

    try:
        latest_version_name = docs[safe_base_name]['versions'][-1]
        safe_path = os.path.join(DOCUMENTS_DIR, latest_version_name)
        with open(safe_path, 'rb') as f:
            encrypted_bytes = f.read()
        decrypted_bytes = crypto_manager.decrypt_file_data(encrypted_bytes)
        return send_file(io.BytesIO(decrypted_bytes), download_name=latest_version_name, as_attachment=True)
    except Exception as e:
        security_log.log_event('DATA_ACCESS_ERROR', g.user, f'Failed to download: {filename}', 'ERROR')
        return jsonify({"error": "Decryption failed or file missing on disk"}), 500

@app.route('/share', methods=['POST'])
@require_auth
@audit_log("FILE_SHARE")
def share_document():
    data = request.get_json()
    filename = secure_filename(data.get('filename', ''))
    target_user = data.get('user')
    role = data.get('role')

    if role not in ['editor', 'viewer']: return jsonify({"error": "Invalid role."}), 400
    users = load_json(USERS_FILE)
    if target_user not in users: return jsonify({"error": "Target user does not exist."}), 400

    docs = load_json(DOCS_METADATA_FILE)
    if filename not in docs: return jsonify({"error": "Document not found."}), 404

    if docs[filename]['owner'] != g.user:
        security_log.log_event('AUTH_FAILURE', g.user, f'Attempted to share {filename} without being owner', 'WARNING')
        return jsonify({"error": "Forbidden. Only the owner can share."}), 403

    if role == 'viewer' and target_user not in docs[filename]['viewers']:
        docs[filename]['viewers'].append(target_user)
    elif role == 'editor' and target_user not in docs[filename]['editors']:
        docs[filename]['editors'].append(target_user)

    save_json(DOCS_METADATA_FILE, docs)
    security_log.log_event('DOCUMENT_SHARED', g.user, f'Shared {filename} with {target_user} as {role}')
    return jsonify({"success": True, "message": f"Successfully shared {html.escape(filename)} with {target_user}."}), 200

# --- SECURITY HEADERS ---
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self';"
    response.headers['X-Frame-Options'] = 'DENY' 
    response.headers['X-Content-Type-Options'] = 'nosniff' 
    response.headers['X-XSS-Protection'] = '1; mode=block' 
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' 
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()' 
    return response

if __name__ == '__main__':
    cert_exists = os.path.exists('cert.pem') and os.path.exists('key.pem')
    if cert_exists:
        app.run(debug=True, port=5000, ssl_context=('cert.pem', 'key.pem'))
    else:
        print("WARNING: cert.pem or key.pem not found. Running without TLS. Transport Encryption will fail.")
        app.run(debug=True, port=5000)