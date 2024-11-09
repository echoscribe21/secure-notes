from flask import Flask, render_template, request, jsonify, session, redirect
import bcrypt
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
from datetime import datetime, timedelta
import sqlite3
import logging
from functools import wraps

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Constants
DATABASE = 'secure_notes.db'
PEPPER = "S3cureP3pperStr1ng!"  # Store this securely in production
ADMIN_USERNAME = "admin"  # Change this in production
ADMIN_PASSWORD = "Admin@SecureNotes2024!"  # Change this in production
ITEMS_PER_PAGE = 10

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        # Create tables
        c.executescript('''
            DROP TABLE IF EXISTS notes;
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS admins;
            DROP TABLE IF EXISTS user_activity;
            
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                decryption_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );
            
            CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                encrypted_content TEXT,
                created_at TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username)
            );
            
            CREATE TABLE admins (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE user_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username)
            );
        ''')
        
        # Create default admin account
        admin_password_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt())
        c.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)',
                 (ADMIN_USERNAME, admin_password_hash))
        
        conn.commit()
        logging.debug('Database initialized successfully with admin account')

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def log_activity(username, action):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO user_activity (username, action) VALUES (?, ?)',
                     (username, action))
    except Exception as e:
        logging.error(f"Error logging activity: {str(e)}")

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_username' not in session:
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated_function

def derive_key(password, salt=None):
    if salt is None:
        salt = bcrypt.gensalt()
    password_with_pepper = password + PEPPER
    key = bcrypt.kdf(
        password=password_with_pepper.encode(),
        salt=salt,
        desired_key_bytes=32,
        rounds=200
    )
    return key, salt

def encrypt_message(message, decryption_key):
    try:
        key, salt = derive_key(decryption_key)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        if isinstance(message, str):
            message = message.encode()
            
        encrypted_data = encryptor.update(message) + encryptor.finalize()
        return f"{salt.hex()}:{nonce.hex()}:{encryptor.tag.hex()}:{encrypted_data.hex()}"
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        raise

def decrypt_message(encrypted_message, decryption_key):
    try:
        salt_hex, nonce_hex, tag_hex, data_hex = encrypted_message.split(':')
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        tag = bytes.fromhex(tag_hex)
        encrypted_data = bytes.fromhex(data_hex)
        
        key, _ = derive_key(decryption_key, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise

def validate_password(password):
    if len(password) < 16:
        return False, "Password must be at least 16 characters long."
    if not any(char.isupper() for char in password):
        return False, "Password must contain uppercase characters."
    if not any(char.islower() for char in password):
        return False, "Password must contain lowercase characters."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain numbers."
    if not any(char in "!@#$%^&*()-_+=" for char in password):
        return False, "Password must contain special characters."
    return True, "Password valid"

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return render_template('dashboard.html')
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    
    valid, msg = validate_password(password)
    if not valid:
        return jsonify({'error': msg}), 400
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            if c.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
                return jsonify({'error': 'Username already exists'}), 400
            
            decryption_key = secrets.token_hex(16)
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            
            c.execute('''
                INSERT INTO users (username, password_hash, decryption_key, created_at) 
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, decryption_key, datetime.now()))
            
            log_activity(username, "Account created")
            session['username'] = username
            
            return jsonify({
                'success': True,
                'decryption_key': decryption_key,
                'message': 'Account created successfully. SAVE YOUR DECRYPTION KEY!'
            })
    except Exception as e:
        logging.error(f"Signup error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            user = c.execute('SELECT password_hash FROM users WHERE username = ?', 
                           (username,)).fetchone()
            
            if user and bcrypt.checkpw(password.encode(), user['password_hash']):
                c.execute('UPDATE users SET last_login = ? WHERE username = ?',
                         (datetime.now(), username))
                session['username'] = username
                log_activity(username, "Logged in")
                return jsonify({'success': True})
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/create_note', methods=['POST'])
def create_note():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        content = request.form['content']
        
        with get_db() as conn:
            c = conn.cursor()
            
            # Get decryption key
            user = c.execute('SELECT decryption_key FROM users WHERE username = ?', 
                           (session['username'],)).fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Encrypt and store note
            encrypted_content = encrypt_message(content, user['decryption_key'])
            c.execute('''
                INSERT INTO notes (username, encrypted_content, created_at) 
                VALUES (?, ?, ?)
            ''', (session['username'], encrypted_content, datetime.now().isoformat()))
            
            log_activity(session['username'], "Created new note")
            return jsonify({'success': True, 'message': 'Note created successfully'})
    except Exception as e:
        logging.error(f"Create note error: {str(e)}")
        return jsonify({'error': 'Failed to create note'}), 500

@app.route('/view_notes', methods=['POST'])
def view_notes():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    provided_key = request.form.get('decryption_key')
    if not provided_key:
        return jsonify({'error': 'Decryption key is required'}), 400

    try:
        with get_db() as conn:
            c = conn.cursor()
            notes = c.execute('''
                SELECT encrypted_content, created_at 
                FROM notes 
                WHERE username = ? 
                ORDER BY created_at DESC
            ''', (session['username'],)).fetchall()

            decrypted_notes = []
            for note in notes:
                try:
                    decrypted_content = decrypt_message(note['encrypted_content'], provided_key).decode()
                    decrypted_notes.append({
                        'content': decrypted_content,
                        'created_at': note['created_at']
                    })
                except Exception as e:
                    logging.error(f"Decryption error for note: {str(e)}")
                    decrypted_notes.append({
                        'content': 'Error: Could not decrypt this note with the provided key',
                        'created_at': note['created_at']
                    })

            log_activity(session['username'], "Viewed notes")
            return jsonify({'success': True, 'notes': decrypted_notes})
    except Exception as e:
        logging.error(f"View notes error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve notes'}), 500

@app.route('/logout')
def logout():
    if 'username' in session:
        log_activity(session['username'], "Logged out")
    session.pop('username', None)
    return redirect('/')

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    
    username = request.form['username']
    password = request.form['password']
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            admin = c.execute('SELECT password_hash FROM admins WHERE username = ?',
                           (username,)).fetchone()
            
            if admin and bcrypt.checkpw(password.encode(), admin['password_hash']):
                session['admin_username'] = username
                return jsonify({'success': True})
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logging.error(f"Admin login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/stats')
@admin_required
def get_stats():
    try:
        with get_db() as conn:
            c = conn.cursor()
            stats = {
                'total_users': c.execute('SELECT COUNT(*) FROM users').fetchone()[0],
                'total_notes': c.execute('SELECT COUNT(*) FROM notes').fetchone()[0],
                'active_users': c.execute('''
                    SELECT COUNT(DISTINCT username) FROM user_activity 
                    WHERE timestamp > datetime('now', '-7 days')
                ''').fetchone()[0],
                'recent_signups': c.execute('''
                    SELECT COUNT(*) FROM users 
                    WHERE created_at > datetime('now', '-24 hours')
                ''').fetchone()[0]
            }
            return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logging.error(f"Get stats error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve stats'}), 500

@app.route('/admin/users')
@admin_required
def get_users():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', ITEMS_PER_PAGE))
    offset = (page - 1) * per_page
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Get total count for pagination
            total_users = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            total_pages = (total_users + per_page - 1) // per_page
            
            # Get paginated users
            users = c.execute('''
                SELECT username, created_at, last_login,
                       (SELECT COUNT(*) FROM notes WHERE notes.username = users.username) as note_count
                FROM users
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ''', (per_page, offset)).fetchall()
            
            return jsonify({
                'success': True,
                'users': [{
                    'username': user['username'],
                    'created_at': user['created_at'],
                    'last_login': user['last_login'],
                    'note_count': user['note_count']
                } for user in users],
                'total_pages': total_pages,
                'current_page': page
            })
    except Exception as e:
        logging.error(f"Get users error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve users'}), 500

@app.route('/admin/users/search')
@admin_required
def search_users():
    query = request.args.get('q', '')
    try:
        with get_db() as conn:
            c = conn.cursor()
            users = c.execute('''
                SELECT username, created_at, last_login,
                       (SELECT COUNT(*) FROM notes WHERE notes.username = users.username) as note_count
                FROM users
                WHERE username LIKE ?
                ORDER BY created_at DESC
            ''', (f'%{query}%',)).fetchall()
            
            return jsonify({
                'success': True,
                'users': [{
                    'username': user['username'],
                    'created_at': user['created_at'],
                    'last_login': user['last_login'],
                    'note_count': user['note_count']
                } for user in users]})
    except Exception as e:
        logging.error(f"Search users error: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/admin/user/<username>/details')
@admin_required
def get_user_details(username):
    try:
        with get_db() as conn:
            c = conn.cursor()
            user = c.execute('''
                SELECT username, created_at, last_login,
                       (SELECT COUNT(*) FROM notes WHERE notes.username = users.username) as note_count,
                       (SELECT SUM(LENGTH(encrypted_content)) FROM notes WHERE notes.username = users.username) as storage_used
                FROM users
                WHERE username = ?
            ''', (username,)).fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Get recent activity
            activity = c.execute('''
                SELECT timestamp, action 
                FROM user_activity 
                WHERE username = ? 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''', (username,)).fetchall()
            
            # Get user's decryption key (for admin purposes)
            decryption_key = c.execute('''
                SELECT decryption_key
                FROM users
                WHERE username = ?
            ''', (username,)).fetchone()['decryption_key']
            
            return jsonify({
                'success': True,
                'user': {
                    'username': user['username'],
                    'created_at': user['created_at'],
                    'last_login': user['last_login'],
                    'note_count': user['note_count'],
                    'storage_used': f"{user['storage_used']/1024:.2f} KB" if user['storage_used'] else "0 KB",
                    'decryption_key': decryption_key,
                    'activity': [{
                        'timestamp': act['timestamp'],
                        'action': act['action']
                    } for act in activity]
                }
            })
    except Exception as e:
        logging.error(f"Get user details error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve user details'}), 500

@app.route('/admin/user/<username>/notes')
@admin_required
def get_user_notes(username):
    try:
        with get_db() as conn:
            c = conn.cursor()
            notes = c.execute('''
                SELECT id, encrypted_content, created_at
                FROM notes
                WHERE username = ?
                ORDER BY created_at DESC
            ''', (username,)).fetchall()
            
            # Get user's decryption key to show decrypted content to admin
            user = c.execute('SELECT decryption_key FROM users WHERE username = ?',
                           (username,)).fetchone()
            
            return jsonify({
                'success': True,
                'notes': [{
                    'id': note['id'],
                    'encrypted_content': note['encrypted_content'],
                    'decrypted_content': decrypt_message(note['encrypted_content'], 
                                                       user['decryption_key']).decode(),
                    'created_at': note['created_at']
                } for note in notes]
            })
    except Exception as e:
        logging.error(f"Get user notes error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve notes'}), 500

@app.route('/admin/user/<username>/delete', methods=['POST'])
@admin_required
def delete_user(username):
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Delete user's notes first (due to foreign key constraint)
            c.execute('DELETE FROM notes WHERE username = ?', (username,))
            
            # Delete user's activity logs
            c.execute('DELETE FROM user_activity WHERE username = ?', (username,))
            
            # Delete the user
            c.execute('DELETE FROM users WHERE username = ?', (username,))
            
            return jsonify({
                'success': True,
                'message': f'User {username} and all associated data deleted successfully'
            })
    except Exception as e:
        logging.error(f"Delete user error: {str(e)}")
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/admin/user/<username>/reset-key', methods=['POST'])
@admin_required
def reset_user_key(username):
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Generate new decryption key
            new_key = secrets.token_hex(16)
            
            # Update user's decryption key
            c.execute('UPDATE users SET decryption_key = ? WHERE username = ?',
                     (new_key, username))
            
            log_activity(username, "Decryption key reset by admin")
            
            return jsonify({
                'success': True,
                'new_key': new_key,
                'message': f'Decryption key reset successfully for user {username}'
            })
    except Exception as e:
        logging.error(f"Reset key error: {str(e)}")
        return jsonify({'error': 'Failed to reset decryption key'}), 500

@app.route('/admin/logs')
@admin_required
def get_system_logs():
    days = int(request.args.get('days', 7))
    try:
        with get_db() as conn:
            c = conn.cursor()
            logs = c.execute('''
                SELECT username, action, timestamp
                FROM user_activity
                WHERE timestamp > datetime('now', '-? days')
                ORDER BY timestamp DESC
            ''', (days,)).fetchall()
            
            return jsonify({
                'success': True,
                'logs': [{
                    'username': log['username'],
                    'action': log['action'],
                    'timestamp': log['timestamp']
                } for log in logs]
            })
    except Exception as e:
        logging.error(f"Get logs error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve system logs'}), 500

@app.route('/admin/stats/detailed')
@admin_required
def get_detailed_stats():
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Get various system statistics
            stats = {
                'user_stats': {
                    'total_users': c.execute('SELECT COUNT(*) FROM users').fetchone()[0],
                    'active_users_7d': c.execute('''
                        SELECT COUNT(DISTINCT username) FROM user_activity 
                        WHERE timestamp > datetime('now', '-7 days')
                    ''').fetchone()[0],
                    'active_users_30d': c.execute('''
                        SELECT COUNT(DISTINCT username) FROM user_activity 
                        WHERE timestamp > datetime('now', '-30 days')
                    ''').fetchone()[0],
                    'new_users_24h': c.execute('''
                        SELECT COUNT(*) FROM users 
                        WHERE created_at > datetime('now', '-24 hours')
                    ''').fetchone()[0]
                },
                'note_stats': {
                    'total_notes': c.execute('SELECT COUNT(*) FROM notes').fetchone()[0],
                    'notes_24h': c.execute('''
                        SELECT COUNT(*) FROM notes 
                        WHERE created_at > datetime('now', '-24 hours')
                    ''').fetchone()[0],
                    'total_storage': c.execute('''
                        SELECT SUM(LENGTH(encrypted_content)) FROM notes
                    ''').fetchone()[0] or 0
                },
                'activity_stats': {
                    'logins_24h': c.execute('''
                        SELECT COUNT(*) FROM user_activity 
                        WHERE action = 'Logged in' 
                        AND timestamp > datetime('now', '-24 hours')
                    ''').fetchone()[0],
                    'notes_created_7d': c.execute('''
                        SELECT COUNT(*) FROM user_activity 
                        WHERE action = 'Created new note' 
                        AND timestamp > datetime('now', '-7 days')
                    ''').fetchone()[0]
                }
            }
            
            return jsonify({
                'success': True,
                'stats': stats
            })
    except Exception as e:
        logging.error(f"Get detailed stats error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve detailed statistics'}), 500

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_username', None)
    return redirect('/admin/login')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
    