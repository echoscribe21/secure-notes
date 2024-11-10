from flask import Flask, render_template, request, jsonify, session, redirect, send_file
import bcrypt
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
from datetime import datetime, timedelta
import sqlite3
import logging
from functools import wraps
from werkzeug.utils import secure_filename
import io
from dotenv import load_dotenv

load_dotenv()  # Load environment variables

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
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        # Create tables
        c.executescript('''
            DROP TABLE IF EXISTS attachments;
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
            
            CREATE TABLE attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# [Previous routes remain unchanged up to create_note]
# ... [Keep all your existing routes from the previous app.py]

@app.route('/note/<int:note_id>/attach', methods=['POST'])
def attach_file(note_id):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
        
    if file and allowed_file(file.filename):
        try:
            # Read file data
            file_data = file.read()
            if len(file_data) > MAX_FILE_SIZE:
                return jsonify({'error': 'File size exceeds maximum limit'}), 400
            
            with get_db() as conn:
                c = conn.cursor()
                
                # Check if note exists and belongs to user
                note = c.execute('SELECT username FROM notes WHERE id = ?', (note_id,)).fetchone()
                if not note or note['username'] != session['username']:
                    return jsonify({'error': 'Note not found or access denied'}), 404
                
                # Get user's decryption key
                user = c.execute('SELECT decryption_key FROM users WHERE username = ?', 
                               (session['username'],)).fetchone()
                
                # Encrypt file data
                encrypted_data = encrypt_message(file_data, user['decryption_key'])
                
                # Store in database
                c.execute('''
                    INSERT INTO attachments (note_id, filename, encrypted_content, file_type, file_size)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    note_id,
                    secure_filename(file.filename),
                    encrypted_data,
                    file.content_type,
                    len(file_data)
                ))
                
                log_activity(session['username'], f"Added attachment to note {note_id}")
                return jsonify({'success': True, 'message': 'File attached successfully'})
                
        except Exception as e:
            logging.error(f"File attachment error: {str(e)}")
            return jsonify({'error': 'Failed to attach file'}), 500

@app.route('/note/<int:note_id>/attachments', methods=['GET'])
def get_attachments(note_id):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Check if note belongs to user
            note = c.execute('SELECT username FROM notes WHERE id = ?', (note_id,)).fetchone()
            if not note or note['username'] != session['username']:
                return jsonify({'error': 'Note not found or access denied'}), 404
            
            attachments = c.execute('''
                SELECT id, filename, file_type, file_size, created_at
                FROM attachments
                WHERE note_id = ?
                ORDER BY created_at DESC
            ''', (note_id,)).fetchall()
            
            return jsonify({
                'success': True,
                'attachments': [{
                    'id': att['id'],
                    'filename': att['filename'],
                    'file_type': att['file_type'],
                    'file_size': att['file_size'],
                    'created_at': att['created_at']
                } for att in attachments]
            })
            
    except Exception as e:
        logging.error(f"Get attachments error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve attachments'}), 500

@app.route('/attachment/<int:attachment_id>/download', methods=['GET'])
def download_attachment(attachment_id):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Get attachment and verify ownership
            attachment = c.execute('''
                SELECT a.*, n.username
                FROM attachments a
                JOIN notes n ON a.note_id = n.id
                WHERE a.id = ?
            ''', (attachment_id,)).fetchone()
            
            if not attachment or attachment['username'] != session['username']:
                return jsonify({'error': 'Attachment not found or access denied'}), 404
            
            # Get user's decryption key
            user = c.execute('SELECT decryption_key FROM users WHERE username = ?', 
                           (session['username'],)).fetchone()
            
            # Decrypt file data
            decrypted_data = decrypt_message(attachment['encrypted_content'], user['decryption_key'])
            
            return send_file(
                io.BytesIO(decrypted_data),
                mimetype=attachment['file_type'],
                as_attachment=True,
                download_name=attachment['filename']
            )
            
    except Exception as e:
        logging.error(f"Download attachment error: {str(e)}")
        return jsonify({'error': 'Failed to download attachment'}), 500

@app.route('/attachment/<int:attachment_id>/delete', methods=['DELETE'])
def delete_attachment(attachment_id):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Verify ownership
            attachment = c.execute('''
                SELECT n.username
                FROM attachments a
                JOIN notes n ON a.note_id = n.id
                WHERE a.id = ?
            ''', (attachment_id,)).fetchone()
            
            if not attachment or attachment['username'] != session['username']:
                return jsonify({'error': 'Attachment not found or access denied'}), 404
            
            # Delete attachment
            c.execute('DELETE FROM attachments WHERE id = ?', (attachment_id,))
            
            log_activity(session['username'], f"Deleted attachment {attachment_id}")
            return jsonify({'success': True, 'message': 'Attachment deleted successfully'})
            
    except Exception as e:
        logging.error(f"Delete attachment error: {str(e)}")
        return jsonify({'error': 'Failed to delete attachment'}), 500

# [All existing routes remain unchanged]
# ... [Keep all your existing routes from the previous app.py]

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)