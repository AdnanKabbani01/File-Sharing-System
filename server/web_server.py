import os
import sys
import time
import json
import threading
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import setup_logger, calculate_file_hash, handle_duplicate_filename, get_file_size
from database import Database, ROLE_ADMIN, ROLE_USER
HOST = '0.0.0.0'
PORT = 5000
SHARED_FILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shared_files')
UPLOAD_TEMP_DIR = os.path.join(SHARED_FILES_DIR, 'temp')
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  
os.makedirs(SHARED_FILES_DIR, exist_ok=True)
os.makedirs(UPLOAD_TEMP_DIR, exist_ok=True)
logger = setup_logger('web_server', 'logs/web_server.log')
db = Database()
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'))
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
upload_progress = {}
upload_progress_lock = threading.Lock()
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.username = username
        self.role = role
@login_manager.user_loader
def load_user(user_id):
    role = db.get_user_role(user_id)
    if role:
        return User(user_id, role)
    return None
@app.context_processor
def inject_now():
    return {'now': datetime.now()}
@app.route('/')
def index():
    """Home page"""
    return redirect(url_for('files'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html')
        success, role = db.authenticate_user(username, password)
        if success:
            user = User(username, role)
            login_user(user)
            logger.info(f"User {username} logged in with role {role}")
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('files'))
        else:
            flash('Invalid username or password', 'danger')
            logger.warning(f"Failed login attempt for user {username}")
    return render_template('login.html')
@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logger.info(f"User {current_user.username} logged out")
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))
@app.route('/files')
@login_required
def files():
    """List available files"""
    files = []
    for filename in os.listdir(SHARED_FILES_DIR):
        file_path = os.path.join(SHARED_FILES_DIR, filename)
        if os.path.isfile(file_path) and not filename.endswith('.part'):
            size = get_file_size(file_path)
            modified = os.path.getmtime(file_path)
            modified_str = datetime.fromtimestamp(modified).strftime('%Y-%m-%d %H:%M:%S')
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size/1024:.2f} KB"
            else:
                size_str = f"{size/(1024*1024):.2f} MB"
            files.append({
                'name': filename,
                'size': size,
                'size_str': size_str,
                'modified': modified,
                'modified_str': modified_str
            })
    files.sort(key=lambda x: x['modified'], reverse=True)
    return render_template('files.html', files=files)
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Upload a file"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        target_path = os.path.join(SHARED_FILES_DIR, filename)
        if os.path.exists(target_path):
            overwrite = request.form.get('overwrite') == 'true'
            if not overwrite:
                new_filename, is_duplicate = handle_duplicate_filename(SHARED_FILES_DIR, filename)
                filename = new_filename
                target_path = os.path.join(SHARED_FILES_DIR, filename)
                logger.info(f"File {file.filename} already exists, renamed to {filename}")
        upload_id = secrets.token_hex(8)
        try:
            temp_path = os.path.join(UPLOAD_TEMP_DIR, f"{upload_id}_{filename}")
            with upload_progress_lock:
                upload_progress[upload_id] = {
                    'filename': filename,
                    'total_size': 0,
                    'uploaded': 0,
                    'status': 'starting'
                }
            file.save(temp_path)
            file_hash = calculate_file_hash(temp_path)
            os.rename(temp_path, target_path)
            with upload_progress_lock:
                if upload_id in upload_progress:
                    del upload_progress[upload_id]
            logger.info(f"File uploaded: {filename} by {current_user.username}")
            flash(f'File {filename} uploaded successfully', 'success')
            return redirect(url_for('files'))
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            flash(f'Error uploading file: {str(e)}', 'danger')
            with upload_progress_lock:
                if upload_id in upload_progress:
                    upload_progress[upload_id]['status'] = 'error'
            return redirect(url_for('upload'))
    return render_template('upload.html')
@app.route('/download/<filename>')
@login_required
def download(filename):
    """Download a file"""
    file_path = os.path.join(SHARED_FILES_DIR, filename)
    if not os.path.exists(file_path):
        flash(f'File {filename} not found', 'danger')
        return redirect(url_for('files'))
    logger.info(f"File downloaded: {filename} by {current_user.username}")
    return send_file(file_path, as_attachment=True)
@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete(filename):
    """Delete a file (admin only)"""
    if current_user.role != ROLE_ADMIN:
        flash('You do not have permission to delete files', 'danger')
        return redirect(url_for('files'))
    file_path = os.path.join(SHARED_FILES_DIR, filename)
    if not os.path.exists(file_path):
        flash(f'File {filename} not found', 'danger')
        return redirect(url_for('files'))
    try:
        os.remove(file_path)
        logger.info(f"File deleted: {filename} by {current_user.username}")
        flash(f'File {filename} deleted successfully', 'success')
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
        flash(f'Error deleting file: {str(e)}', 'danger')
    return redirect(url_for('files'))
@app.route('/users')
@login_required
def users():
    """List users (admin only)"""
    if current_user.role != ROLE_ADMIN:
        flash('You do not have permission to view users', 'danger')
        return redirect(url_for('files'))
    users_list = []
    for username, user_data in db.users.items():
        users_list.append({
            'username': username,
            'role': user_data['role']
        })
    return render_template('users.html', users=users_list)
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    """Add a new user (admin only)"""
    if current_user.role != ROLE_ADMIN:
        flash('You do not have permission to add users', 'danger')
        return redirect(url_for('files'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', ROLE_USER)
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return redirect(url_for('add_user'))
        if role not in [ROLE_ADMIN, ROLE_USER]:
            role = ROLE_USER
        success = db.add_user(username, password, role)
        if success:
            logger.info(f"User {username} added with role {role} by {current_user.username}")
            flash(f'User {username} added successfully', 'success')
            return redirect(url_for('users'))
        else:
            flash(f'Error adding user {username}', 'danger')
    return render_template('add_user.html')
@app.route('/delete_user/<username>', methods=['POST'])
@login_required
def delete_user(username):
    """Delete a user (admin only)"""
    if current_user.role != ROLE_ADMIN:
        flash('You do not have permission to delete users', 'danger')
        return redirect(url_for('files'))
    if username == current_user.username:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('users'))
    success = db.delete_user(username)
    if success:
        logger.info(f"User {username} deleted by {current_user.username}")
        flash(f'User {username} deleted successfully', 'success')
    else:
        flash(f'Error deleting user {username}', 'danger')
    return redirect(url_for('users'))
@app.route('/logs')
@login_required
def logs():
    """View logs (admin only)"""
    if current_user.role != ROLE_ADMIN:
        flash('You do not have permission to view logs', 'danger')
        return redirect(url_for('files'))
    log_files = {
        'server': 'logs/server.log',
        'web_server': 'logs/web_server.log',
        'database': 'logs/database.log'
    }
    log_type = request.args.get('type', 'web_server')
    if log_type not in log_files:
        log_type = 'web_server'
    log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), log_files[log_type])
    log_content = []
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            lines = f.readlines()
            for line in reversed(lines[-100:]):
                log_content.append(line.strip())
    return render_template('logs.html', log_content=log_content, log_type=log_type)
@app.route('/upload_progress/<upload_id>')
@login_required
def get_upload_progress(upload_id):
    """Get upload progress for AJAX requests"""
    with upload_progress_lock:
        if upload_id in upload_progress:
            progress = upload_progress[upload_id]
            if progress['total_size'] > 0:
                percent = int((progress['uploaded'] / progress['total_size']) * 100)
            else:
                percent = 0
            return jsonify({
                'filename': progress['filename'],
                'uploaded': progress['uploaded'],
                'total_size': progress['total_size'],
                'percent': percent,
                'status': progress['status']
            })
    return jsonify({'status': 'not_found'})
def start_web_server():
    """Start the web server"""
    templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    os.makedirs(static_dir, exist_ok=True)
    logger.info(f"Web server starting on {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
if __name__ == "__main__":
    start_web_server()