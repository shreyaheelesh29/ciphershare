from flask import Blueprint, render_template, redirect, url_for, flash, request, session, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from .models import User, File, Permission, Activity, db
from .utils.crypto import CryptoUtils
from .utils.s3 import S3Utils
from flask import current_app
import os
import io
import uuid
from datetime import datetime

def log_activity(user_id, file_id, action, details):
    activity = Activity(user_id=user_id, file_id=file_id, action=action, details=details)
    db.session.add(activity)
    db.session.commit()

auth_bp = Blueprint('auth', __name__)
file_bp = Blueprint('file', __name__)

# Authentication Routes
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('file.index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('auth.register'))
        
        # Generate RSA keys for the user
        private_pem, public_pem = CryptoUtils.generate_rsa_keys()
        
        # Encrypt the private key with user password
        encrypted_private_key = CryptoUtils.encrypt_private_key(private_pem, password)
        
        user = User(username=username, 
                    rsa_public_key=public_pem, 
                    rsa_private_key_encrypted=encrypted_private_key)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful!')
        return redirect(url_for('auth.login'))
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('file.index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Store decrypted private key in session for current session operations
            private_pem = CryptoUtils.decrypt_private_key(user.rsa_private_key_encrypted, password)
            if private_pem:
                session['private_key'] = private_pem
                login_user(user)
                flash('Welcome back to CipherShare!', 'success')
                return redirect(url_for('file.index'))
            else:
                flash('Error decrypting your secure keys.', 'danger')
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    session.pop('private_key', None)
    logout_user()
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    my_files_count = File.query.filter_by(owner_id=current_user.id).count()
    shared_files_count = Permission.query.filter_by(user_id=current_user.id).count()
    return render_template('profile.html', 
                           my_files_count=my_files_count, 
                           shared_files_count=shared_files_count)

@auth_bp.route('/activity')
@login_required
def activity_history():
    all_activities = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.timestamp.desc()).all()
    return render_template('activity.html', activities=all_activities)

@auth_bp.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('file.index'))
    
    total_users = User.query.count()
    total_files = File.query.count()
    all_users = User.query.all()
    all_activities = Activity.query.order_by(Activity.timestamp.desc()).limit(50).all()
    
    return render_template('admin.html', 
                           total_users=total_users, 
                           total_files=total_files, 
                           all_users=all_users, 
                           all_activities=all_activities)

# File Management Routes
@file_bp.route('/')
@login_required
def index():
    my_files = File.query.filter_by(owner_id=current_user.id).all()
    shared_files = Permission.query.filter_by(user_id=current_user.id).all()
    all_users = User.query.filter(User.id != current_user.id).all()
    # Get recent activities (last 10)
    activities = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.timestamp.desc()).limit(10).all()
    return render_template('index.html', my_files=my_files, shared_files=shared_files, all_users=all_users, activities=activities)

@file_bp.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file:
        original_filename = secure_filename(file.filename)
        # Unique filename on disk
        unique_filename = str(uuid.uuid4())
        
        # 1. Generate AES key for the file
        aes_key = CryptoUtils.generate_aes_key()
        
        # 2. Encrypt the file data
        file_data = file.read()
        encrypted_data = CryptoUtils.encrypt_file(file_data, aes_key)
        
        # 3. Encrypt the AES key with user's RSA public key
        encrypted_aes_key = CryptoUtils.rsa_encrypt_aes_key(aes_key, current_user.rsa_public_key)
        
        # 4. Save the encrypted file to disk or S3
        if current_app.config['USE_S3']:
            S3Utils.upload_file(encrypted_data, unique_filename)
        else:
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            with open(upload_path, 'wb') as f:
                f.write(encrypted_data)
        
        # 5. Save metadata to DB
        new_file = File(filename=unique_filename, 
                        original_name=original_filename, 
                        owner_id=current_user.id,
                        encrypted_aes_key=encrypted_aes_key)
        db.session.add(new_file)
        db.session.commit()
        
        log_activity(current_user.id, new_file.id, 'Upload', f'Uploaded and encrypted {original_filename}')
        
        flash('File encrypted and uploaded successfully!', 'success')
        return redirect(url_for('file.index'))

@file_bp.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file_record = File.query.get_or_404(file_id)
    
    # Check if owner or has permission
    encrypted_aes_key = None
    if file_record.owner_id == current_user.id:
        encrypted_aes_key = file_record.encrypted_aes_key
    else:
        perm = Permission.query.filter_by(file_id=file_id, user_id=current_user.id).first()
        if perm:
            encrypted_aes_key = perm.encrypted_aes_key
        else:
            flash('Access denied.')
            return redirect(url_for('file.index'))
    
    # 1. Decrypt AES key with user's RSA private key (from session)
    private_pem = session.get('private_key')
    if not private_pem:
        flash('Session expired or key missing. Please re-login.')
        return redirect(url_for('auth.logout'))
    
    aes_key = CryptoUtils.rsa_decrypt_aes_key(encrypted_aes_key, private_pem)
    if not aes_key:
        flash('Error decrypting file key.')
        return redirect(url_for('file.index'))
    
    # 2. Read encrypted file from disk or S3
    encrypted_data = None
    if current_app.config['USE_S3']:
        encrypted_data = S3Utils.download_file(file_record.filename)
        if not encrypted_data:
            flash('File not found in S3.')
            return redirect(url_for('file.index'))
    else:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.filename)
        if not os.path.exists(file_path):
            flash('File not found on server.')
            return redirect(url_for('file.index'))
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
    
    # 3. Decrypt file data
    decrypted_data = CryptoUtils.decrypt_file(encrypted_data, aes_key)
    if not decrypted_data:
        flash('Error decrypting file content.', 'danger')
        return redirect(url_for('file.index'))
    
    log_activity(current_user.id, file_id, 'Download', f'Downloaded and decrypted {file_record.original_name}')
    
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=file_record.original_name,
        as_attachment=True
    )

@file_bp.route('/preview/<int:file_id>')
@login_required
def preview(file_id):
    file_record = File.query.get_or_404(file_id)
    
    # Check if owner or has permission
    encrypted_aes_key = None
    if file_record.owner_id == current_user.id:
        encrypted_aes_key = file_record.encrypted_aes_key
    else:
        perm = Permission.query.filter_by(file_id=file_id, user_id=current_user.id).first()
        if perm:
            encrypted_aes_key = perm.encrypted_aes_key
        else:
            return "Access denied", 403
    
    private_pem = session.get('private_key')
    if not private_pem:
        return "Session expired", 401
    
    aes_key = CryptoUtils.rsa_decrypt_aes_key(encrypted_aes_key, private_pem)
    if not aes_key:
        print(f"DEBUG: Key decryption failed. Encrypted Key: {encrypted_aes_key[:20]}...")
        return "Error decrypting key", 500
    
    # 2. Read encrypted file from disk or S3
    encrypted_data = None
    if current_app.config['USE_S3']:
        encrypted_data = S3Utils.download_file(file_record.filename)
        if not encrypted_data:
            return "File not found in S3", 404
    else:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.filename)
        if not os.path.exists(file_path):
            return "File not found on server", 404
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
    
    decrypted_data = CryptoUtils.decrypt_file(encrypted_data, aes_key)
    if not decrypted_data:
        return "Error decrypting content", 500
    
    # Infer mime type
    import mimetypes
    mime_type, _ = mimetypes.guess_type(file_record.original_name)
    if not mime_type:
        mime_type = 'application/octet-stream'
        
    return send_file(
        io.BytesIO(decrypted_data),
        mimetype=mime_type
    )

@file_bp.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.owner_id != current_user.id:
        flash('Only the owner can share the file.')
        return redirect(url_for('file.index'))
    
    username_to_share = request.form.get('username')
    recipient = User.query.filter_by(username=username_to_share).first()
    
    if not recipient:
        flash('User not found.')
        return redirect(url_for('file.index'))
    
    if Permission.query.filter_by(file_id=file_id, user_id=recipient.id).first():
        flash('File already shared with this user.')
        return redirect(url_for('file.index'))
    
    # 1. Decrypt file AES key with owner's private key
    private_pem = session.get('private_key')
    aes_key = CryptoUtils.rsa_decrypt_aes_key(file_record.encrypted_aes_key, private_pem)
    
    # 2. Re-encrypt AES key with recipient's public key
    encrypted_aes_key_for_recipient = CryptoUtils.rsa_encrypt_aes_key(aes_key, recipient.rsa_public_key)
    
    # 3. Save permission
    new_perm = Permission(file_id=file_id, user_id=recipient.id, encrypted_aes_key=encrypted_aes_key_for_recipient)
    db.session.add(new_perm)
    db.session.commit()
    
    log_activity(current_user.id, file_id, 'Share', f'Shared {file_record.original_name} with {username_to_share}')
    
    flash(f'File shared with {username_to_share}!', 'success')
    return redirect(url_for('file.index'))
