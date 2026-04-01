from flask_login import UserMixin
from . import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rsa_public_key = db.Column(db.Text, nullable=False)
    rsa_private_key_encrypted = db.Column(db.Text, nullable=False) # Encrypted with user's password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    files = db.relationship('File', backref='owner', lazy=True)
    permissions = db.relationship('Permission', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(128), nullable=False) # The secure random filename on disk
    original_name = db.Column(db.String(128), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # The AES key for this file, encrypted with the owner's RSA public key
    encrypted_aes_key = db.Column(db.Text, nullable=False)

    permissions = db.relationship('Permission', backref='file', lazy=True)
    activities = db.relationship('Activity', backref='file', lazy=True)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # The AES key for this file, encrypted with this user's RSA public key
    encrypted_aes_key = db.Column(db.Text, nullable=False)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=True)
    action = db.Column(db.String(128), nullable=False) # e.g., 'Upload', 'Download', 'Share'
    details = db.Column(db.String(256), nullable=False) # e.g., 'Shared report.pdf with Alice'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='activities', foreign_keys=[user_id])


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
