import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key')
    
    # DBaaS (RDS PostgreSQL/MySQL) configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///secure_fs.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Storage as a Service (AWS S3) configuration
    USE_S3 = os.environ.get('USE_S3', 'False') == 'True'
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    S3_BUCKET = os.environ.get('S3_BUCKET')
    
    # Local Storage fallback
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
