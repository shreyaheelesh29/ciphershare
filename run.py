from app import create_app, db
import os

app = create_app()

if __name__ == '__main__':
    # Ensure upload directory exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    with app.app_context():
        db.create_all()
    
    app.run(debug=True, port=5000)
