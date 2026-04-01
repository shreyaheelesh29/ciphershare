import boto3
import os
from flask import current_app

class S3Utils:
    @staticmethod
    def get_client():
        return boto3.client(
            's3',
            aws_access_key_id=current_app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=current_app.config['AWS_SECRET_ACCESS_KEY'],
            region_name=current_app.config['AWS_REGION']
        )

    @staticmethod
    def upload_file(file_data, filename):
        if not current_app.config['USE_S3']:
            # Fallback to local storage if needed, though routes.py should handle this
            return False
            
        s3 = S3Utils.get_client()
        bucket = current_app.config['S3_BUCKET']
        s3.put_object(Bucket=bucket, Key=filename, Body=file_data)
        return True

    @staticmethod
    def download_file(filename):
        if not current_app.config['USE_S3']:
            return None
            
        s3 = S3Utils.get_client()
        bucket = current_app.config['S3_BUCKET']
        response = s3.get_object(Bucket=bucket, Key=filename)
        return response['Body'].read()

    @staticmethod
    def delete_file(filename):
        if not current_app.config['USE_S3']:
            return False
            
        s3 = S3Utils.get_client()
        bucket = current_app.config['S3_BUCKET']
        s3.delete_object(Bucket=bucket, Key=filename)
        return True
