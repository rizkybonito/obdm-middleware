import os
from flask import Flask, current_app

class Config:
    """Configuration class to set utility."""
    API_BASE_URL = os.environ.get('API_BASE_URL', "http://10.10.6.40:8080/api/v1/")
    CLUSTER_NAME = os.environ.get('CLUSTER_NAME')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'rahasia-banget')
    TOKEN_EXPIRY_HOURS = 2
    AES_KEY = b"optimasidataonyx" 

class DevelopmentConfig(Config):
    """Configuration to set credential to access ambari"""
    DEBUG = True
    CORS_ORIGINS = "*"
    DEFAULT_USERNAME = os.environ.get('DEFAULT_USERNAME', 'admin')
    DEFAULT_PASSWORD = os.environ.get('DEFAULT_PASSWORD', 'admin')

def set_cluster_name_in_config(app: Flask, cluster_name: str):
    """Utility to set the CLUSTER_NAME in the application config."""
    app.config['CLUSTER_NAME'] = cluster_name