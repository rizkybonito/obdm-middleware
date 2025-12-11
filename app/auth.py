import os
import base64
import jwt
import datetime
from functools import wraps

from flask import request, jsonify, make_response, current_app
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag
from werkzeug.exceptions import Unauthorized, Forbidden, InternalServerError

_cached_credentials = {}

def encrypt_password(password: str) -> bytes:
    """Encrypts a password using AES in CBC mode."""
    key = current_app.config['AES_KEY']
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()
    
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
    return iv + encrypted_password

def decrypt_password(encrypted_password: bytes) -> str:
    """Decrypts AES-encrypted password data."""
    key = current_app.config['AES_KEY']
    try:
        iv = encrypted_password[:16]
        encrypted_password_data = encrypted_password[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted_password_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_password = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted_password.decode()
    except InvalidTag:
        current_app.logger.error("Decryption failed: Invalid tag/data.")
        raise Unauthorized("Invalid decryption data.")
    except Exception as e:
        current_app.logger.error(f"Decryption error: {e}")
        raise Unauthorized("Failed to decrypt credentials.")

def get_auth_credentials():
    """Retrieves cached credentials for the current request's remote address."""
    return _cached_credentials.get(request.environ.get('REMOTE_ADDR'))

def set_auth_credentials(username, password):
    """Caches credentials for the current request's remote address."""
    _cached_credentials[request.environ.get('REMOTE_ADDR')] = (username, password)

def auth_required(f):
    """Decorator to ensure valid JWT is provided in the Authorization header."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)

        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise Unauthorized("Authorization header missing.")
        
        try:
            scheme, token = auth_header.split(" ", 1)
            if scheme.lower() != 'bearer':
                raise Unauthorized("Authorization scheme must be 'Bearer'.")
            decoded_data = jwt.decode(
                token, 
                key=current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )            
            key = decoded_data.get('key')
            username = decoded_data.get('username')
            
            if not key or not username:
                raise Forbidden("Invalid token structure (missing key or username).")
                
            decoded_bytes = base64.b64decode(key)
            password = decrypt_password(decoded_bytes)
            set_auth_credentials(username, password)
        except jwt.ExpiredSignatureError:
            raise Unauthorized("Token has expired.")
        except jwt.InvalidSignatureError:
            raise Unauthorized("Invalid token signature.")
        except jwt.InvalidTokenError:
            raise Unauthorized("Invalid token.")
        except Unauthorized as e:
            raise e 
        except Exception as e:
            current_app.logger.error(f"Token processing failed: {e}")
            raise InternalServerError("Token processing failed.")

        return f(*args, **kwargs)
    return decorated_function