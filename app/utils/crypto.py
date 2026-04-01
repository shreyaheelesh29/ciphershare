import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    @staticmethod
    def generate_rsa_keys():
        """Generates a new RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem.decode(), public_pem.decode()

    @staticmethod
    def _get_key_from_password(password: str, salt: bytes):
        """Derive a key from a password for AES encryption."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_private_key(private_pem: str, password: str):
        """Encrypts the private key using the user's password."""
        salt = os.urandom(16)
        key = CryptoUtils._get_key_from_password(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, private_pem.encode(), None)
        # Store as salt:nonce:encrypted (base64)
        result = base64.b64encode(salt).decode() + ":" + \
                 base64.b64encode(nonce).decode() + ":" + \
                 base64.b64encode(encrypted).decode()
        return result

    @staticmethod
    def decrypt_private_key(encrypted_str: str, password: str):
        """Decrypts the private key using the user's password."""
        try:
            salt_b64, nonce_b64, encrypted_b64 = encrypted_str.split(":")
            salt = base64.b64decode(salt_b64)
            nonce = base64.b64decode(nonce_b64)
            encrypted = base64.b64decode(encrypted_b64)
            
            key = CryptoUtils._get_key_from_password(password, salt)
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, encrypted, None)
            return decrypted.decode()
        except Exception:
            return None

    @staticmethod
    def generate_aes_key():
        """Generates a random AES-256 key."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt_file(file_data: bytes, aes_key: bytes):
        """Encrypts file data using AES-GCM."""
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, file_data, None)
        # Store nonce at the beginning of the data
        return nonce + encrypted_data

    @staticmethod
    def decrypt_file(encrypted_data: bytes, aes_key: bytes):
        """Decrypts file data using AES-GCM."""
        try:
            nonce = encrypted_data[:12]
            actual_encrypted_data = encrypted_data[12:]
            aesgcm = AESGCM(aes_key)
            return aesgcm.decrypt(nonce, actual_encrypted_data, None)
        except Exception:
            return None

    @staticmethod
    def rsa_encrypt_aes_key(aes_key: bytes, public_pem: str):
        """Encrypts the AES key with the user's RSA public key."""
        public_key = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend()
        )
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_aes_key).decode()

    @staticmethod
    def rsa_decrypt_aes_key(encrypted_aes_key_b64: str, private_pem: str):
        """Decrypts the AES key with the user's RSA private key."""
        try:
            private_key = serialization.load_pem_private_key(
                private_pem.encode(),
                password=None,
                backend=default_backend()
            )
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return aes_key
        except Exception as e:
            print(f"Decryption error details: {str(e)}")
            return None
