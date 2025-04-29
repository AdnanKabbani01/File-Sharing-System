import os
import json
import hashlib
import logging
import sqlite3
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from utils import setup_logger
import datetime

logger = setup_logger('database', 'logs/database.log')

ROLE_ADMIN = 'admin'
ROLE_USER = 'user'

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SECURE_DIR = os.path.join(ROOT_DIR, 'secure')
DB_FILE = os.path.join(SECURE_DIR, 'user_credentials.db')
KEY_FILE = os.path.join(SECURE_DIR, 'encryption.key')

class Database:
    def __init__(self, db_file=None):
        os.makedirs(SECURE_DIR, exist_ok=True)
        
        if db_file is None:
            self.db_file = DB_FILE
        else:
            self.db_file = db_file
        
        logger.info(f"Using database file: {os.path.abspath(self.db_file)}")
        
        self.key = self._get_encryption_key()
        self.cipher = Fernet(self.key)
        self._setup_database()
    
    def _setup_database(self):
        """Initialize the SQLite database schema"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()

            # Create users table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # Check if admin user exists, create if not
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("admin",))
            if cursor.fetchone()[0] == 0:
                admin_hash = self._hash_password("admin123")
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    ("admin", admin_hash, ROLE_ADMIN)
                )
                logger.info("Created new database with default admin user")

            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {self.db_file}")
        except Exception as e:
            logger.error(f"Error setting up database: {str(e)}")
            raise

    def _hash_password(self, password):
        """Securely hashes a password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate_user(self, username, password):
        """
        Verifies user credentials against stored values
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT password_hash, role FROM users WHERE username = ?", 
                (username,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                stored_hash, role = result
                if stored_hash == self._hash_password(password):
                    logger.info(f"User {username} authenticated successfully")
                    return True, role
                else:
                    logger.warning(f"Failed authentication attempt for user {username}")
                    return False, None
            else:
                logger.warning(f"Authentication attempt for non-existent user {username}")
                return False, None
        except Exception as e:
            logger.error(f"Error during authentication: {str(e)}")
            return False, None
    
    def add_user(self, username, password, role=ROLE_USER):
        """Creates a new user account in the database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cursor.fetchone()[0] > 0:
                logger.warning(f"Attempted to add existing user {username}")
                conn.close()
                return False
            
            # Add new user
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, self._hash_password(password), role)
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Added new user {username} with role {role}")
            return True
        except Exception as e:
            logger.error(f"Error adding user: {str(e)}")
            return False
    
    def delete_user(self, username):
        """Removes a user account from the database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cursor.fetchone()[0] == 0:
                logger.warning(f"Attempted to delete non-existent user {username}")
                conn.close()
                return False
            
            # Delete the user
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Deleted user {username}")
            return True
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            return False
    
    def change_password(self, username, new_password):
        """Updates a user's password with a new one"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cursor.fetchone()[0] == 0:
                logger.warning(f"Attempted to change password for non-existent user {username}")
                conn.close()
                return False
            
            # Update password
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (self._hash_password(new_password), username)
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Changed password for user {username}")
            return True
        except Exception as e:
            logger.error(f"Error changing password: {str(e)}")
            return False
    
    def get_user_role(self, username):
        """Retrieves a user's role from the database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return result[0]
            return None
        except Exception as e:
            logger.error(f"Error getting user role: {str(e)}")
            return None
            
    def list_users(self):
        """Returns a dictionary of all usernames and their roles"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute("SELECT username, role FROM users ORDER BY username")
            result = cursor.fetchall()
            conn.close()
            
            if not result:
                logger.warning("No users found in database")
                return {}
                
            users = {username: {"role": role} for username, role in result}
            logger.info(f"Retrieved {len(users)} users from database")
            return users
        except Exception as e:
            logger.error(f"Error listing users: {str(e)}")
            return {} 