import os
import json
import hashlib
import logging
from utils import setup_logger

logger = setup_logger('database', 'logs/database.log')

ROLE_ADMIN = 'admin'
ROLE_USER = 'user'

class Database:
    def __init__(self, db_file='users.json'):
        self.db_file = db_file
        self.users = {}
        self.load_database()
    
    def load_database(self):
        """Loads the user database from disk or creates a default one if it doesn't exist"""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as f:
                    self.users = json.load(f)
                logger.info(f"Database loaded from {self.db_file}")
            else:
                self.users = {
                    "admin": {
                        "password_hash": self._hash_password("admin123"),
                        "role": ROLE_ADMIN
                    }
                }
                self.save_database()
                logger.info("Created new database with default admin user")
        except Exception as e:
            logger.error(f"Error loading database: {str(e)}")
            self.users = {}
    
    def save_database(self):
        """Persists the user database to disk"""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.users, f, indent=4)
            logger.info(f"Database saved to {self.db_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving database: {str(e)}")
            return False
    
    def _hash_password(self, password):
        """Securely hashes a password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate_user(self, username, password):
        """
        Verifies user credentials against stored values
        
        Returns:
            tuple: (success, role) - success is a boolean, role is the user's role if successful
        """
        if username in self.users:
            stored_hash = self.users[username]["password_hash"]
            if stored_hash == self._hash_password(password):
                logger.info(f"User {username} authenticated successfully")
                return True, self.users[username]["role"]
            else:
                logger.warning(f"Failed authentication attempt for user {username}")
                return False, None
        else:
            logger.warning(f"Authentication attempt for non-existent user {username}")
            return False, None
    
    def add_user(self, username, password, role=ROLE_USER):
        """Creates a new user account in the database"""
        if username in self.users:
            logger.warning(f"Attempted to add existing user {username}")
            return False
        
        self.users[username] = {
            "password_hash": self._hash_password(password),
            "role": role
        }
        
        success = self.save_database()
        if success:
            logger.info(f"Added new user {username} with role {role}")
        return success
    
    def delete_user(self, username):
        """Removes a user account from the database"""
        if username not in self.users:
            logger.warning(f"Attempted to delete non-existent user {username}")
            return False
        
        del self.users[username]
        success = self.save_database()
        if success:
            logger.info(f"Deleted user {username}")
        return success
    
    def change_password(self, username, new_password):
        """Updates a user's password with a new one"""
        if username not in self.users:
            logger.warning(f"Attempted to change password for non-existent user {username}")
            return False
        
        self.users[username]["password_hash"] = self._hash_password(new_password)
        success = self.save_database()
        if success:
            logger.info(f"Changed password for user {username}")
        return success
    
    def get_user_role(self, username):
        """Retrieves a user's role from the database"""
        if username in self.users:
            return self.users[username]["role"]
        return None 