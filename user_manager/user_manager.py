import argon2
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import secrets
import hashlib
from .db_config import get_db_connection, return_db_connection

class UserManager:
    """Manages user registration, authentication, and profiles"""
    
    def __init__(self):
        self.pwd_hasher = argon2.PasswordHasher()
        self.max_password_age_days = 90
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 15
    
    # ==================== REGISTRATION ====================
    
    def register_user(self, username, password, public_key):
        """
        Register a new user with username, password, and RSA public key
        
        Args:
            username (str): Username (3-50 chars, alphanumeric + underscore)
            password (str): Password (min 12 chars)
            public_key (str): RSA public key in PEM format
        
        Returns:
            dict: {'success': bool, 'user_id': int, 'message': str}
        
        Raises:
            ValueError: If validation fails
        """
        
        # Validate inputs
        validation = self._validate_username_password(username, password)
        if not validation['valid']:
            return {'success': False, 'message': validation['error']}
        
        if not self._validate_public_key(public_key):
            return {'success': False, 'message': 'Invalid RSA public key format'}
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                return {'success': False, 'message': 'Username already exists'}
            
            # Generate salt and hash password
            salt = secrets.token_hex(16)
            password_hash = self.pwd_hasher.hash(password + salt)
            
            # Insert user
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt, public_key, storage_quota)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, username, created_at
            """, (username, password_hash, salt, public_key, 104857600))  # 100MB default
            
            user = cursor.fetchone()
            user_id = user[0]
            
            # Initialize storage usage
            cursor.execute("""
                INSERT INTO storage_usage (user_id, used_space)
                VALUES (%s, %s)
            """, (user_id, 0))
            
            # Log the registration
            cursor.execute("""
                INSERT INTO logs (user_id, action, status, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (user_id, 'REGISTER', 'SUCCESS', datetime.now()))
            
            conn.commit()
            
            return {
                'success': True,
                'user_id': user_id,
                'message': f'User {username} registered successfully'
            }
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    # ==================== VALIDATION ====================
    
    def _validate_username_password(self, username, password):
        """Validate username and password format"""
        
        if not username or len(username) < 3 or len(username) > 50:
            return {
                'valid': False,
                'error': 'Username must be 3-50 characters'
            }
        
        if not username.replace('_', '').isalnum():
            return {
                'valid': False,
                'error': 'Username must contain only alphanumeric and underscore'
            }
        
        if not password or len(password) < 12:
            return {
                'valid': False,
                'error': 'Password must be at least 12 characters'
            }
        
        # Check password complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*' for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            return {
                'valid': False,
                'error': 'Password must contain uppercase, lowercase, digit, and special char (!@#$%^&*)'
            }
        
        return {'valid': True, 'error': None}
    
    def _validate_public_key(self, public_key):
        """Validate RSA public key format"""
        if not public_key:
            return False
        
        required_headers = ['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----']
        return all(header in public_key for header in required_headers)
    
    # ==================== USER RETRIEVAL ====================
    
    def get_user(self, username):
        """
        Get user by username
        
        Returns:
            dict: User data or None
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT id, username, public_key, storage_quota, created_at
                FROM users
                WHERE username = %s
            """, (username,))
            return cursor.fetchone()
        
        finally:
            return_db_connection(conn)
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT id, username, public_key, storage_quota, created_at
                FROM users
                WHERE id = %s
            """, (user_id,))
            return cursor.fetchone()
        
        finally:
            return_db_connection(conn)
    
    def user_exists(self, username):
        """Check if user exists"""
        user = self.get_user(username)
        return user is not None
    
    # ==================== PASSWORD MANAGEMENT ====================
    
    def verify_password(self, username, password):
        """
        Verify user password
        
        Returns:
            dict: {'valid': bool, 'message': str}
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, salt FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            if not result:
                return {'valid': False, 'message': 'User not found'}
            
            password_hash, salt = result
            
            try:
                # Verify with Argon2
                self.pwd_hasher.verify(password_hash, password + salt)
                return {'valid': True, 'message': 'Password verified'}
            
            except argon2.exceptions.VerifyMismatchError:
                return {'valid': False, 'message': 'Invalid password'}
        
        finally:
            return_db_connection(conn)
    
    def change_password(self, username, old_password, new_password):
        """
        Change user password
        
        Returns:
            dict: {'success': bool, 'message': str}
        """
        # Verify old password
        verify_result = self.verify_password(username, old_password)
        if not verify_result['valid']:
            return {'success': False, 'message': 'Current password is incorrect'}
        
        # Validate new password
        validation = self._validate_username_password(username, new_password)
        if not validation['valid']:
            return {'success': False, 'message': validation['error']}
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Generate new salt and hash
            salt = secrets.token_hex(16)
            password_hash = self.pwd_hasher.hash(new_password + salt)
            
            cursor.execute("""
                UPDATE users
                SET password_hash = %s, salt = %s
                WHERE username = %s
            """, (password_hash, salt, username))
            
            conn.commit()
            return {'success': True, 'message': 'Password changed successfully'}
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    # ==================== PUBLIC KEY MANAGEMENT ====================
    
    def get_public_key(self, username):
        """Get user's RSA public key"""
        user = self.get_user(username)
        return user['public_key'] if user else None
    
    def update_public_key(self, username, new_public_key):
        """
        Update user's RSA public key (for key rotation)
        
        Returns:
            dict: {'success': bool, 'message': str}
        """
        if not self._validate_public_key(new_public_key):
            return {'success': False, 'message': 'Invalid RSA public key format'}
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET public_key = %s
                WHERE username = %s
            """, (new_public_key, username))
            
            conn.commit()
            return {'success': True, 'message': 'Public key updated successfully'}
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    # ==================== FAILED LOGIN TRACKING ====================
    
    def record_failed_login(self, username, ip_address=None):
        """Record failed login attempt"""
        user = self.get_user(username)
        if not user:
            return
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO logs (user_id, action, status, ip_address, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (user['id'], 'LOGIN', 'FAILED', ip_address, datetime.now()))
            
            conn.commit()
        
        finally:
            return_db_connection(conn)
    
    def get_failed_login_count(self, username, hours=1):
        """Get failed login attempts in last N hours"""
        user = self.get_user(username)
        if not user:
            return 0
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM logs
                WHERE user_id = %s 
                AND action = 'LOGIN' 
                AND status = 'FAILED'
                AND timestamp > NOW() - INTERVAL '%s hours'
            """, (user['id'], hours))
            
            result = cursor.fetchone()
            return result[0] if result else 0
        
        finally:
            return_db_connection(conn)
    
    def reset_failed_login_count(self, username):
        """Reset failed login attempts after successful login"""
        user = self.get_user(username)
        if not user:
            return
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            # Log successful login
            cursor.execute("""
                INSERT INTO logs (user_id, action, status, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (user['id'], 'LOGIN', 'SUCCESS', datetime.now()))
            
            conn.commit()
        
        finally:
            return_db_connection(conn)
    
    def is_account_locked(self, username):
        """Check if account is locked due to failed attempts"""
        failed_attempts = self.get_failed_login_count(username, hours=1)
        return failed_attempts >= self.max_failed_attempts
    
    # ==================== DELETION ====================
    
    def delete_user(self, username, confirm_username=None):
        """
        Delete user account (requires confirmation)
        
        Args:
            username (str): Username to delete
            confirm_username (str): Must match username for safety
        
        Returns:
            dict: {'success': bool, 'message': str}
        """
        if username != confirm_username:
            return {'success': False, 'message': 'Username confirmation does not match'}
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # User deletion cascades to files, encrypted_keys, etc.
            cursor.execute('DELETE FROM users WHERE username = %s', (username,))
            
            conn.commit()
            return {'success': True, 'message': f'User {username} deleted successfully'}
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)