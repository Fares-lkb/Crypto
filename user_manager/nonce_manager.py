import psycopg2
from datetime import datetime, timedelta
import secrets
from .db_config import get_db_connection, return_db_connection

class NonceManager:
    """Manages nonces for challenge-response authentication"""
    
    def __init__(self):
        self.nonce_validity_minutes = 5  # Nonces valid for 5 minutes
        self.max_nonces_per_user = 10  # Keep last 10 nonces
    
    # ==================== NONCE GENERATION ====================
    
    def generate_nonce(self, username):
        """
        Generate a new nonce for user challenge
        
        Args:
            username (str): Username requesting nonce
        
        Returns:
            dict: {'success': bool, 'nonce': str, 'timestamp': str, 'message': str}
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            if not result:
                return {'success': False, 'message': 'User not found'}
            
            user_id = result[0]
            
            # Generate random nonce
            nonce = secrets.token_hex(32)  # 64-char hex string
            timestamp = datetime.now()
            
            # Insert nonce
            cursor.execute("""
                INSERT INTO nonces (user_id, nonce, created_at, used)
                VALUES (%s, %s, %s, %s)
            """, (user_id, nonce, timestamp, False))
            
            # Clean up old nonces (keep last N nonces)
            cursor.execute("""
                DELETE FROM nonces
                WHERE user_id = %s
                AND id NOT IN (
                    SELECT id FROM nonces
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                )
            """, (user_id, user_id, self.max_nonces_per_user))
            
            conn.commit()
            
            return {
                'success': True,
                'nonce': nonce,
                'timestamp': timestamp.isoformat(),
                'message': 'Nonce generated successfully'
            }
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    # ==================== NONCE VALIDATION ====================
    
    def validate_nonce(self, username, nonce):
        """
        Validate nonce for authentication
        
        Returns:
            dict: {'valid': bool, 'expired': bool, 'already_used': bool, 'message': str}
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            if not result:
                return {
                    'valid': False,
                    'expired': False,
                    'already_used': False,
                    'message': 'User not found'
                }
            
            user_id = result[0]
            
            # Get nonce info
            cursor.execute("""
                SELECT id, created_at, used FROM nonces
                WHERE user_id = %s AND nonce = %s
            """, (user_id, nonce))
            
            nonce_record = cursor.fetchone()
            
            if not nonce_record:
                return {
                    'valid': False,
                    'expired': False,
                    'already_used': False,
                    'message': 'Nonce not found'
                }
            
            nonce_id, created_at, already_used = nonce_record
            
            # Check if already used
            if already_used:
                return {
                    'valid': False,
                    'expired': False,
                    'already_used': True,
                    'message': 'Nonce already used (replay attack detected)'
                }
            
            # Check if expired
            expiry_time = created_at + timedelta(minutes=self.nonce_validity_minutes)
            if datetime.now() > expiry_time:
                return {
                    'valid': False,
                    'expired': True,
                    'already_used': False,
                    'message': f'Nonce expired after {self.nonce_validity_minutes} minutes'
                }
            
            # Mark nonce as used
            cursor.execute("""
                UPDATE nonces SET used = TRUE WHERE id = %s
            """, (nonce_id,))
            
            conn.commit()
            
            return {
                'valid': True,
                'expired': False,
                'already_used': False,
                'message': 'Nonce valid and verified'
            }
        
        except psycopg2.Error as e:
            conn.rollback()
            return {
                'valid': False,
                'expired': False,
                'already_used': False,
                'message': f'Database error: {str(e)}'
            }
        
        finally:
            return_db_connection(conn)
    
    def mark_nonce_used(self, username, nonce):
        """Mark nonce as used"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            if not result:
                return False
            
            user_id = result[0]
            
            cursor.execute("""
                UPDATE nonces SET used = TRUE
                WHERE user_id = %s AND nonce = %s
            """, (user_id, nonce))
            
            conn.commit()
            return True
        
        except psycopg2.Error:
            conn.rollback()
            return False
        
        finally:
            return_db_connection(conn)
    
    # ==================== NONCE CLEANUP ====================
    
    def cleanup_expired_nonces(self):
        """Remove expired nonces from database"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            expiry_time = datetime.now() - timedelta(minutes=self.nonce_validity_minutes)
            
            cursor.execute("""
                DELETE FROM nonces WHERE created_at < %s
            """, (expiry_time,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            return {'success': True, 'deleted': deleted_count}
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': str(e)}
        
        finally:
            return_db_connection(conn)
    
    def get_unused_nonces_count(self, username):
        """Get count of unused nonces for user"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            if not result:
                return 0
            
            user_id = result[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM nonces
                WHERE user_id = %s AND used = FALSE
                AND created_at > NOW() - INTERVAL '%s minutes'
            """, (user_id, self.nonce_validity_minutes))
            
            return cursor.fetchone()[0]
        
        finally:
            return_db_connection(conn)