import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from .db_config import get_db_connection, return_db_connection

class StorageManager:
    """Manages file storage, quotas, and usage tracking"""
    
    def __init__(self):
        self.default_quota = 104857600  # 100MB
    
    # ==================== QUOTA MANAGEMENT ====================
    
    def allocate_quota(self, username, quota_bytes):
        """
        Allocate storage quota to user
        
        Args:
            username (str): Username
            quota_bytes (int): Quota in bytes
        
        Returns:
            dict: {'success': bool, 'message': str}
        
        Raises:
            ValueError: If capacity is not a positive integer greater than zero
        """
        # Validate capacity is a positive integer
        if not isinstance(quota_bytes, int) or isinstance(quota_bytes, bool):
            return {'success': False, 'message': 'Capacity must be a positive integer greater than zero'}
        
        if quota_bytes <= 0:
            return {'success': False, 'message': 'Capacity must be a positive integer greater than zero'}
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            if not result:
                return {'success': False, 'message': 'User not found'}
            
            user_id = result[0]
            
            # Update quota
            cursor.execute("""
                UPDATE users
                SET storage_quota = %s
                WHERE id = %s
            """, (quota_bytes, user_id))
            
            conn.commit()
            return {'success': True, 'message': f'Quota set to {quota_bytes} bytes'}
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    def get_user_quota(self, username):
        """Get user's storage quota in bytes"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT storage_quota FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            return result[0] if result else None
        
        finally:
            return_db_connection(conn)
    
    def get_user_quota_readable(self, username):
        """Get user's quota in human-readable format (e.g., '100 MB')"""
        quota = self.get_user_quota(username)
        if quota is None:
            return None
        return self._bytes_to_readable(quota)
    
    # ==================== SPACE TRACKING ====================
    
    def get_used_space(self, username):
        """Get user's used space in bytes"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            if not result:
                return None
            
            user_id = result[0]
            
            # Get used space
            cursor.execute("""
                SELECT used_space FROM storage_usage WHERE user_id = %s
            """, (user_id,))
            
            result = cursor.fetchone()
            return result[0] if result else 0
        
        finally:
            return_db_connection(conn)
    
    def get_used_space_readable(self, username):
        """Get used space in human-readable format"""
        space = self.get_used_space(username)
        if space is None:
            return None
        return self._bytes_to_readable(space)
    
    def get_available_space(self, username):
        """Get available space (quota - used) in bytes"""
        quota = self.get_user_quota(username)
        used = self.get_used_space(username)
        
        if quota is None or used is None:
            return None
        
        return quota - used
    
    def get_available_space_readable(self, username):
        """Get available space in human-readable format"""
        space = self.get_available_space(username)
        if space is None:
            return None
        return self._bytes_to_readable(space)
    
    def get_storage_usage_percentage(self, username):
        """Get storage usage as percentage"""
        quota = self.get_user_quota(username)
        used = self.get_used_space(username)
        
        if quota is None or quota == 0:
            return 0
        
        return round((used / quota) * 100, 2)
    
    def get_storage_stats(self, username):
        """Get complete storage statistics"""
        return {
            'quota': self.get_user_quota(username),
            'quota_readable': self.get_user_quota_readable(username),
            'used': self.get_used_space(username),
            'used_readable': self.get_used_space_readable(username),
            'available': self.get_available_space(username),
            'available_readable': self.get_available_space_readable(username),
            'usage_percentage': self.get_storage_usage_percentage(username)
        }
    
    # ==================== FILE TRACKING ====================
    
    def add_file(self, username, filename, file_path, file_size, file_hash, signature=None):
        """
        Register file in database
        
        Args:
            username (str): User uploading file
            filename (str): Original filename
            file_path (str): Server storage path
            file_size (int): File size in bytes
            file_hash (str): SHA-256 hash
            signature (str): Digital signature (optional)
        
        Returns:
            dict: {'success': bool, 'file_id': int, 'message': str}
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            user_result = cursor.fetchone()
            
            if not user_result:
                return {'success': False, 'message': 'User not found'}
            
            user_id = user_result[0]
            
            # Check quota
            available = self.get_available_space(username)
            if available is not None and file_size > available:
                return {
                    'success': False,
                    'message': f'Insufficient storage. Available: {self._bytes_to_readable(available)}'
                }
            
            # Insert file
            cursor.execute("""
                INSERT INTO files (user_id, file_name, file_path, file_size, file_hash, signature, uploaded_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (user_id, filename, file_path, file_size, file_hash, signature, datetime.now()))
            
            file_id = cursor.fetchone()[0]
            
            # Update storage usage
            cursor.execute("""
                UPDATE storage_usage
                SET used_space = used_space + %s
                WHERE user_id = %s
            """, (file_size, user_id))
            
            # Log action
            cursor.execute("""
                INSERT INTO logs (user_id, action, status, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (user_id, 'FILE_UPLOAD', 'SUCCESS', datetime.now()))
            
            conn.commit()
            
            return {
                'success': True,
                'file_id': file_id,
                'message': f'File {filename} registered successfully'
            }
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    def get_file(self, username, filename):
        """Get file information"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute("""
                SELECT f.* FROM files f
                JOIN users u ON f.user_id = u.id
                WHERE u.username = %s AND f.file_name = %s
            """, (username, filename))
            
            return cursor.fetchone()
        
        finally:
            return_db_connection(conn)
    
    def get_user_files(self, username):
        """Get all files for user"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute("""
                SELECT f.id, f.file_name, f.file_size, f.file_hash, f.signature, f.uploaded_at
                FROM files f
                JOIN users u ON f.user_id = u.id
                WHERE u.username = %s
                ORDER BY f.uploaded_at DESC
            """, (username,))
            
            return cursor.fetchall()
        
        finally:
            return_db_connection(conn)
    
    def delete_file(self, username, filename):
        """
        Delete file and update storage usage
        
        Returns:
            dict: {'success': bool, 'freed_space': int, 'message': str}
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Get file and user info
            cursor.execute("""
                SELECT f.id, f.file_size, f.user_id
                FROM files f
                JOIN users u ON f.user_id = u.id
                WHERE u.username = %s AND f.file_name = %s
            """, (username, filename))
            
            result = cursor.fetchone()
            if not result:
                return {'success': False, 'message': 'File not found'}
            
            file_id, file_size, user_id = result
            
            # Delete file
            cursor.execute('DELETE FROM files WHERE id = %s', (file_id,))
            
            # Update storage usage
            cursor.execute("""
                UPDATE storage_usage
                SET used_space = used_space - %s
                WHERE user_id = %s
            """, (file_size, user_id))
            
            # Log action
            cursor.execute("""
                INSERT INTO logs (user_id, action, status, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (user_id, 'FILE_DELETE', 'SUCCESS', datetime.now()))
            
            conn.commit()
            
            return {
                'success': True,
                'freed_space': file_size,
                'message': f'File {filename} deleted. Freed {self._bytes_to_readable(file_size)}'
            }
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    def file_exists(self, username, filename):
        """Check if file exists"""
        file = self.get_file(username, filename)
        return file is not None
    
    # ==================== ENCRYPTED KEY MANAGEMENT ====================
    
    def store_encrypted_key(self, file_id, encrypted_aes_key):
        """Store encrypted AES key"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO encrypted_keys (file_id, encrypted_aes_key)
                VALUES (%s, %s)
            """, (file_id, encrypted_aes_key))
            
            conn.commit()
            return {'success': True, 'message': 'Encrypted key stored'}
        
        except psycopg2.Error as e:
            conn.rollback()
            return {'success': False, 'message': f'Database error: {str(e)}'}
        
        finally:
            return_db_connection(conn)
    
    def get_encrypted_key(self, file_id):
        """Retrieve encrypted AES key"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT encrypted_aes_key FROM encrypted_keys WHERE file_id = %s
            """, (file_id,))
            
            result = cursor.fetchone()
            return result[0] if result else None
        
        finally:
            return_db_connection(conn)
    
    # ==================== UTILITY ====================
    
    def _bytes_to_readable(self, bytes_value):
        """Convert bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def get_all_users_stats(self):
        """Get storage stats for all users (admin function)"""
        conn = get_db_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute("""
                SELECT 
                    u.username,
                    u.storage_quota,
                    su.used_space,
                    (u.storage_quota - su.used_space) as available_space,
                    ROUND(((su.used_space::float / u.storage_quota) * 100)::numeric, 2) as usage_percentage,
                    COUNT(f.id) as file_count
                FROM users u
                LEFT JOIN storage_usage su ON u.id = su.user_id
                LEFT JOIN files f ON u.id = f.user_id
                GROUP BY u.id, u.username, u.storage_quota, su.used_space
                ORDER BY usage_percentage DESC
            """)
            
            return cursor.fetchall()
        
        finally:
            return_db_connection(conn)