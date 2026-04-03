import unittest
import sys
import os
from datetime import datetime
import uuid

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from user_manager import UserManager, StorageManager, NonceManager

class TestUserManager(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.user_manager = UserManager()
        cls.storage_manager = StorageManager()
        cls.nonce_manager = NonceManager()
    
    def setUp(self):
        """Run before each test"""
        # Generate unique usernames to avoid database conflicts
        self.unique_id = str(uuid.uuid4())[:8]
    
    def _get_test_username(self, base='testuser'):
        """Generate unique username for test"""
        return f"{base}_{self.unique_id}"
    
    # ==================== REGISTRATION TESTS ====================
    
    def test_register_valid_user(self):
        """Test successful user registration"""
        username = self._get_test_username('testuser')
        result = self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        self.assertTrue(result['success'])
        self.assertIn('user_id', result)
        print(f"✓ Registration test passed: {result['message']}")
    
    def test_register_weak_password(self):
        """Test registration with weak password"""
        username = self._get_test_username('testuser2')
        result = self.user_manager.register_user(
            username=username,
            password='weak',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        self.assertFalse(result['success'])
        self.assertIn('12 characters', result['message'])
        print(f"✓ Weak password test passed: {result['message']}")
    
    def test_register_duplicate_user(self):
        """Test registration with duplicate username"""
        # Register first user
        username = self._get_test_username('dupuser')
        self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Try to register with same username
        result = self.user_manager.register_user(
            username=username,
            password='OtherPass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        self.assertFalse(result['success'])
        self.assertIn('already exists', result['message'])
        print(f"✓ Duplicate user test passed: {result['message']}")
    
    # ==================== PASSWORD TESTS ====================
    
    def test_password_verification(self):
        """Test password verification"""
        username = self._get_test_username('passtest')
        password = 'SecurePass123!@#'
        
        # Register
        self.user_manager.register_user(
            username=username,
            password=password,
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Verify correct password
        result = self.user_manager.verify_password(username, password)
        self.assertTrue(result['valid'])
        print(f"✓ Correct password verified: {result['message']}")
        
        # Verify wrong password
        result = self.user_manager.verify_password(username, 'WrongPass123!@#')
        self.assertFalse(result['valid'])
        print(f"✓ Wrong password rejected: {result['message']}")
    
    # ==================== STORAGE TESTS ====================
    
    def test_quota_allocation(self):
        """Test storage quota allocation"""
        username = self._get_test_username('storageuser')
        
        # Register user
        self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Allocate different quota
        new_quota = 1073741824  # 1GB
        result = self.storage_manager.allocate_quota(username, new_quota)
        self.assertTrue(result['success'])
        
        # Verify
        quota = self.storage_manager.get_user_quota(username)
        self.assertEqual(quota, new_quota)
        print(f"✓ Quota allocation test passed")
    
    def test_storage_stats(self):
        """Test storage statistics"""
        username = self._get_test_username('statsuser')
        
        # Register
        self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Get stats
        stats = self.storage_manager.get_storage_stats(username)
        
        self.assertIsNotNone(stats['quota'])
        self.assertEqual(stats['used'], 0)
        self.assertEqual(stats['usage_percentage'], 0.0)
        print(f"✓ Storage stats test passed")
        print(f"  Quota: {stats['quota_readable']}")
        print(f"  Used: {stats['used_readable']}")
        print(f"  Available: {stats['available_readable']}")
        print(f"  Usage: {stats['usage_percentage']}%")
    
    # ==================== FAILED LOGIN TESTS ====================
    
    def test_failed_login_tracking(self):
        """Test failed login attempt tracking"""
        username = self._get_test_username('loginuser')
        
        # Register
        self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Record failed attempts
        for i in range(3):
            self.user_manager.record_failed_login(username)
        
        # Check count
        count = self.user_manager.get_failed_login_count(username)
        self.assertEqual(count, 3)
        print(f"✓ Failed login tracking test passed: {count} attempts recorded")
    
    def test_account_lockout(self):
        """Test account lockout after failed attempts"""
        username = self._get_test_username('lockoutuser')
        
        # Register
        self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Record 5 failed attempts
        for i in range(5):
            self.user_manager.record_failed_login(username)
        
        # Check lockout
        is_locked = self.user_manager.is_account_locked(username)
        self.assertTrue(is_locked)
        print(f"✓ Account lockout test passed: Account locked after 5 attempts")
    
    # ==================== NONCE TESTS ====================
    
    def test_nonce_generation(self):
        """Test nonce generation"""
        username = self._get_test_username('nonceuser')
        
        # Register
        self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Generate nonce
        result = self.nonce_manager.generate_nonce(username)
        
        self.assertTrue(result['success'])
        self.assertIn('nonce', result)
        self.assertIsNotNone(result['timestamp'])
        print(f"✓ Nonce generation test passed")
        print(f"  Nonce: {result['nonce'][:20]}...")
    
    def test_nonce_validation(self):
        """Test nonce validation"""
        username = self._get_test_username('noncevaluser')
        
        # Register
        self.user_manager.register_user(
            username=username,
            password='SecurePass123!@#',
            public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
        )
        
        # Generate nonce
        gen_result = self.nonce_manager.generate_nonce(username)
        nonce = gen_result['nonce']
        
        # Validate valid nonce
        result = self.nonce_manager.validate_nonce(username, nonce)
        self.assertTrue(result['valid'])
        print(f"✓ Nonce validation test passed: Valid nonce accepted")
        
        # Try to use same nonce again (replay attack)
        result = self.nonce_manager.validate_nonce(username, nonce)
        self.assertFalse(result['valid'])
        self.assertTrue(result['already_used'])
        print(f"✓ Replay attack prevention passed: Reused nonce rejected")

if __name__ == '__main__':
    unittest.main(verbosity=2)