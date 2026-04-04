import psycopg2
from psycopg2 import pool
import os
from dotenv import load_dotenv

load_dotenv()

class DatabaseConfig:
    """Handles database connection pooling"""
    
    def __init__(self):
        self.connection_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1,
            maxconn=5,
            host=os.getenv('DB_HOST', 'localhost'),
            port=os.getenv('DB_PORT', '5432'),
            database=os.getenv('DB_NAME', 'secure_cloud'),
            user=os.getenv('DB_USER', 'postgres'),
            password=os.getenv('DB_PASSWORD', 'nabil')
        )
    
    def get_connection(self):
        """Get a connection from the pool"""
        return self.connection_pool.getconn()
    
    def return_connection(self, conn):
        """Return connection to the pool"""
        self.connection_pool.putconn(conn)
    
    def close_all(self):
        """Close all connections"""
        self.connection_pool.closeall()

# Global instance
db_config = DatabaseConfig()

def get_db_connection():
    """Helper function to get database connection"""
    return db_config.get_connection()

def return_db_connection(conn):
    """Helper function to return database connection"""
    db_config.return_connection(conn)