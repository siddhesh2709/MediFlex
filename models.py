from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random
import string
from config import Config
import certifi
import os

class Database:
    """MongoDB Database handler"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            try:
                print(f"Attempting MongoDB connection...")
                
                # Check if using local MongoDB (no SSL) or Atlas (with SSL)
                mongodb_uri = Config.MONGODB_URI
                is_atlas = 'mongodb+srv://' in mongodb_uri or 'mongodb.net' in mongodb_uri
                
                if is_atlas:
                    # MongoDB Atlas connection (with SSL)
                    os.environ['SSL_CERT_FILE'] = certifi.where()
                    cls._instance.client = MongoClient(
                        mongodb_uri,
                        tlsCAFile=certifi.where(),
                        tls=True,
                        serverSelectionTimeoutMS=5000,
                        connectTimeoutMS=5000
                    )
                else:
                    # Local MongoDB connection (without SSL)
                    cls._instance.client = MongoClient(
                        mongodb_uri,
                        serverSelectionTimeoutMS=5000,
                        connectTimeoutMS=5000
                    )
                
                # Test connection
                cls._instance.client.admin.command('ping')
                cls._instance.db = cls._instance.client[Config.MONGODB_DB_NAME]
                print("✓ MongoDB connected successfully!")
                
            except Exception as e:
                print(f"✗ MongoDB connection error: {e}")
                print("⚠️  Application will continue but database features may not work")
                cls._instance.client = None
                cls._instance.db = None
                
        return cls._instance
    
    def get_collection(self, name):
        """Get a collection from the database"""
        if self.db is None:
            raise Exception("Database not connected")
        return self.db[name]

class User:
    """User model for authentication and profile management"""
    
    def __init__(self, email, name=None, password=None, google_id=None):
        self.email = email
        self.name = name
        self.password_hash = generate_password_hash(password) if password else None
        self.google_id = google_id
        self.created_at = datetime.utcnow()
        self.verified = False
        self.otp = None
        self.otp_expires = None
        self.consultations = []
    
    @staticmethod
    def get_collection():
        """Get users collection"""
        try:
            db = Database()
            if db.db is None:
                return None
            return db.get_collection('users')
        except Exception as e:
            print(f"Warning: Could not get users collection: {e}")
            return None
    
    @staticmethod
    def find_by_email(email):
        """Find user by email"""
        try:
            collection = User.get_collection()
            if collection is None:
                return None
            return collection.find_one({'email': email})
        except Exception as e:
            print(f"Warning: Database query failed: {e}")
            return None
    
    @staticmethod
    def find_by_google_id(google_id):
        """Find user by Google ID"""
        collection = User.get_collection()
        return collection.find_one({'google_id': google_id})
    
    @staticmethod
    def create_user(email, name, password=None, google_id=None):
        """Create a new user"""
        try:
            collection = User.get_collection()
            if collection is None:
                print("Warning: Database not available, user cannot be created")
                return None
            
            # Check if user exists
            if User.find_by_email(email):
                return None
            
            user_data = {
                'email': email,
                'name': name,
                'password_hash': generate_password_hash(password) if password else None,
                'google_id': google_id,
                'created_at': datetime.utcnow(),
                'verified': True if google_id else False,  # Google OAuth users are auto-verified
                'otp': None,
                'otp_expires': None,
                'consultations': [],
                'profile': {
                    'age': None,
                    'weight': None,
                    'allergies': [],
                    'medical_conditions': []
                }
            }
            
            result = collection.insert_one(user_data)
            user_data['_id'] = result.inserted_id
            return user_data
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
    
    @staticmethod
    def verify_password(email, password):
        """Verify user password"""
        user = User.find_by_email(email)
        if user and user.get('password_hash'):
            return check_password_hash(user['password_hash'], password)
        return False
    
    @staticmethod
    def generate_otp():
        """Generate 6-digit OTP"""
        return ''.join(random.choices(string.digits, k=6))
    
    @staticmethod
    def set_otp(email, otp):
        """Set OTP for email verification"""
        from datetime import timedelta
        collection = User.get_collection()
        
        otp_expires = datetime.utcnow() + timedelta(minutes=10)  # OTP valid for 10 minutes
        
        collection.update_one(
            {'email': email},
            {'$set': {
                'otp': otp,
                'otp_expires': otp_expires
            }}
        )
    
    @staticmethod
    def verify_otp(email, otp):
        """Verify OTP and mark user as verified"""
        collection = User.get_collection()
        user = User.find_by_email(email)
        
        if not user:
            return False
        
        # Check if OTP matches and not expired
        if user.get('otp') == otp and user.get('otp_expires') > datetime.utcnow():
            collection.update_one(
                {'email': email},
                {'$set': {
                    'verified': True,
                    'otp': None,
                    'otp_expires': None
                }}
            )
            return True
        return False
    
    @staticmethod
    def verify_user(email):
        """Mark user as verified (for OAuth users)"""
        try:
            collection = User.get_collection()
            if collection is None:
                return False
            collection.update_one(
                {'email': email},
                {'$set': {'verified': True}}
            )
            return True
        except Exception as e:
            print(f"Error verifying user: {e}")
            return False
    
    @staticmethod
    def add_consultation(email, consultation_data):
        """Add a consultation to user's history"""
        collection = User.get_collection()
        consultation_data['timestamp'] = datetime.utcnow()
        
        collection.update_one(
            {'email': email},
            {'$push': {'consultations': consultation_data}}
        )
    
    @staticmethod
    def get_consultations(email, limit=10):
        """Get user's consultation history"""
        user = User.find_by_email(email)
        if user and 'consultations' in user:
            consultations = user['consultations']
            # Sort by timestamp descending and limit
            consultations.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
            return consultations[:limit]
        return []
    
    @staticmethod
    def update_profile(email, profile_data):
        """Update user profile"""
        collection = User.get_collection()
        collection.update_one(
            {'email': email},
            {'$set': {'profile': profile_data}}
        )
    
    @staticmethod
    def get_user_stats(email):
        """Get user statistics"""
        user = User.find_by_email(email)
        if not user:
            return None
        
        total_consultations = len(user.get('consultations', []))
        
        return {
            'name': user.get('name'),
            'email': user.get('email'),
            'joined': user.get('created_at'),
            'total_consultations': total_consultations,
            'verified': user.get('verified', False),
            'profile': user.get('profile', {})
        }
    
    @staticmethod
    def add_reminder(email, reminder_data):
        """Add medication reminder to user profile"""
        collection = User.get_collection()
        collection.update_one(
            {'email': email},
            {'$push': {'reminders': reminder_data}}
        )
    
    @staticmethod
    def get_reminders(email):
        """Get user's medication reminders"""
        user = User.find_by_email(email)
        return user.get('reminders', []) if user else []
    
    @staticmethod
    def delete_reminder(email, reminder_index):
        """Delete a specific reminder"""
        user = User.find_by_email(email)
        if user and 'reminders' in user:
            reminders = user['reminders']
            if 0 <= reminder_index < len(reminders):
                reminders.pop(reminder_index)
                collection = User.get_collection()
                collection.update_one(
                    {'email': email},
                    {'$set': {'reminders': reminders}}
                )
                return True
        return False
