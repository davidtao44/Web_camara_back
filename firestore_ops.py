from firebase_admin import firestore
from firebase_config import db
import uuid

# User operations
def create_user(user_data):
    """Create a new user in Firestore"""
    # Generate a unique ID for the user
    user_id = str(uuid.uuid4())
    user_ref = db.collection('users').document(user_id)
    
    # Add timestamp and active status
    user_data['isActive'] = True
    user_data['createdAt'] = firestore.SERVER_TIMESTAMP
    
    # Save to Firestore
    user_ref.set(user_data)
    
    # Get the created user with ID
    user_doc = user_ref.get()
    user = user_doc.to_dict()
    user['id'] = user_doc.id
    return user

def get_user_by_username(username):
    """Get a user by username"""
    users_ref = db.collection('users')
    query = users_ref.where('username', '==', username).limit(1)
    results = query.get()
    
    for doc in results:
        user = doc.to_dict()
        user['id'] = doc.id
        return user
    
    return None

def get_user_by_id(user_id):
    """Get a user by ID"""
    user_ref = db.collection('users').document(user_id)
    doc = user_ref.get()
    
    if doc.exists:
        user = doc.to_dict()
        user['id'] = doc.id
        return user
    
    return None

def get_all_users():
    """Get all users"""
    users = []
    users_ref = db.collection('users')
    docs = users_ref.get()
    
    for doc in docs:
        user = doc.to_dict()
        user['id'] = doc.id
        users.append(user)
    
    return users

def update_user(user_id, user_data):
    """Update a user in Firestore"""
    user_ref = db.collection('users').document(user_id)
    user_ref.update(user_data)
    
    # Get the updated user
    doc = user_ref.get()
    if doc.exists:
        user = doc.to_dict()
        user['id'] = doc.id
        return user
    
    return None

def delete_user(user_id):
    """Delete a user from Firestore"""
    user_ref = db.collection('users').document(user_id)
    user_ref.delete()
    return True