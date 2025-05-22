import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase with your service account credentials
cred = credentials.Certificate(r"/Users/tecon1/Documents/WebAdminCamara/keys/Auth_firestore.json")
firebase_admin.initialize_app(cred)

# Get Firestore client
db = firestore.client()