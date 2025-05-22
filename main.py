from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import schemas
import firestore_ops
import requests
from requests.auth import HTTPDigestAuth
import json
import time
import threading
import uvicorn
from pydantic import BaseModel

# Create FastAPI app
app = FastAPI(title="Camera Visualization API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = "YOUR_SECRET_KEY_CHANGE_THIS_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Almacenamiento en memoria para las imágenes base64 y datos de alarma
imagenes_base64 = {}
alarm_data = {"name": "", "age": "", "position": {}}
alarm_history = []  # Inicializar el historial de alarmas
total_detections = 0  # Inicializar contador de detecciones totales
unknown_detections = 0  # Inicializar contador de detecciones desconocidas

# Crear una sesión que podemos reutilizar
session = requests.Session()

# Credenciales para autenticación digest
username = "admin"
password = "Bolidec0"

# URLs para las diferentes peticiones
login_url = "http://172.16.1.248/API/Web/Login"
alarm_url = "http://172.16.1.248/API/AI/processAlarm/Get"
position_url = "http://172.16.1.248/API/AI/Setup/FD/Get"
heartbeat_url = "http://172.16.1.248/API/Login/Heartbeat"

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    user = firestore_ops.get_user_by_username(username)
    if not user or not verify_password(password, user['password']):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = firestore_ops.get_user_by_username(token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.get('isActive', False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "role": user["role"]}

@app.post("/users/", response_model=schemas.UserResponse)
async def create_user(user: schemas.UserCreate):
    # Check if username already exists
    existing_user = firestore_ops.get_user_by_username(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash the password
    hashed_password = get_password_hash(user.password)
    
    # Create user data
    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "role": user.role
    }
    
    # Create user in Firestore
    db_user = firestore_ops.create_user(user_data)
    return db_user

@app.get("/users/me/", response_model=schemas.UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.get("/users/", response_model=List[schemas.UserResponse])
async def read_users(current_user: dict = Depends(get_current_user)):
    # Only admin can view all users
    if current_user["role"] != "administrador":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    users = firestore_ops.get_all_users()
    return users

@app.get("/users/{user_id}", response_model=schemas.UserResponse)
async def read_user(user_id: str, current_user: dict = Depends(get_current_user)):
    # Only admin or the user themselves can view user details
    if current_user["role"] != "administrador" and current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    user = firestore_ops.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

@app.delete("/users/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    # Only admin can delete users
    if current_user["role"] != "administrador":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    user = firestore_ops.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    firestore_ops.delete_user(user_id)
    return {"message": "User deleted successfully"}

if __name__ == "__main__":
    # Iniciar el servidor FastAPI
    uvicorn.run(app, host="0.0.0.0", port=8000)