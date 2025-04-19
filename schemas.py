from typing import Optional, Any
from pydantic import BaseModel, EmailStr
from datetime import datetime

# Token schemas
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

class TokenData(BaseModel):
    username: Optional[str] = None

# User schemas
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str
    role: str  # administrador, supervisor, operario

class UserResponse(UserBase):
    id: str
    role: str
    isActive: bool
    createdAt: Any = None

class User(UserBase):
    id: str
    role: str
    isActive: bool
    createdAt: Any = None
    
    class Config:
        from_attributes = True

# Camera schemas (if needed later)
class CameraBase(BaseModel):
    name: str
    location: str
    external_id: str
    api_url: str

class CameraCreate(CameraBase):
    pass

class Camera(CameraBase):
    id: str
    isActive: bool
    createdAt: Any = None
    
    class Config:
        from_attributes = True