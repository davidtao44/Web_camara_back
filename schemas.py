from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

# Token schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# User schemas
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str
    role: str  # admin, operator, supervisor

class User(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True

# Camera schemas
class CameraBase(BaseModel):
    name: str
    location: str
    external_id: str
    api_url: str

class CameraCreate(CameraBase):
    pass

class Camera(CameraBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True