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

# Funciones para el monitoreo de cámaras
def heartbeat(session, auth, headers, stop_event):
    while not stop_event.is_set():
        try:
            response = session.post(
                heartbeat_url,
                auth=auth,
                headers=headers,
                verify=False
            )
            print("Heartbeat status:", response.status_code)
        except Exception as e:
            print("Error en heartbeat:", e)
        stop_event.wait(20)  # Espera 20 segundos

def monitorear_alarmas():
    global alarm_data
    try:
        # Primero hacemos login
        print("Iniciando sesión...")
        
        # Hacer el login inicial con timeout
        try:
            login_response = session.post(
                login_url,
                auth=HTTPDigestAuth(username, password),
                verify=False,
                timeout=10  # Agregar timeout de 10 segundos
            )
            print("Estado del login:", login_response.status_code)
            print("Respuesta del login:", login_response.text)
            
            # Obtener cookies y token CSRF de la respuesta del login
            cookies = login_response.cookies
            csrf_token = login_response.headers.get('X-csrftoken')
            
            if login_response.status_code == 200:
                print("Login exitoso, iniciando monitoreo continuo de alarmas...")
                print("Presiona Ctrl+C para detener el monitoreo")
                
                # Configurar headers con el token CSRF obtenido del login
                headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                # Agregar el token CSRF si existe
                if csrf_token:
                    headers['X-csrftoken'] = csrf_token
                    print("Token CSRF obtenido:", csrf_token)
                
                # Iniciar el heartbeat en un hilo separado
                stop_event = threading.Event()
                heartbeat_thread = threading.Thread(
                    target=heartbeat,
                    args=(session, HTTPDigestAuth(username, password), headers, stop_event)
                )
                heartbeat_thread.daemon = True
                heartbeat_thread.start()
                
                # Bucle infinito
                while True:
                    try:
                        setup_params = {
                            "version": "1.0",
                            "data": {
                                "page_type": "ChannelConfig"
                            }
                        }
                        # Obtener configuración FD
                        setup_response = session.post(
                            position_url,
                            auth=HTTPDigestAuth(username, password),
                            headers=headers,
                            json=setup_params,
                            verify=False,
                            timeout=10  # Agregar timeout
                        )
                        print("\nEstado de la petición de configuración:", setup_response.status_code)
                        
                        # Procesar la respuesta de configuración
                        if setup_response.status_code == 200:
                            setup_data = setup_response.json()
                            #print("Configuración FD:", json.dumps(setup_data, indent=2))
                        
                        # Usar la misma sesión para obtener las alarmas con timeout
                        alarm_response = session.post(
                            alarm_url,
                            auth=HTTPDigestAuth(username, password),
                            headers=headers,
                            verify=False,
                            timeout=10  # Agregar timeout
                        )
                        print("\nEstado de la petición de alarmas:", alarm_response.status_code)
                        
                        # Obtener y procesar el JSON de la respuesta
                        json_response = alarm_response.json()
                        json_response_p = setup_response.json()
                        #print("Respuesta de alarmas:", alarm_response.text)
                        
                        try:
                            Name = json_response['data']['FaceInfo'][0]['Name']
                            print("Nombre:", Name)
                            Age = json_response['data']['FaceInfo'][0]['Age']
                            print("Edad:", Age)
                            position = json_response_p['data']['channel_info']
                            
                            # Actualizar los datos de alarma globales
                            alarm_data = {
                                "name": Name,
                                "age": Age,
                                "position": {},
                                "timestamp": datetime.now().isoformat()
                            }
                            
                            for info in position.values():
                                if info.get('switch'):  # Solo canales activos
                                    rule_rect = info.get('rule_info', {}).get('rule_number1', {}).get('rule_rect')
                                    if rule_rect:
                                        print(rule_rect)
                                        alarm_data["position"] = rule_rect
                    
                        except KeyError:
                           print("No hay datos de rostros disponibles en este momento")
                           alarm_data = {
                               "name": "",
                               "age": "",
                               "position": {},
                               "timestamp": datetime.now().isoformat(),
                               "message": "No hay datos de rostros disponibles en este momento"
                           }
                        
                    except KeyboardInterrupt:
                        print("\nDetención manual del monitoreo...")
                        stop_event.set()
                        heartbeat_thread.join()
                        break
                    except Exception as e:
                        print(f"\nError en la petición: {e}")
                        alarm_data = {
                            "name": "",
                            "age": "",
                            "position": {},
                            "timestamp": datetime.now().isoformat(),
                            "error": str(e)
                        }
                        time.sleep(5)
                        continue
            else:
                print("Error en el login")
                alarm_data = {
                    "name": "",
                    "age": "",
                    "position": {},
                    "timestamp": datetime.now().isoformat(),
                    "error": "Error en el login"
                }

        except Exception as e:
            print("Error al hacer la petición:", e)
            alarm_data = {
                "name": "",
                "age": "",
                "position": {},
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }

        finally:
            print("\nCerrando sesión...")
            session.close()
    finally:
        print("Sesión cerrada")
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

# Nuevo endpoint para obtener datos de alarma de cámara
@app.get("/alarmcamera")
async def get_alarm_data(current_user: dict = Depends(get_current_user)):
    """
    Endpoint para obtener los datos de alarma de la cámara.
    Incluye datos actuales y estadísticas acumuladas.
    """
    global alarm_data, alarm_history, total_detections, unknown_detections
    
    # Si hay un nombre en los datos de alarma, consideramos que es una nueva detección
    if alarm_data.get("name") and alarm_data.get("timestamp"):
        # Verificar si este es un nuevo registro (para no contar múltiples veces la misma detección)
        is_new_detection = True
        if alarm_history and alarm_history[-1].get("timestamp") == alarm_data.get("timestamp"):
            is_new_detection = False
            
        if is_new_detection:
            # Agregar a historial
            alarm_history.append(alarm_data.copy())
            # Limitar el historial a los últimos 100 registros
            if len(alarm_history) > 100:
                alarm_history.pop(0)
            
            # Actualizar contadores
            total_detections += 1
            if not alarm_data.get("name") or alarm_data.get("name").lower() == "unknown":
                unknown_detections += 1
    
    # Calcular porcentaje de reconocimiento
    recognition_percentage = 0
    if total_detections > 0:
        recognition_percentage = ((total_detections - unknown_detections) / total_detections) * 100
    
    # Preparar respuesta con datos actuales y estadísticas
    response = {
        "current_data": alarm_data,
        "stats": {
            "total_detections": total_detections,
            "unknown_detections": unknown_detections,
            "identified_detections": total_detections - unknown_detections,
            "recognition_percentage": round(recognition_percentage, 2)
        },
        "history": alarm_history
    }
    
    return response

# Nuevo endpoint para reiniciar contadores
@app.post("/alarmcamera/reset")
async def reset_alarm_counters(current_user: dict = Depends(get_current_user)):
    """
    Endpoint para reiniciar todos los contadores de alarma.
    Reinicia el total de detecciones, detecciones desconocidas y el historial.
    """
    global alarm_history, total_detections, unknown_detections
    
    # Reiniciar contadores globales
    total_detections = 0
    unknown_detections = 0
    
    # Limpiar historial
    alarm_history = []
    
    return {
        "message": "Contadores reiniciados correctamente",
        "stats": {
            "total_detections": 0,
            "unknown_detections": 0,
            "identified_detections": 0,
            "recognition_percentage": 0
        }
    }

if __name__ == "__main__":
    # Iniciar el monitoreo de alarmas en un hilo separado
    monitoring_thread = threading.Thread(target=monitorear_alarmas)
    monitoring_thread.daemon = True
    monitoring_thread.start()
    
    # Iniciar el servidor FastAPI
    uvicorn.run(app, host="0.0.0.0", port=8000)