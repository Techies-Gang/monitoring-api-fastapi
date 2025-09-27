from datetime import datetime, timedelta
from typing import Annotated

import jwt
import redis
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

# CONFIG
SECRET_KEY = "mysecretkey"   # use a stronger key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 3  # session valid for 3 minutes

# REDIS CLIENT
redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

# FAKE USER DB
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "secret",  # plain for demo
        "disabled": False,
    }
}

# MODELS
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

# HELPERS
def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password

def get_user(db, username: str):
    if username in db:
        return UserInDB(**db[username])

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    username = data["sub"]
    
    # Check if user already has an active session
    existing_token = redis_client.get(username)
    if existing_token:
        return None  # user already logged in

    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Save token and username mapping in Redis with expiration
    redis_client.setex(username, ACCESS_TOKEN_EXPIRE_MINUTES * 60, token)
    redis_client.setex(token, ACCESS_TOKEN_EXPIRE_MINUTES * 60, "valid")
    return token

# FASTAPI SETUP
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# LOGIN ROUTE
@app.post("/token", response_model=Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    if access_token is None:
        raise HTTPException(
            status_code=404,
            detail="User already has an active session. Please logout first."
        )

    return {"access_token": access_token, "token_type": "bearer"}

# VERIFY CURRENT USER
def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    # Check token in Redis
    if not redis_client.get(token):
        raise HTTPException(status_code=401, detail="Token expired or invalid")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user(fake_users_db, username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# PROTECTED ROUTES
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

# LOGOUT ROUTE
@app.post("/logout")
async def logout(token: Annotated[str, Depends(oauth2_scheme)]):
    # Check if token exists in Redis
    if not redis_client.get(token):
        raise HTTPException(
            status_code=400,
            detail="Token already expired or user already logged out"
        )

    # Get username from token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Remove token and username mapping from Redis
    redis_client.delete(token)
    if username:
        redis_client.delete(username)

    return {"message": "Successfully logged out"}




#in wsl for install redis server in machine

# sudo apt update
# sudo apt install redis-server -y
# redis-server