from datetime import datetime, timedelta
from typing import Annotated
import redis
import uuid
from fastapi import Depends, FastAPI, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

# CONFIG
SESSION_EXPIRE_MINUTES = 3  # session valid for 3 minutes

# REDIS CLIENT
redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

# FAKE USER DB (for demo)
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "secret",  # plain-text for demo only
        "disabled": False,
    }
}

# MODELS
class SessionToken(BaseModel):
    session_id: str
    token_type: str = "bearer"

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

def create_session(username: str) -> str:
    """
    Create or reuse a session_id for a user.
    - If user has active session → reuse session_id and reset expiry to 3 mins
    - If no active session → create new session_id
    """
    existing_session = redis_client.get(username)
    
    if existing_session:
        # Extend TTL to 3 minutes from now
        redis_client.expire(existing_session, SESSION_EXPIRE_MINUTES * 60)
        redis_client.expire(username, SESSION_EXPIRE_MINUTES * 60)
        return existing_session

    # Create new session
    session_id = str(uuid.uuid4())
    redis_client.setex(session_id, SESSION_EXPIRE_MINUTES * 60, username)
    redis_client.setex(username, SESSION_EXPIRE_MINUTES * 60, session_id)
    return session_id


# ORDER 2: FASTAPI
app = FastAPI()

# LOGIN ROUTE (SESSION START)
@app.post("/login", response_model=SessionToken)
async def login(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # Create or reuse session
    session_id = create_session(user.username)

    # Set cookie
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,  # set True if using HTTPS
        max_age=SESSION_EXPIRE_MINUTES * 60
    )

    return {"session_id": session_id, "token_type": "bearer"}

# ORDER 3: VERIFY CURRENT USER (SESSION CHECK from COOKIE)
def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="No session cookie")

    username = redis_client.get(session_id)
    if not username:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    user = get_user(fake_users_db, username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return user

# ORDER 4: PROTECTED ROUTE (SESSION REQUIRED)
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

# ORDER 5: LOGOUT ROUTE (SESSION END)
@app.post("/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="No active session")

    username = redis_client.get(session_id)
    if username:
        # Delete both mappings
        redis_client.delete(session_id)
        redis_client.delete(username)

    response.delete_cookie("session_id")

    return {"message": "Successfully logged out"}


# sudo apt update
# sudo apt install redis-server -y
# sudo service redis-server start

# redis-cli ping
# PONG
