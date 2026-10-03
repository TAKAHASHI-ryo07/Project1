from fastapi import FastAPI, HTTPException, Response, status, Cookie
from pydantic import BaseModel
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

app = FastAPI()

SECRET_KEY = "super-secret-key-for-selection-project"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

USER_DATABASE = {}

class UserRegister(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str


@app.post("/register")
def register(user: UserRegister):
    if user.username in USER_DATABASE:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "This user already has an account."
        )
    

    password_bytes = user.password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    USER_DATABASE[user.username] = {
        "hashed_password":hashed_password,
        "role": user.role
    }

    return {"message":f"welcome {user.username} !!"}

@app.post("/login")
def login(user: UserLogin, response: Response):
    if user.username not in USER_DATABASE:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "username is wrong or does not exist"
        )

    user_info = USER_DATABASE[user.username]

    password_bytes = user.password.encode("utf-8")
    is_valid = bcrypt.checkpw(password_bytes, user_info["hashed_password"])

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="username is wrong or does not exist"
        )

    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user.username,
        "role": user_info["role"],
        "exp": expire
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=15*60
    )

    return {"message": "login successed", "username": user.username, "role": user_info["role"]}

#test %you gotta delete
@app.get("/users")
def get_users():
    return { uname : { "role" : udata["role"]} for uname, udata in USER_DATABASE.items()}   


@app.get("/me")
def get_my_profile(access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login plz"
        )
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        
        return {
            "message": "Authorization successful",
            "username": username,
            "role": role,
            "secret_data": "This is the secret data"
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="expired token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")