from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import List
from config import SECRET_KEY, ALGORITHM, API_KEY  
import requests


app = FastAPI()

fake_users_db = {
    "ismayalegit": {
        "username": "ismayalegit",
        "full_name": "ISMAYA LEGIT GROUP",
        "email": "example@mail.com",
        "hashed_password": "$2b$12$aEX1Goa9uVq/i7hOQNicu.Msjh3R7OfPql.nx54ZM/iKd3NpmB/qi",  # password2024
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    password: str

class Weather(BaseModel):
    coord: dict
    weather: List[dict]
    base: str
    main: dict
    visibility: int
    wind: dict
    clouds: dict
    dt: int
    sys: dict
    timezone: int
    id: int
    name: str
    cod: int


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    data_with_timestamp = data.copy()
    data_with_timestamp["timestamp"] = datetime.utcnow().timestamp()
    encoded_jwt = jwt.encode(data_with_timestamp, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# async def get_current_user(token: str = Header(...)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
#     return username

async def get_current_user(authorization: str = Header(...)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    except (ValueError, AttributeError):
        raise credentials_exception
    return username


@app.get("/")
async def home():
    return("Welcome to FastAPI Project")

@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: User):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user["username"], "username": user["username"], "email": user["email"]}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/weather/{city}", response_model=Weather)
async def get_weather(city: str, current_user: str = Depends(get_current_user)):
    url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&APPID={API_KEY}"
    response = requests.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="City not found")
    data = response.json()
    weather = Weather(
        coord=data.get('coord'),
        weather=[data.get('weather')[0]],  
        base=data.get('base'),
        main=data.get('main'),
        visibility=data.get('visibility'),
        wind=data.get('wind'),
        clouds=data.get('clouds'),
        dt=data.get('dt'),
        sys=data.get('sys'),
        timezone=data.get('timezone'),
        id=data.get('id'),
        name=data.get('name'),  
        cod=data.get('cod')
    )

    print(f"User {current_user} accessed weather information for {city}")

    return weather

