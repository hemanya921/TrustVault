from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session
from app.core.config import settings
from app.db import get_session
from app.models import User
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth = OAuth2PasswordBearer(tokenUrl="/auth/token")
def hash_password(password): return pwd.hash(password)
def verify_password(password, hashed): return pwd.verify(password, hashed)
def make_token(user): return jwt.encode({"sub": str(user.id), "exp": datetime.now(timezone.utc)+timedelta(hours=8)}, settings.secret_key, algorithm="HS256")
def current_user(token: str = Depends(oauth), db: Session = Depends(get_session)):
    try: uid = int(jwt.decode(token, settings.secret_key, algorithms=["HS256"])["sub"])
    except (JWTError, KeyError, ValueError): raise HTTPException(401, "Invalid credentials")
    user = db.get(User, uid)
    if not user or not user.active: raise HTTPException(401, "Account unavailable")
    return user
def require_admin(user=Depends(current_user)):
    if user.role != "admin": raise HTTPException(403, "Administrator required")
    return user
