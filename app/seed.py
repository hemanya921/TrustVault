from sqlmodel import Session, select
from app.db import engine
from app.models import User
from app.security import hash_password
def seed():
    with Session(engine) as db:
        if db.exec(select(User)).first(): return
        for email,password,role in [("admin@example.test","Admin123!","admin"),("owner@example.test","Owner123!","owner"),("viewer@example.test","Viewer123!","viewer")]:
            db.add(User(email=email,password_hash=hash_password(password),role=role))
        db.commit()
