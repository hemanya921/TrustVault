from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field
def now(): return datetime.now(timezone.utc)
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    role: str = "viewer"
    active: bool = True
class Document(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    category: str = "General"
    owner_id: int = Field(index=True, foreign_key="user.id")
    storage_key: str = Field(unique=True)
    content_type: str
    size: int
    created_at: datetime = Field(default_factory=now)
    deleted: bool = False
class Grant(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    document_id: int = Field(index=True, foreign_key="document.id")
    user_id: int = Field(index=True, foreign_key="user.id")
    permission: str = "read"
class AuditEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    actor_id: Optional[int] = Field(default=None, index=True)
    action: str
    document_id: Optional[int] = Field(default=None, index=True)
    details: str = ""
    occurred_at: datetime = Field(default_factory=now, index=True)
