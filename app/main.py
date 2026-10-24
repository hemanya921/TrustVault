
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
)
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.db import init_db, get_session
from app.models import User, Document, Grant, AuditEvent
from app.security import (
    current_user,
    verify_password,
    make_token,
    require_admin,
)
from app.access import authorized_document
from app.audit import record
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database and file storage at startup."""
    init_db()
    Path(settings.storage_dir).mkdir(parents=True, exist_ok=True)

    from app.seed import seed
    seed()

    yield


app = FastAPI(
    title="TrustVault API",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def homepage():
    return RedirectResponse(url="/docs")


# -------------------- AUTHENTICATION --------------------


@app.post("/auth/token")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_session),
):
    user = db.exec(
        select(User).where(User.email == form.username)
    ).first()

    if (
        not user
        or not user.active
        or not verify_password(form.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
        )

    return {
        "access_token": make_token(user),
        "token_type": "bearer",
    }


@app.get("/auth/me")
def me(user: User = Depends(current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
    }


# -------------------- UPLOAD DOCUMENT --------------------


@app.post("/documents")
def upload(
    file: UploadFile = File(...),
    category: str = Form("General"),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    name = Path(file.filename or "").name

    if not name or len(name) > 200 or name.startswith("."):
        raise HTTPException(400, "Invalid filename")

    allowed = {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "text/plain",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }

    if file.content_type not in allowed:
        raise HTTPException(415, "Unsupported file type")

    data = file.file.read(settings.max_upload_bytes + 1)

    if len(data) > settings.max_upload_bytes:
        raise HTTPException(413, "File too large")

    key = uuid4().hex
    path = Path(settings.storage_dir) / key

    path.write_bytes(data)

    document = Document(
        name=name,
        category=category[:80],
        owner_id=user.id,
        storage_key=key,
        content_type=file.content_type,
        size=len(data),
    )

    try:
        db.add(document)
        db.commit()
        db.refresh(document)
    except Exception:
        db.rollback()
        path.unlink(missing_ok=True)
        raise

    record(
        db,
        user.id,
        "upload",
        document.id,
        f"name={name}; bytes={len(data)}",
    )

    return {
        "id": document.id,
        "name": document.name,
        "category": document.category,
    }


# -------------------- LIST DOCUMENTS --------------------


@app.get("/documents")
def list_documents(
    q: str = "",
    category: str = "",
    owner_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    documents = db.exec(
        select(Document).where(Document.deleted == False)
    ).all()

    output = []

    for document in documents:
        grant_entry = db.exec(
            select(Grant).where(
                Grant.document_id == document.id,
                Grant.user_id == user.id,
            )
        ).first()

        if user.id == document.owner_id or grant_entry:
            if (
                q.lower() in document.name.lower()
                and (
                    not category
                    or category.lower() in document.category.lower()
                )
                and (
                    owner_id is None
                    or owner_id == document.owner_id
                )
            ):
                output.append(
                    {
                        "id": document.id,
                        "name": document.name,
                        "category": document.category,
                        "owner_id": document.owner_id,
                        "created_at": document.created_at,
                        "size": document.size,
                    }
                )

    return output


# -------------------- DOCUMENT DETAILS --------------------


@app.get("/documents/{doc_id}")
def get_document(
    doc_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    document = authorized_document(db, user, doc_id)

    record(db, user.id, "read", document.id)

    return {
        "id": document.id,
        "name": document.name,
        "category": document.category,
        "owner_id": document.owner_id,
        "size": document.size,
        "created_at": document.created_at,
    }


# -------------------- DOWNLOAD DOCUMENT --------------------


@app.get("/documents/{doc_id}/download")
def download(
    doc_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    document = authorized_document(db, user, doc_id)
    path = Path(settings.storage_dir) / document.storage_key

    if not path.is_file():
        raise HTTPException(404, "File missing")

    record(db, user.id, "download", document.id)

    return FileResponse(
        path,
        media_type=document.content_type,
        filename=document.name,
    )


# -------------------- EDIT DOCUMENT --------------------


@app.patch("/documents/{doc_id}")
def edit(
    doc_id: int,
    name: str | None = None,
    category: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    document = authorized_document(db, user, doc_id, "edit")

    if user.id != document.owner_id:
        grant_entry = db.exec(
            select(Grant).where(
                Grant.document_id == doc_id,
                Grant.user_id == user.id,
            )
        ).first()

        if not grant_entry or grant_entry.permission != "edit":
            raise HTTPException(403, "Edit permission required")

    if name is not None:
        name = name.strip()
        if not name or len(name) > 200 or name.startswith("."):
            raise HTTPException(400, "Invalid filename")

    if category is not None:
        category = category.strip()
        if not category or len(category) > 80:
            raise HTTPException(400, "Invalid category")

    previous = f"name={document.name}; category={document.category}"

    if name is not None:
        document.name = name

    if category is not None:
        document.category = category

    db.add(document)
    db.commit()
    db.refresh(document)

    record(db, user.id, "change", document.id, previous)

    return {
        "id": document.id,
        "name": document.name,
        "category": document.category,
    }


# -------------------- DELETE DOCUMENT --------------------


@app.delete("/documents/{doc_id}")
def delete(
    doc_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    document = authorized_document(db, user, doc_id)

    if user.id != document.owner_id and user.role != "admin":
        raise HTTPException(403, "Only owner or admin may delete")

    document.deleted = True
    db.add(document)
    db.commit()

    record(db, user.id, "delete", document.id)

    return {"ok": True}


# -------------------- GRANT DOCUMENT ACCESS --------------------


@app.put("/documents/{doc_id}/grants/{target_user_id}")
def grant(
    doc_id: int,
    target_user_id: int,
    permission: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    document = authorized_document(db, user, doc_id)

    if user.id != document.owner_id and user.role != "admin":
        raise HTTPException(403, "Owner or admin required")

    if permission not in {"read", "edit"}:
        raise HTTPException(400, "Permission must be read or edit")

    target = db.get(User, target_user_id)

    if not target or not target.active:
        raise HTTPException(404, "User not found")

    existing_grant = db.exec(
        select(Grant).where(
            Grant.document_id == doc_id,
            Grant.user_id == target_user_id,
        )
    ).first()

    if existing_grant:
        existing_grant.permission = permission
        db.add(existing_grant)
    else:
        db.add(
            Grant(
                document_id=doc_id,
                user_id=target_user_id,
                permission=permission,
            )
        )

    db.commit()

    record(
        db,
        user.id,
        "grant",
        doc_id,
        f"target={target_user_id}; permission={permission}",
    )

    return {"ok": True}


# -------------------- REVOKE DOCUMENT ACCESS --------------------


@app.delete("/documents/{doc_id}/grants/{target_user_id}")
def revoke(
    doc_id: int,
    target_user_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    document = db.get(Document, doc_id)

    if document is None or document.deleted:
        raise HTTPException(404, "Document not found")

    # Return 404 to unauthorized non-owners to avoid
    # revealing whether a grant exists.
    if user.id != document.owner_id and user.role != "admin":
        raise HTTPException(404, "Grant not found")

    existing_grant = db.exec(
        select(Grant).where(
            Grant.document_id == doc_id,
            Grant.user_id == target_user_id,
        )
    ).first()

    if existing_grant is None:
        raise HTTPException(404, "Grant not found")

    db.delete(existing_grant)
    db.commit()

    record(
        db,
        user.id,
        "revoke",
        doc_id,
        f"target={target_user_id}",
    )

    return {"ok": True}


# -------------------- ADMIN USERS --------------------


@app.get("/admin/users")
def users(
    user: User = Depends(require_admin),
    db: Session = Depends(get_session),
):
    return [
        {
            "id": item.id,
            "email": item.email,
            "role": item.role,
            "active": item.active,
        }
        for item in db.exec(select(User)).all()
    ]


# -------------------- ADMIN AUDIT LOG --------------------


@app.get("/admin/audit")
def audit(
    user: User = Depends(require_admin),
    db: Session = Depends(get_session),
    limit: int = 100,
):
    limit = max(1, min(limit, 500))

    events = db.exec(
        select(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
    ).all()

    return [
        {
            "id": event.id,
            "actor_id": event.actor_id,
            "action": event.action,
            "document_id": event.document_id,
            "details": event.details,
            "occurred_at": event.occurred_at,
        }
        for event in events
    ]
