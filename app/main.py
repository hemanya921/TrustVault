from pathlib import Path
from uuid import uuid4
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from app.db import init_db, get_session
from app.models import User, Document, Grant, AuditEvent
from app.security import current_user, verify_password, make_token, hash_password, require_admin
from app.access import authorized_document
from app.audit import record
from app.core.config import settings
from fastapi.responses import RedirectResponse
app = FastAPI(title="TrustVault API", version="0.1.0")
@app.get("/", include_in_schema=False)
def homepage():
    return RedirectResponse(url="/docs")
@app.on_event("startup")
def startup():
    init_db(); Path(settings.storage_dir).mkdir(parents=True, exist_ok=True)
    from app.seed import seed
    seed()
@app.post("/auth/token")
def login(form: OAuth2PasswordRequestForm=Depends(), db: Session=Depends(get_session)):
    user=db.exec(select(User).where(User.email==form.username)).first()
    if not user or not user.active or not verify_password(form.password,user.password_hash): raise HTTPException(401,"Incorrect email or password")
    return {"access_token":make_token(user),"token_type":"bearer"}
@app.get("/auth/me")
def me(user: User=Depends(current_user)): return {"id":user.id,"email":user.email,"role":user.role}
@app.post("/documents")
def upload(file: UploadFile=File(...), category: str=Form("General"), user: User=Depends(current_user), db: Session=Depends(get_session)):
    name=Path(file.filename or "").name
    if not name or len(name)>200 or name.startswith("."): raise HTTPException(400,"Invalid filename")
    allowed={"application/pdf","image/png","image/jpeg","text/plain","application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    if file.content_type not in allowed: raise HTTPException(415,"Unsupported file type")
    data=file.file.read(settings.max_upload_bytes+1)
    if len(data)>settings.max_upload_bytes: raise HTTPException(413,"File too large")
    key=uuid4().hex; path=Path(settings.storage_dir)/key
    path.write_bytes(data)
    doc=Document(name=name,category=category[:80],owner_id=user.id,storage_key=key,content_type=file.content_type,size=len(data))
    db.add(doc); db.commit(); db.refresh(doc); record(db,user.id,"upload",doc.id,f"name={name}; bytes={len(data)}")
    return {"id":doc.id,"name":doc.name,"category":doc.category}
@app.get("/documents")
def list_documents(q: str="", category: str="", owner_id: int|None=None, user: User=Depends(current_user), db: Session=Depends(get_session)):
    docs=db.exec(select(Document).where(Document.deleted==False)).all(); out=[]
    for d in docs:
        g=db.exec(select(Grant).where(Grant.document_id==d.id,Grant.user_id==user.id)).first()
        if user.id==d.owner_id or g:
            if q.lower() in d.name.lower() and (not category or category.lower() in d.category.lower()) and (owner_id is None or owner_id==d.owner_id): out.append({"id":d.id,"name":d.name,"category":d.category,"owner_id":d.owner_id,"created_at":d.created_at,"size":d.size})
    return out
@app.get("/documents/{doc_id}")
def get_document(doc_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    d=authorized_document(db,user,doc_id); record(db,user.id,"read",d.id); return {"id":d.id,"name":d.name,"category":d.category,"owner_id":d.owner_id,"size":d.size,"created_at":d.created_at}
@app.get("/documents/{doc_id}/download")
def download(doc_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    d=authorized_document(db,user,doc_id); path=Path(settings.storage_dir)/d.storage_key
    if not path.is_file(): raise HTTPException(404,"File missing")
    record(db,user.id,"download",d.id); return FileResponse(path,media_type=d.content_type,filename=d.name)
@app.patch("/documents/{doc_id}")
def edit(doc_id:int,name:str|None=None,category:str|None=None,user:User=Depends(current_user),db:Session=Depends(get_session)):
    d=authorized_document(db,user,doc_id,"edit")
    if user.id!=d.owner_id:
        g=db.exec(select(Grant).where(Grant.document_id==doc_id,Grant.user_id==user.id)).first()
        if not g or g.permission!="edit": raise HTTPException(403,"Edit permission required")
    before=f"name={d.name}; category={d.category}"
    if name is not None: d.name=name[:200]
    if category is not None: d.category=category[:80]
    db.add(d); db.commit(); record(db,user.id,"change",d.id,before); return {"id":d.id,"name":d.name,"category":d.category}
@app.delete("/documents/{doc_id}")
def delete(doc_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    d=authorized_document(db,user,doc_id,"edit")
    if user.id!=d.owner_id and user.role!="admin": raise HTTPException(403,"Only owner may delete")
    d.deleted=True; db.add(d); db.commit(); record(db,user.id,"delete",d.id); return {"ok":True}
@app.put("/documents/{doc_id}/grants/{target_user_id}")
def grant(doc_id:int,target_user_id:int,permission:str,user:User=Depends(current_user),db:Session=Depends(get_session)):
    d=authorized_document(db,user,doc_id,"edit")
    if user.id!=d.owner_id and user.role!="admin": raise HTTPException(403,"Owner or admin required")
    if permission not in {"read","edit"}: raise HTTPException(400,"Permission must be read or edit")
    target=db.get(User,target_user_id)
    if not target or not target.active: raise HTTPException(404,"User not found")
    g=db.exec(select(Grant).where(Grant.document_id==doc_id,Grant.user_id==target_user_id)).first()
    if g: g.permission=permission
    else: db.add(Grant(document_id=doc_id,user_id=target_user_id,permission=permission))
    db.commit(); record(db,user.id,"grant",doc_id,f"target={target_user_id}; permission={permission}"); return {"ok":True}
@app.delete("/documents/{doc_id}/grants/{target_user_id}")
def revoke(doc_id:int,target_user_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    d=authorized_document(db,user,doc_id,"edit")
    if user.id!=d.owner_id and user.role!="admin": raise HTTPException(403,"Owner or admin required")
    g=db.exec(select(Grant).where(Grant.document_id==doc_id,Grant.user_id==target_user_id)).first()
    if g: db.delete(g); db.commit()
    record(db,user.id,"revoke",doc_id,f"target={target_user_id}"); return {"ok":True}
@app.get("/admin/users")
def users(user:User=Depends(require_admin),db:Session=Depends(get_session)):
    return [{"id":u.id,"email":u.email,"role":u.role,"active":u.active} for u in db.exec(select(User)).all()]
@app.get("/admin/audit")
def audit(user:User=Depends(require_admin),db:Session=Depends(get_session),limit:int=100):
    return [{"id":e.id,"actor_id":e.actor_id,"action":e.action,"document_id":e.document_id,"details":e.details,"occurred_at":e.occurred_at} for e in db.exec(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(min(limit,500))).all()]
