from fastapi import HTTPException
from sqlmodel import select
from app.models import Document, Grant
def authorized_document(db, user, doc_id, required="read"):
    doc = db.get(Document, doc_id)
    if not doc or doc.deleted: raise HTTPException(404, "Document not found")
    grant = db.exec(select(Grant).where(Grant.document_id==doc_id, Grant.user_id==user.id)).first()
    if user.id != doc.owner_id and not (grant and (grant.permission == "edit" or (grant.permission == "read" and required == "read"))):
        raise HTTPException(404, "Document not found")
    return doc
