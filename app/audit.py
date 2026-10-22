from app.models import AuditEvent
def record(db, actor_id, action, document_id=None, details=""):
    db.add(AuditEvent(actor_id=actor_id, action=action, document_id=document_id, details=details[:500]))
    db.commit()
