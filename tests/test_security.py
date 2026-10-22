import os
os.environ["DATABASE_URL"]="sqlite:///./test_trustvault.db"
os.environ["STORAGE_DIR"]="./test_private_storage"
from fastapi.testclient import TestClient
from app.main import app
from app.db import engine
from sqlmodel import SQLModel
import pytest
@pytest.fixture(autouse=True)
def reset_db():
    SQLModel.metadata.drop_all(engine); SQLModel.metadata.create_all(engine)
    from app.seed import seed; seed()
    yield
    SQLModel.metadata.drop_all(engine)
def token(client,email,password):
    r=client.post('/auth/token',data={'username':email,'password':password}); return r.json()['access_token']
def test_other_user_cannot_read_download_edit_or_delete():
    with TestClient(app) as c:
        own=token(c,'owner@example.test','Owner123!'); stranger=token(c,'viewer@example.test','Viewer123!')
        doc=c.post('/documents',headers={'Authorization':f'Bearer {own}'},files={'file':('secret.txt',b'salary data','text/plain')}).json()['id']
        h={'Authorization':f'Bearer {stranger}'}
        assert c.get(f'/documents/{doc}',headers=h).status_code==404
        assert c.get(f'/documents/{doc}/download',headers=h).status_code==404
        assert c.patch(f'/documents/{doc}',headers=h,params={'name':'stolen'}).status_code==404
        assert c.delete(f'/documents/{doc}',headers=h).status_code==404
def test_revoke_blocks_subsequent_download():
    with TestClient(app) as c:
        own=token(c,'owner@example.test','Owner123!'); view=token(c,'viewer@example.test','Viewer123!')
        doc=c.post('/documents',headers={'Authorization':f'Bearer {own}'},files={'file':('secret.txt',b'x','text/plain')}).json()['id']
        ho={'Authorization':f'Bearer {own}'}; hv={'Authorization':f'Bearer {view}'}
        assert c.put(f'/documents/{doc}/grants/3',headers=ho,params={'permission':'read'}).status_code==200
        assert c.get(f'/documents/{doc}/download',headers=hv).status_code==200
        assert c.delete(f'/documents/{doc}/grants/3',headers=ho).status_code==200
        assert c.get(f'/documents/{doc}/download',headers=hv).status_code==404
