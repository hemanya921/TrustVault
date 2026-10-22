
import os
import tempfile
from pathlib import Path

# Configure test environment before importing the application.
_test_workspace = tempfile.TemporaryDirectory(prefix="trustvault_tests_")
_test_root = Path(_test_workspace.name)
_test_database = _test_root / "test.db"
_test_storage = _test_root / "storage"
_test_storage.mkdir(parents=True, exist_ok=True)

os.environ["DATABASE_URL"] = f"sqlite:///{_test_database.as_posix()}"
os.environ["STORAGE_DIR"] = str(_test_storage)
os.environ["SECRET_KEY"] = (
    "test-only-secret-not-for-production-f7268ea2b19943baa0dc88609a664847"
)

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

from app.db import engine
from app.main import app
from app.seed import seed


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_workspace():
    """Dispose of the database engine and remove temporary test files."""
    try:
        yield
    finally:
        engine.dispose()
        _test_workspace.cleanup()


@pytest.fixture(autouse=True)
def reset_database():
    """Create a clean database and seed test accounts before each test."""
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    seed()
    yield


@pytest.fixture
def client():
    """Create a FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


def login_headers(client, email, password):
    """Log in and return authorization headers."""
    response = client.post(
        "/auth/token",
        data={"username": email, "password": password},
    )
    assert response.status_code == 200, response.text

    access_token = response.json()["access_token"]
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def accounts(client):
    """Authenticate the seeded test accounts."""
    return {
        "owner": login_headers(
            client, "owner@example.test", "Owner123!"
        ),
        "viewer": login_headers(
            client, "viewer@example.test", "Viewer123!"
        ),
        "admin": login_headers(
            client, "admin@example.test", "Admin123!"
        ),
    }


def get_user_id(client, headers):
    """Return the authenticated user's database ID."""
    response = client.get("/auth/me", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["id"]


def create_document(
    client,
    owner_headers,
    filename="confidential.txt",
    content=b"Confidential test document",
):
    """Upload a text document and return the response."""
    response = client.post(
        "/documents",
        headers=owner_headers,
        files={
            "file": (filename, content, "text/plain"),
        },
    )
    assert response.status_code in (200, 201), response.text
    return response


# ---------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------

def test_unauthenticated_user_cannot_list_documents(client):
    response = client.get("/documents")
    assert response.status_code == 401


def test_unauthenticated_user_cannot_upload_document(client):
    response = client.post(
        "/documents",
        files={
            "file": ("test.txt", b"test content", "text/plain"),
        },
    )
    assert response.status_code == 401


def test_owner_can_view_own_profile(client, accounts):
    response = client.get(
        "/auth/me",
        headers=accounts["owner"],
    )

    assert response.status_code == 200
    assert response.json()["email"] == "owner@example.test"


def test_invalid_login_is_rejected(client):
    response = client.post(
        "/auth/token",
        data={
            "username": "owner@example.test",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401


# ---------------------------------------------------------
# Document upload and access tests
# ---------------------------------------------------------

def test_owner_can_upload_document(client, accounts):
    response = create_document(client, accounts["owner"])

    assert response.status_code in (200, 201)
    assert response.json()["name"] == "confidential.txt"
    assert "id" in response.json()


def test_owner_can_read_own_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}",
        headers=accounts["owner"],
    )

    assert response.status_code == 200
    assert response.json()["name"] == "confidential.txt"


def test_viewer_cannot_read_private_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}",
        headers=accounts["viewer"],
    )

    assert response.status_code == 404


def test_owner_can_list_own_document(client, accounts):
    create_document(client, accounts["owner"])

    response = client.get(
        "/documents",
        headers=accounts["owner"],
    )

    assert response.status_code == 200
    assert any(
        document["name"] == "confidential.txt"
        for document in response.json()
    )


def test_viewer_cannot_download_private_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}/download",
        headers=accounts["viewer"],
    )

    assert response.status_code == 404


# ---------------------------------------------------------
# Sharing and permission tests
# ---------------------------------------------------------

def test_owner_can_share_document_with_read_permission(
    client, accounts
):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    viewer_id = get_user_id(client, accounts["viewer"])

    grant_response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        params={"permission": "read"},
        headers=accounts["owner"],
    )

    assert grant_response.status_code == 200

    read_response = client.get(
        f"/documents/{document_id}",
        headers=accounts["viewer"],
    )

    assert read_response.status_code == 200


def test_shared_viewer_can_download_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    viewer_id = get_user_id(client, accounts["viewer"])

    grant_response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        params={"permission": "read"},
        headers=accounts["owner"],
    )
    assert grant_response.status_code == 200

    download_response = client.get(
        f"/documents/{document_id}/download",
        headers=accounts["viewer"],
    )

    assert download_response.status_code == 200
    assert download_response.content == b"Confidential test document"


def test_read_permission_does_not_allow_editing(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    viewer_id = get_user_id(client, accounts["viewer"])

    grant_response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        params={"permission": "read"},
        headers=accounts["owner"],
    )
    assert grant_response.status_code == 200

    edit_response = client.patch(
        f"/documents/{document_id}",
        params={"name": "changed.txt"},
        headers=accounts["viewer"],
    )

    assert edit_response.status_code == 404


def test_owner_can_grant_edit_permission(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    viewer_id = get_user_id(client, accounts["viewer"])

    response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        params={"permission": "edit"},
        headers=accounts["owner"],
    )

    assert response.status_code == 200

    edit_response = client.patch(
        f"/documents/{document_id}",
        params={"name": "updated.txt"},
        headers=accounts["viewer"],
    )

    assert edit_response.status_code == 200
    assert edit_response.json()["name"] == "updated.txt"


def test_invalid_permission_is_rejected(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    viewer_id = get_user_id(client, accounts["viewer"])

    response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        params={"permission": "admin"},
        headers=accounts["owner"],
    )

    assert response.status_code == 400


def test_non_owner_cannot_share_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    admin_id = get_user_id(client, accounts["admin"])

    # The viewer has no edit grant and must not be allowed to share.
    response = client.put(
        f"/documents/{document_id}/grants/{admin_id}",
        params={"permission": "read"},
        headers=accounts["viewer"],
    )

    assert response.status_code == 404


# ---------------------------------------------------------
# Revocation tests
# ---------------------------------------------------------

def test_revoked_user_cannot_read_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    viewer_id = get_user_id(client, accounts["viewer"])

    grant_response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        params={"permission": "read"},
        headers=accounts["owner"],
    )
    assert grant_response.status_code == 200

    revoke_response = client.delete(
        f"/documents/{document_id}/grants/{viewer_id}",
        headers=accounts["owner"],
    )
    assert revoke_response.status_code == 200

    read_response = client.get(
        f"/documents/{document_id}",
        headers=accounts["viewer"],
    )

    assert read_response.status_code == 404


def test_non_owner_cannot_revoke_grant(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]
    viewer_id = get_user_id(client, accounts["viewer"])
    admin_id = get_user_id(client, accounts["admin"])

    grant_response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        params={"permission": "read"},
        headers=accounts["owner"],
    )
    assert grant_response.status_code == 200

    response = client.delete(
        f"/documents/{document_id}/grants/{admin_id}",
        headers=accounts["viewer"],
    )

    assert response.status_code == 404


# ---------------------------------------------------------
# Document update and deletion tests
# ---------------------------------------------------------

def test_owner_can_update_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]

    response = client.patch(
        f"/documents/{document_id}",
        params={
            "name": "updated.txt",
            "category": "Reports",
        },
        headers=accounts["owner"],
    )

    assert response.status_code == 200
    assert response.json()["name"] == "updated.txt"
    assert response.json()["category"] == "Reports"


def test_viewer_cannot_delete_private_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]

    response = client.delete(
        f"/documents/{document_id}",
        headers=accounts["viewer"],
    )

    assert response.status_code == 404


def test_owner_can_delete_document(client, accounts):
    upload_response = create_document(client, accounts["owner"])
    document_id = upload_response.json()["id"]

    delete_response = client.delete(
        f"/documents/{document_id}",
        headers=accounts["owner"],
    )

    assert delete_response.status_code == 200
    assert delete_response.json()["ok"] is True

    read_response = client.get(
        f"/documents/{document_id}",
        headers=accounts["owner"],
    )

    assert read_response.status_code == 404


# ---------------------------------------------------------
# File validation tests
# ---------------------------------------------------------

def test_unsupported_file_type_is_rejected(client, accounts):
    response = client.post(
        "/documents",
        headers=accounts["owner"],
        files={
            "file": (
                "malware.exe",
                b"not an executable",
                "application/octet-stream",
            ),
        },
    )

    assert response.status_code == 415


def test_hidden_filename_is_rejected(client, accounts):
    response = client.post(
        "/documents",
        headers=accounts["owner"],
        files={
            "file": (".secret.txt", b"secret", "text/plain"),
        },
    )

    assert response.status_code == 400


# ---------------------------------------------------------
# Administrator access tests
# ---------------------------------------------------------

def test_non_admin_cannot_access_admin_users(client, accounts):
    response = client.get(
        "/admin/users",
        headers=accounts["viewer"],
    )

    assert response.status_code == 403


def test_admin_can_access_admin_users(client, accounts):
    response = client.get(
        "/admin/users",
        headers=accounts["admin"],
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_non_admin_cannot_access_audit_log(client, accounts):
    response = client.get(
        "/admin/audit",
        headers=accounts["viewer"],
    )

    assert response.status_code == 403


def test_admin_can_access_audit_log(client, accounts):
    response = client.get(
        "/admin/audit",
        headers=accounts["admin"],
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
