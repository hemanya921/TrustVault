import os
import tempfile
from pathlib import Path

# Set test configuration before importing application modules.
# These paths are separate from the live application database/storage.
_test_workspace = tempfile.TemporaryDirectory(
    prefix="trustvault-tests-"
)
_test_root = Path(_test_workspace.name)
_test_database = _test_root / "test_trustvault.db"
_test_storage = _test_root / "private_storage"

_test_storage.mkdir(parents=True, exist_ok=True)

os.environ["DATABASE_URL"] = (
    f"sqlite:///{_test_database.as_posix()}"
)
os.environ["STORAGE_DIR"] = str(_test_storage)
os.environ["SECRET_KEY"] = (
    "test-only-secret-not-for-production-"
    "f7268ea2b19943baa0dc88609a664847"
)

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

from app.db import engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_workspace():
    """Release pooled connections before removing temporary files."""
    yield

    engine.dispose()
    _test_workspace.cleanup()


@pytest.fixture(autouse=True)
def reset_database(cleanup_test_workspace):
    """Create a fresh database for every test."""
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)

    try:
        from app.seed import seed

        seed()
        yield
    finally:
        try:
            SQLModel.metadata.drop_all(engine)
        finally:
            engine.dispose()

            for path in _test_storage.iterdir():
                if path.is_file():
                    path.unlink()


@pytest.fixture
def client(reset_database):
    """Start and stop the application for every test."""
    with TestClient(app) as test_client:
        yield test_client


def login_headers(client, email, password):
    response = client.post(
        "/auth/token",
        data={
            "username": email,
            "password": password,
        },
    )

    assert response.status_code == 200, response.text

    access_token = response.json()["access_token"]

    return {
        "Authorization": f"Bearer {access_token}"
    }


@pytest.fixture
def accounts(client):
    return {
        "owner": login_headers(
            client,
            "owner@example.test",
            "Owner123!",
        ),
        "viewer": login_headers(
            client,
            "viewer@example.test",
            "Viewer123!",
        ),
        "admin": login_headers(
            client,
            "admin@example.test",
            "Admin123!",
        ),
    }


def get_user_id(client, headers):
    response = client.get(
        "/auth/me",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    return response.json()["id"]


def create_document(
    client,
    owner_headers,
    filename="confidential.txt",
    content=b"Confidential test document",
):
    response = client.post(
        "/documents",
        headers=owner_headers,
        files={
            "file": (
                filename,
                content,
                "text/plain",
            )
        },
        data={
            "category": "General"
        },
    )

    assert response.status_code == 200, response.text

    return response.json()["id"]


def grant_access(
    client,
    owner_headers,
    document_id,
    target_user_id,
    permission,
):
    response = client.put(
        f"/documents/{document_id}/grants/{target_user_id}",
        headers=owner_headers,
        params={
            "permission": permission
        },
    )

    assert response.status_code == 200, response.text


def assert_access_denied(response):
    assert response.status_code in {403, 404}, (
        "Expected access denial, received "
        f"{response.status_code}: {response.text}"
    )


def test_other_user_cannot_read_download_edit_or_delete(
    client,
    accounts,
):
    owner = accounts["owner"]
    viewer = accounts["viewer"]

    document_id = create_document(client, owner)

    response = client.get(
        f"/documents/{document_id}",
        headers=viewer,
    )
    assert_access_denied(response)

    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert_access_denied(response)
    assert b"Confidential test document" not in response.content

    response = client.patch(
        f"/documents/{document_id}",
        headers=viewer,
        params={
            "name": "stolen.txt"
        },
    )
    assert_access_denied(response)

    response = client.delete(
        f"/documents/{document_id}",
        headers=viewer,
    )
    assert_access_denied(response)

    # Denied requests must not change or delete the document.
    response = client.get(
        f"/documents/{document_id}",
        headers=owner,
    )
    assert response.status_code == 200, response.text
    assert response.json()["name"] == "confidential.txt"

    response = client.get(
        f"/documents/{document_id}/download",
        headers=owner,
    )
    assert response.status_code == 200
    assert response.content == b"Confidential test document"


def test_revoke_blocks_subsequent_download(
    client,
    accounts,
):
    owner = accounts["owner"]
    viewer = accounts["viewer"]

    viewer_id = get_user_id(client, viewer)
    document_id = create_document(client, owner)

    grant_access(
        client,
        owner,
        document_id,
        viewer_id,
        "read",
    )

    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert response.status_code == 200
    assert response.content == b"Confidential test document"

    response = client.delete(
        f"/documents/{document_id}/grants/{viewer_id}",
        headers=owner,
    )
    assert response.status_code == 200, response.text

    # Reuse the same token after revocation.
    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert_access_denied(response)
    assert b"Confidential test document" not in response.content


def test_anonymous_user_cannot_download(
    client,
    accounts,
):
    document_id = create_document(
        client,
        accounts["owner"],
    )

    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 401, response.text
    assert b"Confidential test document" not in response.content


def test_read_recipient_cannot_edit_delete_or_manage_grants(
    client,
    accounts,
):
    owner = accounts["owner"]
    viewer = accounts["viewer"]
    admin = accounts["admin"]

    viewer_id = get_user_id(client, viewer)
    admin_id = get_user_id(client, admin)

    document_id = create_document(client, owner)

    grant_access(
        client,
        owner,
        document_id,
        viewer_id,
        "read",
    )

    # Verify that legitimate read access works.
    response = client.get(
        f"/documents/{document_id}",
        headers=viewer,
    )
    assert response.status_code == 200

    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert response.status_code == 200
    assert response.content == b"Confidential test document"

    response = client.patch(
        f"/documents/{document_id}",
        headers=viewer,
        params={
            "name": "unauthorized-change.txt"
        },
    )
    assert_access_denied(response)

    response = client.delete(
        f"/documents/{document_id}",
        headers=viewer,
    )
    assert_access_denied(response)

    # A read recipient cannot upgrade their own permission.
    response = client.put(
        f"/documents/{document_id}/grants/{viewer_id}",
        headers=viewer,
        params={
            "permission": "edit"
        },
    )
    assert_access_denied(response)

    # Confirm that the attempted upgrade did not take effect.
    response = client.patch(
        f"/documents/{document_id}",
        headers=viewer,
        params={
            "name": "change-after-upgrade-attempt.txt"
        },
    )
    assert_access_denied(response)

    # A read recipient cannot grant access to another user.
    response = client.put(
        f"/documents/{document_id}/grants/{admin_id}",
        headers=viewer,
        params={
            "permission": "read"
        },
    )
    assert_access_denied(response)

    response = client.get(
        f"/documents/{document_id}/download",
        headers=admin,
    )
    assert_access_denied(response)

    # A read recipient cannot use owner-only grant management.
    response = client.delete(
        f"/documents/{document_id}/grants/{viewer_id}",
        headers=viewer,
    )
    assert_access_denied(response)

    # The original read grant must still work.
    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert response.status_code == 200

    response = client.get(
        f"/documents/{document_id}",
        headers=owner,
    )
    assert response.status_code == 200
    assert response.json()["name"] == "confidential.txt"


def test_edit_recipient_cannot_delete_or_manage_grants(
    client,
    accounts,
):
    owner = accounts["owner"]
    viewer = accounts["viewer"]
    admin = accounts["admin"]

    viewer_id = get_user_id(client, viewer)
    admin_id = get_user_id(client, admin)

    document_id = create_document(client, owner)

    grant_access(
        client,
        owner,
        document_id,
        viewer_id,
        "edit",
    )

    # Edit permission permits metadata changes.
    response = client.patch(
        f"/documents/{document_id}",
        headers=viewer,
        params={
            "name": "permitted-change.txt"
        },
    )
    assert response.status_code == 200, response.text

    # Edit permission does not permit deletion.
    response = client.delete(
        f"/documents/{document_id}",
        headers=viewer,
    )
    assert_access_denied(response)

    # Edit permission does not permit granting access.
    response = client.put(
        f"/documents/{document_id}/grants/{admin_id}",
        headers=viewer,
        params={
            "permission": "read"
        },
    )
    assert_access_denied(response)

    # Edit permission does not permit revoking grants.
    response = client.delete(
        f"/documents/{document_id}/grants/{viewer_id}",
        headers=viewer,
    )
    assert_access_denied(response)

    # Verify the actual effects of these requests.
    response = client.get(
        f"/documents/{document_id}",
        headers=owner,
    )
    assert response.status_code == 200
    assert response.json()["name"] == "permitted-change.txt"

    response = client.get(
        f"/documents/{document_id}/download",
        headers=admin,
    )
    assert_access_denied(response)

    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert response.status_code == 200


def test_admin_has_no_implicit_document_access(
    client,
    accounts,
):
    owner = accounts["owner"]
    admin = accounts["admin"]

    document_id = create_document(client, owner)

    response = client.get(
        f"/documents/{document_id}",
        headers=admin,
    )
    assert_access_denied(response)

    response = client.get(
        f"/documents/{document_id}/download",
        headers=admin,
    )
    assert_access_denied(response)
    assert b"Confidential test document" not in response.content

    # Audit access is separate from document-content access.
    response = client.get(
        "/admin/audit",
        headers=admin,
    )
    assert response.status_code == 200, response.text


def test_search_does_not_expose_unshared_documents(
    client,
    accounts,
):
    owner = accounts["owner"]
    viewer = accounts["viewer"]

    owner_id = get_user_id(client, owner)
    document_id = create_document(client, owner)

    filters_to_test = [
        {},
        {
            "q": "confidential"
        },
        {
            "owner_id": owner_id
        },
        {
            "category": "General"
        },
        {
            "q": "confidential",
            "owner_id": owner_id,
            "category": "General",
        },
    ]

    for filters in filters_to_test:
        response = client.get(
            "/documents",
            headers=viewer,
            params=filters,
        )

        assert response.status_code == 200, response.text
        assert response.json() == [], (
            "Unshared document exposed with filters: "
            f"{filters}"
        )

    # Confirm that the document exists and its owner can list it.
    response = client.get(
        "/documents",
        headers=owner,
    )
    assert response.status_code == 200

    visible_ids = {
        item["id"]
        for item in response.json()
    }
    assert document_id in visible_ids


def test_revocation_blocks_metadata_download_and_edit(
    client,
    accounts,
):
    owner = accounts["owner"]
    viewer = accounts["viewer"]

    viewer_id = get_user_id(client, viewer)
    document_id = create_document(client, owner)

    grant_access(
        client,
        owner,
        document_id,
        viewer_id,
        "edit",
    )

    # Confirm that granted operations work before revocation.
    response = client.get(
        f"/documents/{document_id}",
        headers=viewer,
    )
    assert response.status_code == 200

    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert response.status_code == 200

    response = client.patch(
        f"/documents/{document_id}",
        headers=viewer,
        params={
            "category": "Reviewed"
        },
    )
    assert response.status_code == 200

    response = client.delete(
        f"/documents/{document_id}/grants/{viewer_id}",
        headers=owner,
    )
    assert response.status_code == 200, response.text

    # Reuse the same credentials after revocation.
    response = client.get(
        f"/documents/{document_id}",
        headers=viewer,
    )
    assert_access_denied(response)

    response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer,
    )
    assert_access_denied(response)
    assert b"Confidential test document" not in response.content

    response = client.patch(
        f"/documents/{document_id}",
        headers=viewer,
        params={
            "name": "change-after-revocation.txt"
        },
    )
    assert_access_denied(response)

    response = client.get(
        "/documents",
        headers=viewer,
    )
    assert response.status_code == 200
    assert response.json() == []

    # Confirm that the refused edit did not change the document.
    response = client.get(
        f"/documents/{document_id}",
        headers=owner,
    )
    assert response.status_code == 200
    assert response.json()["name"] == "confidential.txt"
    assert response.json()["category"] == "Reviewed"