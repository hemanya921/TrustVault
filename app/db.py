
from collections.abc import Generator

from sqlmodel import SQLModel, Session, create_engine

from app.core.config import settings


database_url = str(settings.database_url)

connect_args = (
    {"check_same_thread": False}
    if database_url.startswith("sqlite")
    else {}
)

engine = create_engine(
    database_url,
    connect_args=connect_args,
)


def init_db() -> None:
    # Import models so SQLModel registers their tables.
    from app import models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
