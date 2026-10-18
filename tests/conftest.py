import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from src.database.session import Base, get_db
from src.main import app
from src.middleware.rate_limiter import login_rate_limiter
from src.models.user import User
from src.utils.hash import hash_password

# Use in-memory SQLite database for isolated test execution
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"

engine_test = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_test)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine_test)
    login_rate_limiter.reset_all()
    yield
    Base.metadata.drop_all(bind=engine_test)
    login_rate_limiter.reset_all()


@pytest.fixture
def db():
    connection = engine_test.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client():
    def override_get_db():
        db_session = TestingSessionLocal()
        try:
            yield db_session
        finally:
            db_session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def seed_users(client):
    """Creates a standard set of test users."""
    db_session = TestingSessionLocal()
    users = [
        User(username="test_user1", password_hash=hash_password("Password123!"), role="user"),
        User(username="test_user2", password_hash=hash_password("Password123!"), role="user"),
        User(username="test_curator", password_hash=hash_password("Password123!"), role="curator"),
        User(username="test_admin", password_hash=hash_password("Password123!"), role="admin"),
    ]
    db_session.add_all(users)
    db_session.commit()
    db_session.close()
