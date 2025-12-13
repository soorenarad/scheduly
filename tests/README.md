# Test Suite Documentation

This directory contains comprehensive pytest tests for all API endpoints in the Scheduly application.

## Test Structure

- `conftest.py`: Shared fixtures and test configuration
- `test_auth.py`: Authentication endpoints (signup, signin, access token, logout)
- `test_organizations.py`: Organization management endpoints
- `test_channels.py`: Channel management endpoints
- `test_posts.py`: Post management endpoints

## Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_auth.py

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=. --cov-report=html
```

## Test Coverage

### Authentication Tests (`test_auth.py`)
- User signup (success, duplicate email/username, invalid email)
- User signin (success, wrong credentials)
- Access token refresh
- Logout

### Organization Tests (`test_organizations.py`)
- Create organization
- Get organization members
- Invite members (with role-based permissions)
- Change member roles (with permission checks)

### Channel Tests (`test_channels.py`)
- Create channel (OAuth flow)
- OAuth callback
- Get channels
- Delete channels (with permission checks)

### Post Tests (`test_posts.py`)
- Create posts (with role-based approval requirements)
- List posts (with filtering and pagination)
- Edit posts (with permission checks)
- Approve posts
- Cancel posts
- Publish posts immediately

## Test Fixtures

- `db_session`: In-memory SQLite database session
- `redis_mock`: Mock Redis client
- `client`: Async HTTP test client
- `test_user`: Test user with owner role
- `test_user2`: Second test user
- `test_org`: Test organization
- `test_channel`: Test channel
- `auth_headers`: Authentication headers for test user
- `admin_user`: Admin user in organization
- `editor_user`: Editor user in organization
- `viewer_user`: Viewer user in organization

## Notes

- Tests use an in-memory SQLite database for isolation
- Redis is mocked to avoid external dependencies
- Each test is independent and cleans up after itself
- Tests cover both success cases and error scenarios
- Role-based permissions are thoroughly tested
