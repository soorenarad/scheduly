# Scheduly - Social Media Post Scheduling API

A comprehensive FastAPI-based application for scheduling and managing social media posts across multiple channels and organizations. The system supports role-based access control, post approval workflows, and automated publishing using Celery.

## Features

- **User Authentication & Authorization**
  - JWT-based authentication with access and refresh tokens
  - Secure password hashing using pbkdf2_sha256
  - Token refresh mechanism with Redis-backed revocation

- **Organization Management**
  - Create and manage organizations
  - Role-based access control (Owner, Admin, Editor, Viewer)
  - Invite members to organizations
  - Manage member roles and permissions

- **Channel Management**
  - Connect multiple social media channels (Twitter, Instagram)
  - OAuth-based channel authentication
  - Channel activation and management

- **Post Scheduling**
  - Create and schedule posts for future publication
  - Support for text and media content
  - Post approval workflow for editors
  - Post status tracking (draft, queued, publishing, published, failed, canceled)
  - Edit and cancel scheduled posts
  - Immediate publishing option

- **Background Processing**
  - Celery-based task queue for scheduled post publishing
  - Automatic post publication at scheduled times
  - Error handling and status updates

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL (via SQLAlchemy ORM)
- **Task Queue**: Celery with Redis broker
- **Caching/Session**: Redis
- **Authentication**: JWT (python-jose)
- **Password Hashing**: Passlib (pbkdf2_sha256)
- **Migrations**: Alembic

## Prerequisites

- Python 3.8+
- PostgreSQL database
- Redis server
- Celery worker (for background tasks)

## Installation

### Quick Start with Docker (Recommended)

The easiest way to run the application is using Docker Compose:

```bash
docker-compose up
```

This single command will:
- Start PostgreSQL database
- Start Redis server
- Build and start the FastAPI application
- Start Celery worker
- Run database migrations automatically

The API will be available at `http://localhost:8000`

To run in detached mode (background):
```bash
docker-compose up -d
```

To stop all services:
```bash
docker-compose down
```

To stop and remove volumes (clears database):
```bash
docker-compose down -v
```

### Manual Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd scheduly
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   DB_URL=postgresql://username:password@localhost:5432/dbname
   Redis_host=localhost
   Redis_port=6379
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

6. **Start Redis server**
   ```bash
   redis-server
   ```

7. **Start Celery worker** (in a separate terminal)
   ```bash
   celery -A celery_app worker --loglevel=info
   ```

8. **Start the FastAPI server**
   ```bash
   uvicorn main:app --reload
   ```

The API will be available at `http://localhost:8000`

## API Documentation

Once the server is running, you can access:
- **Interactive API docs**: `http://localhost:8000/docs` (Swagger UI)
- **Alternative docs**: `http://localhost:8000/redoc` (ReDoc)

## Project Structure

```
scheduly/
├── alembic/              # Database migration scripts
│   ├── versions/         # Migration version files
│   └── env.py           # Alembic environment configuration
├── main.py              # FastAPI application and API endpoints
├── models.py            # SQLAlchemy database models
├── db.py                # Database connection and session management
├── dbcrud.py            # Database CRUD operations
├── jwt_manual.py        # JWT token creation and verification
├── celery_app.py        # Celery application configuration
├── celery_task.py       # Celery background tasks
├── alembic.ini          # Alembic configuration
├── requirements.txt     # Python dependencies
├── Dockerfile           # Docker image configuration
├── docker-compose.yml   # Docker Compose orchestration
├── .dockerignore        # Files to exclude from Docker build
└── README.md           # This file
```

## API Endpoints

### Authentication

- `POST /auth/signup` - Create a new user account
- `POST /auth/signin` - Sign in and get access token
- `POST /auth/access` - Get new access token using refresh token
- `POST /auth/logout` - Logout and revoke refresh token

### Organizations

- `POST /orgs` - Create a new organization
- `GET /orgs/{org_id}/members` - Get organization members
- `POST /orgs/{org_id}/invite` - Invite a member to organization
- `PATCH /orgs/{org_id}/members/{user_id}` - Update member role

### Channels

- `POST /orgs/{org_id}/channels/oauth` - Create channel and get OAuth URL
- `POST /orgs/{org_id}/channels/{channel_id}/oauth/callback` - Handle OAuth callback
- `GET /orgs/{org_id}/channels` - List all channels for an organization
- `DELETE /channels/{channel_id}` - Delete a channel

### Posts

- `POST /orgs/{org_id}/posts` - Create a new scheduled post
- `GET /orgs/{org_id}/posts` - List posts with pagination and filtering
- `POST /posts/{post_id}` - Edit an existing post
- `POST /posts/{post_id}/approve` - Approve a post (for editors)
- `POST /posts/{post_id}/cancel` - Cancel a scheduled post
- `POST /posts/{post_id}/publish` - Publish a post immediately

## Database Models

### Core Models

- **User**: User accounts with email, username, and hashed password
- **Organizations**: Organizations that users can belong to
- **UserOrgMemberships**: Many-to-many relationship between users and organizations with roles
- **Channels**: Social media channels connected to organizations
- **Posts**: Scheduled posts with content, scheduling info, and status
- **PostApprovals**: Approval records for posts requiring approval

### Enums

- **OrgRole**: `owner`, `admin`, `editor`, `viewer`
- **Providers**: `twt` (Twitter), `insta` (Instagram)
- **StatusPosts**: `draft`, `queued`, `publishing`, `published`, `failed`, `canceled`

## Role-Based Permissions

### Owner
- Full access to all organization features
- Can manage members and roles
- Can create, edit, approve, and publish posts
- Can manage channels

### Admin
- Similar to owner, except cannot change owner role
- Can manage members (except owners)
- Can create, edit, approve, and publish posts
- Can manage channels

### Editor
- Can create and edit posts (requires approval)
- Cannot approve or publish posts
- Cannot manage channels or members

### Viewer
- Read-only access
- Can view posts and channels
- Cannot create, edit, or manage anything

## Post Approval Workflow

1. **Editors** create posts that require approval
2. **Owners/Admins** can approve posts
3. Once approved, posts are automatically published at the scheduled time
4. **Owners/Admins** can also publish posts immediately without scheduling

## Background Tasks

The application uses Celery for background task processing:

- **publish_post**: Automatically publishes scheduled posts at their scheduled time
- Tasks are stored in Redis and executed by Celery workers
- Failed tasks update post status and store error messages

## Security Features

- JWT-based authentication with access and refresh tokens
- Refresh tokens stored in Redis for revocation capability
- HTTP-only cookies for refresh tokens
- Secure password hashing
- Role-based access control on all endpoints
- Input validation using Pydantic models

## Development

### Running Tests

(Add test instructions when tests are implemented)

### Code Style

The project follows PEP 8 style guidelines. Consider using:
- `black` for code formatting
- `flake8` or `pylint` for linting
- `mypy` for type checking

### Database Migrations

Create a new migration:
```bash
alembic revision --autogenerate -m "description of changes"
```

Apply migrations:
```bash
alembic upgrade head
```

Rollback migration:
```bash
alembic downgrade -1
```

## Environment Variables

| Variable | Description | Required | Default (Docker) |
|----------|-------------|----------|-------------------|
| `DB_URL` | PostgreSQL database connection string | Yes | `postgresql://scheduly:scheduly_password@db:5432/scheduly_db` |
| `Redis_host` | Redis server hostname | Yes | `redis` |
| `Redis_port` | Redis server port | Yes | `6379` |

**Note**: When using Docker Compose, these variables are automatically set. For manual installation, create a `.env` file with the appropriate values.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

(Add your license information here)

## Support

For issues and questions, please open an issue on the GitHub repository.

