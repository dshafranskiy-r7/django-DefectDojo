# DefectDojo DevContainer

This DevContainer configuration provides a complete development environment for DefectDojo using the project's existing Docker infrastructure.

## What's Included

### Architecture
- **Uses existing Docker setup**: Leverages `docker-compose.yml` + `docker-compose.override.dev.yml`
- **DefectDojo Django container**: Based on the official `Dockerfile.django-debian` 
- **PostgreSQL**: Database service for DefectDojo
- **Redis**: Cache and message broker service
- **Nginx**: Reverse proxy (available at port 8080)

### Development Features
- **Integrated debugging**: Uses `docker/entrypoint-uwsgi-dev.sh` with debugpy on port 5678
- **Hot reloading**: Code changes automatically reflected
- **Volume mounting**: Live code editing with `.:/app:z` mount
- **Debug mode**: `DD_DEBUG=True` and `DD_UWSGI_DEBUG=True` enabled

### VS Code Extensions
- Python support with debugging
- Django support and snippets  
- Ruff linting and formatting
- Git and GitHub Copilot
- Additional helpful extensions for web development

## Quick Start

### Prerequisites
- [Docker](https://www.docker.com/get-started)
- [VS Code](https://code.visualstudio.com/)
- [Dev Containers Extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

### Getting Started

1. **Open in DevContainer**
   - Open the project in VS Code
   - When prompted, click "Reopen in Container" or use the Command Palette (`Ctrl+Shift+P`) and select "Dev Containers: Reopen in Container"

2. **Wait for Setup**
   - The initial setup uses the existing DefectDojo Docker infrastructure
   - All services (PostgreSQL, Redis, Django) will start automatically
   - The development server starts with debugpy enabled on port 5678

3. **Access the Application**
   - Django development server: http://localhost:8000
   - Full application with Nginx: http://localhost:8080
   - Default credentials: admin/admin
## Debugging

The DevContainer leverages DefectDojo's built-in debugging infrastructure:

### Remote Debugging (Recommended)
- **Debugpy server**: Automatically started on port 5678
- **VS Code configuration**: Use "Debug DefectDojo (Remote original)" launch configuration
- **How it works**: 
  1. The `DD_UWSGI_DEBUG=True` environment variable triggers debugpy mode
  2. `docker/entrypoint-uwsgi-dev.sh` runs: `debugpy --listen 0.0.0.0:5678 manage.py runserver 0.0.0.0:8000`
  3. VS Code connects to the remote debugpy session for full debugging

### Alternative Debugging
- Use other provided launch configurations for local debugging
- Set breakpoints in your Python code
- Use "Django: Debug Tests" to debug test cases

## Available Services

The devcontainer includes these services accessible on localhost:

- **Port 5678**: Python debugpy server (for remote debugging)
- **Port 8000**: Django development server  
- **Port 8080**: Full DefectDojo application via Nginx
- **Port 5432**: PostgreSQL database
- **Port 6379**: Redis cache

## Development Workflows

### Running Tests
```bash
# Run a specific test case
./run-unittest.sh --test-case unittests.test_utils.TestUtils.test_encryption

# Run integration tests
./run-integration-tests.sh --test-case "tests/finding_test.py"
```

### Database Operations
```bash
# Migrations are automatically run during container startup
# To run additional migrations:
python manage.py migrate

# Create migrations
python manage.py makemigrations

# Access Django shell
python manage.py shell

# Access database shell  
python manage.py dbshell
```

### Code Quality
```bash
# Lint code with Ruff
ruff check .

# Format code with Ruff
ruff format .
```

## VS Code Tasks

The devcontainer includes pre-configured VS Code tasks (accessible via `Ctrl+Shift+P` → "Tasks: Run Task"):

- **Django: Run Server** - Start the Django development server
- **Django: Make Migrations** - Create new database migrations
- **Django: Migrate** - Apply database migrations
- **Django: Create Superuser** - Create a Django superuser
- **Django: Shell** - Open Django shell
- **DefectDojo: Run Unit Tests** - Run specific unit tests
- **Python: Lint with Ruff** - Check code with Ruff linter
- **Python: Format with Ruff** - Format code with Ruff

## Debugging Configurations

Pre-configured debugging setups available in VS Code:

- **Django: Debug Server** - Debug the Django development server
- **Django: Debug Tests** - Debug Django test cases
- **Django: Debug Single Test** - Debug a specific test case
- **Python: Current File** - Debug the currently open Python file

## Environment Variables

The devcontainer is pre-configured with appropriate environment variables for development:

- `DD_DEBUG=True` - Enable Django debug mode
- `DD_ALLOWED_HOSTS=*` - Allow all hosts for development
- Database and Redis connection strings pointing to the included services
- Django settings module set to `dojo.settings.settings`

## Troubleshooting

### Container Build Issues
If the container fails to build:
1. Check Docker is running and has sufficient resources
2. Try rebuilding the container: Command Palette → "Dev Containers: Rebuild Container"

### Database Connection Issues
If you can't connect to the database:
1. Ensure PostgreSQL service is running: `docker compose ps`
2. Check the database service logs: `docker compose logs postgres`

### Permission Issues
If you encounter permission issues:
1. The container runs as the `vscode` user (UID 1000)
2. File permissions should be automatically handled

### Performance Issues
If the container is slow:
1. Increase Docker Desktop memory allocation
2. Ensure your system has sufficient resources
3. Consider using Docker's WSL2 backend on Windows

## Extending the Configuration

### Adding Python Packages
Edit `requirements.txt` or `requirements-lint.txt` and rebuild the container.

### Adding VS Code Extensions
Edit `.devcontainer/devcontainer.json` and add extension IDs to the `extensions` array.

### Modifying Services
Edit `.devcontainer/docker-compose.yml` to add or modify services.

## Production vs Development

This devcontainer is designed for development only. For production deployment, refer to:
- `docker-compose.yml` in the project root
- `readme-docs/DOCKER.md` for production setup instructions

## Support

For issues with the devcontainer setup, please check:
1. The main [DefectDojo documentation](readme-docs/DOCKER.md)
2. VS Code Dev Containers documentation
3. Project GitHub issues