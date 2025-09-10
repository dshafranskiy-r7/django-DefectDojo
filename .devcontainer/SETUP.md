# DefectDojo DevContainer Configuration

This directory contains the Visual Studio Code DevContainer configuration for DefectDojo development.

## Files Overview

### Core Configuration
- **`devcontainer.json`** - Main DevContainer configuration
- **`Dockerfile`** - Custom development container image
- **`docker-compose.yml`** - Services for PostgreSQL and Redis
- **`setup.sh`** - Post-creation setup script

### VS Code Configuration
- **`../.vscode/launch.json`** - Debug configurations for Django
- **`../.vscode/tasks.json`** - Common Django development tasks

### Documentation
- **`README.md`** - Comprehensive usage guide

## Key Features

### 🐍 Python Environment
- Python 3.11.11 (matching project requirements)
- All dependencies from requirements.txt pre-installed
- Development tools: debugpy, ipdb, jupyter

### 🗄️ Database Services
- PostgreSQL 17.5 with DefectDojo schema
- Redis 7.2.10 for caching and message broker
- Health checks for reliable startup

### 🔧 Development Tools
- Ruff linting and formatting
- Django-specific VS Code extensions
- Pre-configured debugging setups
- Common Django management tasks

### 🚀 Quick Start
1. Open project in VS Code
2. Choose "Reopen in Container" when prompted
3. Wait for initial setup (5-10 minutes first time)
4. Run `python manage.py migrate`
5. Run `python manage.py createsuperuser`
6. Start developing!

## Architecture

```
DevContainer
├── Development Container (Python 3.11)
│   ├── Source code mounted at /workspaces/django-DefectDojo
│   ├── All Python dependencies pre-installed
│   └── VS Code extensions and settings
├── PostgreSQL Container
│   ├── Port 5432 exposed
│   └── Persistent data volume
└── Redis Container
    ├── Port 6379 exposed
    └── Persistent data volume
```

## Environment Variables

The devcontainer sets up these DefectDojo-specific environment variables:

- `DD_DEBUG=True` - Enable debug mode
- `DD_DATABASE_URL` - PostgreSQL connection string
- `DD_CELERY_BROKER_URL` - Redis connection string
- `DJANGO_SETTINGS_MODULE=dojo.settings.settings`
- Plus other DefectDojo configuration variables

## Debugging

The configuration includes several debugging scenarios:

1. **Django Development Server** - Debug the main web application
2. **Unit Tests** - Debug specific test cases
3. **Current File** - Debug any Python script
4. **Django Management Commands** - Debug custom management commands

## Customization

### Adding Extensions
Edit `devcontainer.json` and add extension IDs to the `extensions` array.

### Modifying Services
Edit `docker-compose.yml` to adjust PostgreSQL/Redis configuration or add new services.

### Python Dependencies
Add packages to `requirements.txt` or `requirements-lint.txt` and rebuild the container.

## Troubleshooting

### Container Won't Start
- Check Docker is running and has sufficient memory (4GB+ recommended)
- Try rebuilding: "Dev Containers: Rebuild Container"

### Database Connection Issues
- Ensure PostgreSQL service is healthy: `docker compose ps`
- Check environment variables in docker-compose.yml

### Performance Issues
- Increase Docker memory allocation
- Use WSL2 backend on Windows
- Consider using bind mounts instead of volumes for better performance

## Security Note

This configuration is designed for development only. It includes:
- Hard-coded secrets (change for production)
- Debug mode enabled
- Permissive ALLOWED_HOSTS setting
- Development-friendly PostgreSQL configuration

Never use these settings in production environments.