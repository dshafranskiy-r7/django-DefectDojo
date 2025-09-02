# DefectDojo DevContainer Configuration

This directory contains the Visual Studio Code DevContainer configuration for DefectDojo development that leverages the existing Docker infrastructure.

## Files Overview

### Core Configuration
- **`devcontainer.json`** - Main DevContainer configuration using existing Docker setup
- **`setup.sh`** - Post-creation setup script

### VS Code Configuration  
- **`../.vscode/launch.json`** - Debug configurations for Django
- **`../.vscode/tasks.json`** - Common Django development tasks

### Documentation
- **`README.md`** - Comprehensive usage guide

## Key Features

### 🏗️ Infrastructure Reuse
- Uses existing `docker-compose.yml` + `docker-compose.override.dev.yml`
- Leverages official `Dockerfile.django-debian` container
- Utilizes `docker/entrypoint-uwsgi-dev.sh` for debugging

### 🐞 Integrated Debugging
- **Remote debugging**: debugpy server on port 5678 
- **Automatic setup**: `DD_UWSGI_DEBUG=True` enables debug mode
- **VS Code integration**: Pre-configured launch configurations

### 🗄️ Database Services
- PostgreSQL with DefectDojo schema
- Redis for caching and message broker
- All services from the standard DefectDojo Docker setup

### 🔧 Development Tools
- Hot reloading with volume mounts
- Ruff linting and formatting
- Django-specific VS Code extensions
- Pre-configured debugging setups

### 🚀 Quick Start
1. Open project in VS Code
2. Choose "Reopen in Container" when prompted  
3. Services start automatically using existing Docker infrastructure
4. Access application at http://localhost:8000 or http://localhost:8080
5. Debug server automatically available on port 5678

## Architecture

```
DevContainer (uses existing infrastructure)
├── uwsgi service (from docker-compose setup)
│   ├── Source code mounted at /app
│   ├── Python 3.11 with all DefectDojo dependencies
│   ├── debugpy server on port 5678
│   └── VS Code extensions and settings
├── PostgreSQL Container (from existing setup)
│   ├── Port 5432 exposed
│   └── Persistent data volume
├── Redis Container (from existing setup)
│   ├── Port 6379 exposed  
│   └── Persistent data volume
├── nginx Container (from existing setup)
│   └── Port 8080 exposed
└── Other services (celeryworker, celerybeat, initializer)
```

## Environment Variables

The devcontainer uses DefectDojo's existing environment variables:

- `DD_DEBUG=True` - Enable debug mode
- `DD_UWSGI_DEBUG=True` - Enable debugpy remote debugging
- `DD_ADMIN_PASSWORD=admin` - Set admin password
- Plus all standard DefectDojo configuration from docker-compose.override.dev.yml

## Debugging

The configuration leverages DefectDojo's built-in debugging infrastructure:

### Remote Debugging (Primary Method)
- **debugpy server**: Automatically runs on port 5678 when `DD_UWSGI_DEBUG=True`  
- **Entry point**: Uses `docker/entrypoint-uwsgi-dev.sh` which runs:
  ```bash
  debugpy --listen 0.0.0.0:5678 manage.py runserver 0.0.0.0:8000
  ```
- **VS Code**: Use "Debug DefectDojo (Remote original)" launch configuration

### Additional Debugging Options
1. **Current File** - Debug any Python script
2. **Django Tests** - Debug specific test cases  
3. **Django Management Commands** - Debug custom management commands

## Customization

### Adding Extensions
Edit `devcontainer.json` and add extension IDs to the `extensions` array.

### Modifying Services
The devcontainer uses the existing Docker infrastructure, so:
- Edit `docker-compose.override.dev.yml` for development service changes
- Edit environment variables in `devcontainer.json` for container-specific settings

### Python Dependencies
Dependencies are inherited from the existing `Dockerfile.django-debian` and `requirements.txt`.

## Troubleshooting

### Container Won't Start
- Check Docker is running and has sufficient memory (4GB+ recommended)
- Try rebuilding: "Dev Containers: Rebuild Container"
- Check that no conflicting DefectDojo containers are running

### Debugging Connection Issues
- Verify debugpy server is running on port 5678 (check container logs)
- Ensure `DD_UWSGI_DEBUG=True` is set in devcontainer environment
- Use "Debug DefectDojo (Remote original)" launch configuration

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