#!/bin/bash

# DefectDojo macOS Debug Runner
# This script runs DefectDojo Django application natively on macOS for debugging
# while keeping other services (PostgreSQL, Redis, etc.) in Docker containers.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check Python 3
    if ! command_exists python3; then
        print_error "Python 3 is required but not installed."
        print_info "Install Python 3 using Homebrew: brew install python3"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    print_success "Python 3 found: $PYTHON_VERSION"
    
    # Check pip
    if ! command_exists pip3; then
        print_error "pip3 is required but not installed."
        exit 1
    fi
    
    print_success "pip3 found"
    
    # Check Docker
    if ! command_exists docker; then
        print_error "Docker is required but not installed."
        print_info "Install Docker Desktop for macOS from https://www.docker.com/products/docker-desktop"
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is installed but not running."
        print_info "Start Docker Desktop and try again."
        exit 1
    fi
    
    print_success "Docker is running"
    
    # Check docker-compose
    if ! command_exists docker && ! docker compose version >/dev/null 2>&1; then
        print_error "Docker Compose is required but not available."
        exit 1
    fi
    
    print_success "Docker Compose found"
}

# Function to install Python dependencies
install_dependencies() {
    print_info "Installing Python dependencies..."
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_info "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    pip install -r requirements.txt
    
    # Install debugpy if not already installed
    pip install debugpy==1.8.9
    
    print_success "Python dependencies installed"
}

# Function to start supporting services in Docker
start_docker_services() {
    print_info "Starting supporting services in Docker..."
    
    # Set environment to dev first to get docker-compose.override.yml
    ./docker/setEnv.sh dev
    
    # Start only the supporting services, not uwsgi
    docker compose up -d postgres redis mailhog
    
    # Wait for PostgreSQL to be ready
    print_info "Waiting for PostgreSQL to be ready..."
    timeout=30
    while [ $timeout -gt 0 ]; do
        if docker compose exec postgres pg_isready -U defectdojo >/dev/null 2>&1; then
            break
        fi
        sleep 1
        timeout=$((timeout - 1))
    done
    
    if [ $timeout -eq 0 ]; then
        print_error "PostgreSQL failed to start within 30 seconds"
        exit 1
    fi
    
    print_success "Supporting services started"
}

# Function to set environment variables for macOS
set_environment_variables() {
    print_info "Setting environment variables..."
    
    # Database configuration (connecting to dockerized PostgreSQL)
    export DD_DATABASE_HOST="localhost"
    export DD_DATABASE_PORT="5432"
    export DD_DATABASE_NAME="defectdojo"
    export DD_DATABASE_USER="defectdojo"
    export DD_DATABASE_PASSWORD="defectdojo"
    export DD_DATABASE_URL="postgresql://defectdojo:defectdojo@localhost:5432/defectdojo"
    
    # Redis configuration (connecting to dockerized Redis)
    export DD_CELERY_BROKER_URL="redis://localhost:6379/0"
    
    # Debug configuration
    export DD_DEBUG="True"
    export DD_UWSGI_DEBUG="True"
    export PYTHONWARNINGS="error"
    
    # Admin user configuration
    export DD_ADMIN_USER="${DD_ADMIN_USER:-admin}"
    export DD_ADMIN_PASSWORD="${DD_ADMIN_PASSWORD:-admin}"
    
    # Email configuration (connecting to dockerized mailhog)
    export DD_EMAIL_URL="smtp://localhost:1025"
    
    # Security keys (development only)
    export DD_SECRET_KEY="${DD_SECRET_KEY:-hhZCp@D28z!n@NED*yB!ROMt+WzsY*iq}"
    export DD_CREDENTIAL_AES_256_KEY="${DD_CREDENTIAL_AES_256_KEY:-&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw}"
    
    # Site configuration
    export DD_SITE_URL="http://localhost:8000"
    export DD_ALLOWED_HOSTS="localhost,127.0.0.1"
    
    # Django settings
    export DJANGO_SETTINGS_MODULE="dojo.settings.settings"
    
    print_success "Environment variables set"
}

# Function to run database migrations
run_migrations() {
    print_info "Running database migrations..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Run migrations
    python manage.py migrate
    
    print_success "Database migrations completed"
}

# Function to create superuser if needed
create_superuser() {
    print_info "Checking for superuser..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Check if admin user exists, create if not
    python manage.py shell -c "
from django.contrib.auth.models import User
import os
username = os.environ.get('DD_ADMIN_USER', 'admin')
password = os.environ.get('DD_ADMIN_PASSWORD', 'admin')
if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username, 'admin@example.com', password)
    print(f'Superuser {username} created')
else:
    print(f'Superuser {username} already exists')
"
    
    print_success "Superuser check completed"
}

# Function to start Django with debugging
start_django_debug() {
    print_info "Starting Django with debugging enabled..."
    print_info "Debugger will listen on port 5678"
    print_info "VS Code can connect to localhost:5678"
    print_warning "The application will start on http://localhost:8000"
    print_warning "Note: This is different from the Docker setup which uses port 8080"
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Start Django development server with debugpy
    python -c "
import debugpy
import os
import sys
from django.core.management import execute_from_command_line

# Configure debugpy
debugpy.listen(('0.0.0.0', 5678))
print('🐛 Debugger listening on port 5678')
print('🐛 Connect VS Code debugger to localhost:5678')
print('🐛 Application will start after debugger connects or press Ctrl+C to start without debugger')

# Optional: Wait for debugger to connect (comment out for auto-start)
# debugpy.wait_for_client()

# Start Django development server
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
execute_from_command_line(['manage.py', 'runserver', '0.0.0.0:8000'])
"
}

# Function to display usage information
show_usage() {
    echo "DefectDojo macOS Debug Runner"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --skip-deps         Skip dependency installation"
    echo "  --skip-docker       Skip starting Docker services (assumes they're already running)"
    echo "  --skip-migrations   Skip database migrations"
    echo "  --port PORT         Django server port (default: 8000)"
    echo "  --debug-port PORT   Debugger port (default: 5678)"
    echo ""
    echo "This script:"
    echo "1. Checks prerequisites (Python 3, Docker, etc.)"
    echo "2. Installs Python dependencies in a virtual environment"
    echo "3. Starts supporting services (PostgreSQL, Redis, MailHog) in Docker"
    echo "4. Sets up environment variables to connect to Docker services"
    echo "5. Runs database migrations"
    echo "6. Starts Django development server with debugpy enabled"
    echo ""
    echo "The Django application will run natively on macOS while connecting to"
    echo "dockerized services for improved debugging performance."
    echo ""
    echo "VS Code Setup:"
    echo "Add this configuration to your .vscode/launch.json:"
    echo '{'
    echo '    "name": "Debug DefectDojo (Native macOS)",'
    echo '    "type": "python",'
    echo '    "request": "attach",'
    echo '    "connect": {'
    echo '        "host": "localhost",'
    echo '        "port": 5678'
    echo '    },'
    echo '    "pathMappings": [{'
    echo '        "localRoot": "${workspaceFolder}",'
    echo '        "remoteRoot": "."'
    echo '    }]'
    echo '}'
}

# Function to cleanup on exit
cleanup() {
    print_info "Cleaning up..."
    # Deactivate virtual environment if active
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        deactivate
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Parse command line arguments
SKIP_DEPS=false
SKIP_DOCKER=false
SKIP_MIGRATIONS=false
DJANGO_PORT=8000
DEBUG_PORT=5678

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_usage
            exit 0
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        --skip-migrations)
            SKIP_MIGRATIONS=true
            shift
            ;;
        --port)
            DJANGO_PORT="$2"
            shift 2
            ;;
        --debug-port)
            DEBUG_PORT="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo "🚀 DefectDojo macOS Debug Runner"
    echo "=================================="
    echo ""
    
    # Check if we're in the right directory
    if [ ! -f "manage.py" ]; then
        print_error "This script must be run from the DefectDojo root directory"
        exit 1
    fi
    
    check_prerequisites
    
    if [ "$SKIP_DEPS" = false ]; then
        install_dependencies
    else
        print_info "Skipping dependency installation"
    fi
    
    if [ "$SKIP_DOCKER" = false ]; then
        start_docker_services
    else
        print_info "Skipping Docker service startup"
    fi
    
    set_environment_variables
    
    if [ "$SKIP_MIGRATIONS" = false ]; then
        run_migrations
        create_superuser
    else
        print_info "Skipping database migrations"
    fi
    
    echo ""
    print_success "Setup completed!"
    echo ""
    print_info "🔗 Application will be available at: http://localhost:$DJANGO_PORT"
    print_info "🐛 Debugger will listen on: localhost:$DEBUG_PORT"
    print_info "📧 MailHog (email testing) available at: http://localhost:8025"
    print_info "🗄️  PostgreSQL accessible at: localhost:5432"
    echo ""
    
    start_django_debug
}

# Run main function
main "$@"