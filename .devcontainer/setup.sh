#!/bin/bash

# Post-create setup script for DefectDojo devcontainer

set -e

echo "🚀 Setting up DefectDojo development environment..."

# Ensure we're in the right directory
cd /workspaces/django-DefectDojo

# Install any additional development dependencies
echo "📦 Installing additional development dependencies..."
pip install --upgrade pip

# Check if requirements files exist and install them
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi

if [ -f "requirements-lint.txt" ]; then
    pip install -r requirements-lint.txt
fi

# Install additional debugging and development tools
pip install debugpy ipdb jupyter

# Set up Git configuration template (user can customize)
echo "🔧 Setting up Git configuration template..."
git config --global --add safe.directory /workspaces/django-DefectDojo
git config --global init.defaultBranch main

# Create necessary directories for development
echo "📁 Creating necessary directories..."
mkdir -p logs
mkdir -p media
mkdir -p static

# Set proper permissions
chmod +x docker/setEnv.sh 2>/dev/null || true
chmod +x run-unittest.sh 2>/dev/null || true
chmod +x run-integration-tests.sh 2>/dev/null || true

# Check if Django can import properly
echo "🐍 Checking Django setup..."
python -c "import django; print(f'Django version: {django.get_version()}')" || echo "⚠️  Django import check failed"

# Check if we can import the dojo module
python -c "import sys; sys.path.append('.'); import dojo; print('✅ DefectDojo module imports successfully')" || echo "⚠️  DefectDojo module import check failed"

echo "✅ Setup complete!"
echo ""
echo "🔍 Next steps:"
echo "   1. Start the database and Redis services using Docker Compose:"
echo "      docker compose up postgres redis -d"
echo "   2. Run database migrations:"
echo "      python manage.py migrate"
echo "   3. Create a superuser:"
echo "      python manage.py createsuperuser"
echo "   4. Start the development server:"
echo "      python manage.py runserver 0.0.0.0:8000"
echo ""
echo "📚 For more information, see readme-docs/DOCKER.md"
echo "🧪 To run tests: ./run-unittest.sh --test-case <test_case>"
echo "🐛 For debugging, use the VS Code debugger or attach to debugpy"