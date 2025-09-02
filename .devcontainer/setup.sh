#!/bin/bash

# Post-create setup script for DefectDojo devcontainer

set -e

echo "🚀 Setting up DefectDojo development environment..."

# Ensure we're in the right directory
cd /app

# Install any additional development dependencies if needed
echo "📦 Installing additional development dependencies..."

# Install debugging tools that might be missing
pip install debugpy ipdb || echo "Debug tools already installed"

# Set up Git configuration template (user can customize)
echo "🔧 Setting up Git configuration template..."
git config --global --add safe.directory /app
git config --global init.defaultBranch main

# Check if Django can import properly
echo "🐍 Checking Django setup..."
python -c "import django; print(f'Django version: {django.get_version()}')" || echo "⚠️  Django import check failed"

# Check if we can import the dojo module
python -c "import dojo; print('✅ DefectDojo module imports successfully')" || echo "⚠️  DefectDojo module import check failed"

echo "✅ Setup complete!"
echo ""
echo "🔍 Next steps:"
echo "   1. The development server should automatically start with debugpy enabled"
echo "   2. Access the application at http://localhost:8000"
echo "   3. The nginx proxy is available at http://localhost:8080"  
echo "   4. Use VS Code debugger to attach to port 5678"
echo ""
echo "📚 For more information, see readme-docs/DOCKER.md"
echo "🧪 To run tests: ./run-unittest.sh --test-case <test_case>"
echo "🐛 Debug server should be running on port 5678"