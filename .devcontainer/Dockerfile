# Development container based on DefectDojo's Django setup
FROM python:3.11.11-slim-bookworm

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and tools for development
RUN apt-get update && apt-get install -y \
    # Build tools
    gcc \
    build-essential \
    git \
    curl \
    wget \
    # Database and networking tools
    dnsutils \
    libpq-dev \
    postgresql-client \
    # Security and XML tools
    xmlsec1 \
    # Required for pycurl
    libcurl4-openssl-dev \
    # Image processing libraries (required by Pillow)
    libopenjp2-7 \
    libjpeg62 \
    libtiff6 \
    # Additional development tools
    vim \
    nano \
    htop \
    tree \
    jq \
    # UUID tools
    uuid-runtime \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create vscode user with appropriate permissions
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Set working directory
WORKDIR /workspaces/django-DefectDojo

# Copy requirements and install Python dependencies
COPY requirements.txt requirements-lint.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install -r requirements-lint.txt \
    && pip install debugpy ipdb

# Set the default user
USER $USERNAME

# Set environment variables for development
ENV PYTHONPATH=/workspaces/django-DefectDojo
ENV DJANGO_SETTINGS_MODULE=dojo.settings.settings