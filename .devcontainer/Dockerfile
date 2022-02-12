FROM mcr.microsoft.com/vscode/devcontainers/base:debian

# Install additional OS packages
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
  apt-get -y install --no-install-recommends \
  python3-pip \
  npm

# Install Python packages
RUN pip3 --disable-pip-version-check --no-cache-dir install \
  poetry \
  detect-secrets \
  pre-commit

# Install global node packages
RUN npm install -g \
  markdownlint-cli