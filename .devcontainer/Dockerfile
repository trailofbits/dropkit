FROM mcr.microsoft.com/devcontainers/base:debian

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Create Claude Code managed settings with allowed plugin marketplaces
RUN mkdir -p /etc/claude-code && \
    echo '{"extraKnownMarketplaces": [{"source": "github", "repo": "trailofbits/skills"}, {"source": "github", "repo": "anthropics/skills"}, {"source": "github", "repo": "obra/superpowers"}]}' > /etc/claude-code/managed-settings.json

# Switch to non-root user
USER vscode
WORKDIR /home/vscode

# Add ~/.local/bin to PATH for Claude Code
ENV PATH="/home/vscode/.local/bin:$PATH"

# Install Claude Code (installs to ~/.local/bin/claude)
RUN curl -fsSL https://claude.ai/install.sh | bash

# Set environment variables
ENV DEVCONTAINER=true
ENV EDITOR=nano

# Configure zsh and add aliases
RUN echo 'export HISTFILE="$HOME/.zsh_history_data/.zsh_history"' >> ~/.zshrc && \
    echo 'alias yolo="claude --dangerously-skip-permissions"' >> ~/.zshrc

WORKDIR /workspace
