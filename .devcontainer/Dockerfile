FROM mcr.microsoft.com/devcontainers/base:debian

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Switch to non-root user
USER vscode
WORKDIR /home/vscode

# Add ~/.local/bin to PATH for Claude Code
ENV PATH="/home/vscode/.local/bin:$PATH"

# Install Claude Code (installs to ~/.local/bin/claude)
RUN curl -fsSL https://claude.ai/install.sh | bash && \
    claude plugin marketplace add trailofbits/skills && \
    claude plugin marketplace add anthropics/skills && \
    claude plugin marketplace add obra/superpowers

# Set environment variables
ENV DEVCONTAINER=true
ENV EDITOR=nano

# Configure zsh and add aliases
RUN echo 'export HISTFILE="$HOME/.zsh_history_data/.zsh_history"' >> ~/.zshrc && \
    echo 'alias yolo="claude --dangerously-skip-permissions"' >> ~/.zshrc

WORKDIR /workspace
