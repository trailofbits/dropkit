# dropkit

CLI tool for managing DigitalOcean droplets for Trail of Bits engineers.
Pre-configured cloud-init, Tailscale VPN (enabled by default), and SSH config management.

## Critical Rules ⚠️

- **Never use `pip`** — always use `uv` for all Python operations
- **Always run `prek run`** before committing (or `prek install` to auto-run on commit)
- **Keep README.md in sync** when adding commands or features

## Quick Commands

```bash
uv sync                      # Install dependencies
prek install                 # Set up pre-commit hooks (one-time)
prek run                     # Run all checks (ruff, ty, shellcheck, etc.)
uv run pytest                # Run tests
uv run dropkit --help        # CLI help
```

## Project Structure

```
dropkit/
├── dropkit/           # CLI source (Typer entry point: main.py)
│   └── templates/     # Jinja2 cloud-init templates
└── tests/             # pytest tests
```

## Technology Stack

- **Python 3.11+** with `uv` (NOT pip)
- **CLI**: Typer + Rich
- **API**: Direct REST calls (requests library, no SDK)
- **Config**: YAML + Pydantic 2.x validation
- **Templating**: Jinja2 for cloud-init
- **Code Quality**: Ruff (linter + formatter), ty (types)

## Key Conventions

### Username
- **Derived from DigitalOcean account email**, not configured
- Fetched via `/v2/account`, sanitized for Linux compatibility
- `john.doe@example.com` → `john_doe`

### SSH Hostname
- All SSH entries use `dropkit.<droplet-name>` format
- Centralized in `get_ssh_hostname()` helper

### Tags
- Default tags: `owner:<username>` and `firewall`
- Additional tags **extend** defaults (never replace)
- Used for filtering, billing, and security

### SSH Keys
- Only public keys (*.pub) accepted
- Strict validation rejects private keys
- Auto-detects id_ed25519.pub, id_rsa.pub, id_ecdsa.pub

### Tailscale VPN
- **Enabled by default** for new droplets
- Locks down UFW to only allow tailscale0 interface
- Disable with `--no-tailscale` flag

## Architecture Decisions

1. **Username from email** — Not stored in config; fetched from DO API on demand.
   Ensures consistency across machines.

2. **SSH key validation** — Prevents accidental private key upload.
   Validates format (ssh-rsa, ssh-ed25519, ecdsa-sha2-*, etc.).

3. **Tags extend defaults** — `--tags` adds to defaults, never replaces.
   Ensures owner tag always present.

4. **Direct REST API** — No python-digitalocean library.
   Simpler, fewer dependencies, full control.

5. **Tailscale by default** — Secure VPN access without public SSH.
   Local Tailscale required; keeps public IP if local Tailscale not running.

6. **Pydantic validation** — Runtime type safety for config files.
   Clear errors for invalid configurations.

7. **SSH config backups** — Created at `~/.ssh/config.bak` before modifications.
   Each backup overwrites previous.

## Gotchas & Troubleshooting

### Cloud-init JSON parsing (CRITICAL)
`cloud-init status --format=json` may return **non-zero exit code but valid JSON**.
**Always parse JSON regardless of subprocess return code.**

```python
# CORRECT: Parse JSON even on error
result = subprocess.run([...], capture_output=True)
data = json.loads(result.stdout)  # Don't check returncode first

# WRONG: Checking returncode before parsing
if result.returncode == 0:  # May skip valid JSON with error status
    data = json.loads(result.stdout)
```

Status values: `"done"` (success), `"error"` (failed), `"running"` (in progress).

### Disk resize is permanent
Cannot be undone. Use `--no-disk` to resize only CPU/memory.

### SSH config backups overwrite
Only keeps one backup at `~/.ssh/config.bak`.

## Development

### Package Management
```bash
uv add <package>             # Add dependency
uv add --dev <package>       # Add dev dependency
uv sync                      # Install all
uv run <command>             # Run in venv
```

### Linting
```bash
prek run                     # Run all checks (required before commit)
prek run --all-files         # Check all files, not just staged
uv run ruff check --fix .    # Lint + autofix only
uv run ty check dropkit/     # Type check only
```

**Ruff config**: Python 3.11+, 100-char lines, modern syntax (`str | None`, `list[str]`).

### Testing
```bash
uv run pytest                              # All tests
uv run pytest tests/test_api.py            # Specific file
uv run pytest -k "validate_ssh"            # Pattern match
uv run pytest -v                           # Verbose
```

**Coverage**: Minimum 29% enforced via `--cov-fail-under=29` in pyproject.toml.

## Pydantic Models

- **`DropkitConfig`** — Root config with `extra='forbid'`
- **`DigitalOceanConfig`** — API token validation
- **`DefaultsConfig`** — Region, size, image slugs
- **`CloudInitConfig`** — Template path, SSH keys (min 1)
- **`SSHConfig`** — SSH config path, identity file
- **`TailscaleConfig`** — VPN settings (enabled, lock_down_firewall, auth_timeout)

Config files: `~/.config/dropkit/config.yaml`, `~/.config/dropkit/cloud-init.yaml`

## Shell Completion

```bash
dropkit --install-completion zsh  # Enable tab completion
```

Provides dynamic completion for droplet names (filtered by owner tag).
