# dropkit

A command-line tool for managing DigitalOcean droplets with automated setup, SSH configuration, and lifecycle management.

## Features

- 🚀 **Quick droplet creation** with cloud-init automation
- 🔑 **Automatic SSH configuration** - just run `ssh dropkit.<droplet-name>`
- 🔐 **Tailscale VPN** - secure access via Tailscale (enabled by default)
- 👤 **User management** - automatically creates your user account on droplets
- 🏷️ **Smart tagging** - organizes droplets by owner for easy filtering
- 🔒 **Security-first** - SSH key validation, confirmation prompts for destructive operations
- 📊 **Rich CLI** - beautiful tables, progress indicators, and helpful error messages
- 🔄 **Complete lifecycle** - create, list, resize, destroy droplets with ease
- 💤 **Hibernate/Wake** - snapshot and destroy to save costs, restore later with one command

## Prerequisites

- **Python 3.11+**
- **DigitalOcean account** with an API token ([create one here](https://cloud.digitalocean.com/account/api/tokens))
- **SSH key pair** (usually `~/.ssh/id_ed25519.pub` or `~/.ssh/id_rsa.pub`)
- **uv** package manager ([install instructions](https://github.com/astral-sh/uv))
- **Tailscale** (optional but recommended) - install from [tailscale.com/download](https://tailscale.com/download)

## Installation

```bash
# HTTPS or SSH depending on your GitHub setup
uv tool install git+https://github.com/trailofbits/dropkit.git
uv tool install git+ssh://git@github.com/trailofbits/dropkit.git

# Upgrade
uv tool upgrade dropkit
```

## Quick Start

### 1. Initialize Configuration

Run the initialization wizard:

```bash
dropkit init
```

This will validate your DigitalOcean API token, detect SSH keys, register them with DigitalOcean, and let you choose defaults (type `?` for help to see available options).

### 2. Create Your First Droplet

```bash
# Interactive mode - prompts for name, region, size, image (type ? for help)
dropkit create

# Or specify the name and use defaults
dropkit create my-first-droplet

# Assign to a specific project (by name or ID)
dropkit create my-droplet --project "My Project"

# Create without Tailscale VPN
dropkit create my-droplet --no-tailscale
```

The tool will:
1. Create the droplet and wait for it to become active
2. Add SSH configuration automatically
3. Wait for cloud-init to complete
4. **Tailscale setup** (enabled by default):
   - Display an auth URL for you to authenticate in your browser
   - Update SSH config with your Tailscale IP
   - Lock down the firewall to only allow Tailscale traffic

### 3. Connect via SSH

```bash
ssh dropkit.my-first-droplet
```

Your user account is already set up with your SSH keys.

## Available Commands

```
Usage: dropkit [OPTIONS] COMMAND [ARGS]...

Manage DigitalOcean droplets

Commands:
  init             Initialize dropkit configuration.
  create           Create a new DigitalOcean droplet with cloud-init configuration.
  list             List droplets and hibernated snapshots tagged with owner:<username>.
  config-ssh       Configure SSH for an existing droplet.
  info             Show detailed information about a droplet.
  rename           Rename a droplet (requires confirmation).
  destroy          Destroy a droplet or hibernated snapshot (DESTRUCTIVE).
  resize           Resize a droplet (causes downtime - requires power off).
  on               Power on a droplet.
  off              Power off a droplet (requires confirmation).
  hibernate        Hibernate a droplet (snapshot and destroy to save costs).
  wake             Wake a hibernated droplet (restore from snapshot).
  enable-tailscale Enable Tailscale VPN on an existing droplet.
  list-ssh-keys    List SSH keys registered via dropkit.
  add-ssh-key      Add or import an SSH public key to DigitalOcean.
  delete-ssh-key   Delete an SSH key registered via dropkit.
  version          Show the version of dropkit.
```

Use `dropkit <command> --help` for detailed help on any command.

## Configuration

Configuration files are stored in `~/.config/dropkit/`:

- **`config.yaml`** - Main configuration (API token, defaults, SSH keys)
- **`cloud-init.yaml`** - Cloud-init template (customizable)

### Default Tags

All droplets are automatically tagged with:

- `owner:<username>` - Your DigitalOcean account username (derived from email)
- `firewall` - For security group identification

### Projects

- **Set default project** during `dropkit init` (type `?` to see available projects)
- **Override per-droplet** using `--project <name>` with `dropkit create`
- Specify by name or UUID; tab completion available

### SSH Hostname Convention

All SSH config entries use the prefix `dropkit.<droplet-name>`:

- Connect with: `ssh dropkit.my-droplet`

### Shell Completion

Enable tab completion for droplet names in your shell:

**Zsh (recommended):**
```bash
dropkit --install-completion zsh
```

**Bash:**
```bash
dropkit --install-completion bash
```

After installation, restart your shell. Tab completion dynamically fetches your droplets from DigitalOcean:

```bash
dropkit info <TAB>             # Shows your droplets
dropkit destroy <TAB>          # Shows your droplets
dropkit resize <TAB>           # Shows your droplets
dropkit on <TAB>               # Shows your droplets
dropkit off <TAB>              # Shows your droplets
```

### Hibernate and Wake (Cost Saving)

DigitalOcean charges for stopped droplets at the full hourly rate. To avoid this, use hibernate/wake:

```bash
# Hibernate: snapshot the droplet and destroy it (stops billing)
dropkit hibernate my-droplet

# Wake: restore the droplet from the snapshot
dropkit wake my-droplet

# Delete a hibernated snapshot without restoring
dropkit destroy my-droplet
```

**How it works:**
1. `hibernate` powers off the droplet, creates a snapshot (`dropkit-<name>`), then destroys the droplet
2. `wake` creates a new droplet from the snapshot with the same region and size
3. Snapshots are tagged with `owner:<username>` and `size:<size-slug>` for tracking
4. After waking, you're prompted to delete the snapshot (default: yes)

**Note:** Snapshots are billed at $0.06/GB/month, which is typically much cheaper than keeping a droplet running.

### Cloud-Init Customization

Edit `~/.config/dropkit/cloud-init.yaml` to customize user setup, package installation, firewall rules, and shell configuration. The template uses Jinja2 syntax with variables `{{ username }}` and `{{ ssh_keys }}`.

## Troubleshooting

### "Config not found. Run 'dropkit init' first"

Initialize the configuration:

```bash
dropkit init
```

### Cloud-init failed or timeout

Check cloud-init status manually:

```bash
ssh dropkit.my-droplet 'sudo cloud-init status'
ssh dropkit.my-droplet 'sudo cat /var/log/cloud-init.log'
```

Use `--verbose` flag to see detailed output:

```bash
dropkit create my-droplet --verbose
```

### "Droplet not found with tag owner:<username>"

The droplet might belong to someone else. List your droplets:

```bash
dropkit list
```

## Technology Stack

- **CLI Framework**: [Typer](https://typer.tiangolo.com/) - Modern CLI framework
- **UI/Display**: [Rich](https://rich.readthedocs.io/) - Terminal formatting
- **API Client**: [requests](https://requests.readthedocs.io/) - HTTP library
- **Configuration**: [Pydantic](https://docs.pydantic.dev/) - Data validation
- **Templating**: [Jinja2](https://jinja.palletsprojects.com/) - Cloud-init templates
- **Package Manager**: [uv](https://github.com/astral-sh/uv) - Fast Python package manager
- **Code Quality**: Ruff (linter/formatter) + ty (type checker)

## Appendix: API Token Permissions

### Creating Your Token

1. Go to [DigitalOcean API Tokens](https://cloud.digitalocean.com/account/api/tokens)
2. Click **Generate New Token** with name "dropkit-cli"
3. Select **Custom Scopes** (recommended) or **Full Access** (simpler)
4. For custom scopes, enable the 23 scopes listed below

### Required Scopes (23 total)

`account:read`, `actions:read`, `droplet:create`, `droplet:read`, `droplet:update`, `droplet:delete`, `image:create`, `image:read`, `image:update`, `image:delete`, `project:read`, `project:update`, `regions:read`, `sizes:read`, `snapshot:read`, `snapshot:delete`, `ssh_key:create`, `ssh_key:read`, `ssh_key:update`, `ssh_key:delete`, `tag:read`, `tag:create`, `vpc:read`

### Scope Reference by Feature

| Feature | Required Scopes |
|---------|----------------|
| **Initialize config** | `account:read`, `regions:read`, `sizes:read`, `image:read`, `ssh_key:read`, `ssh_key:create`, `project:read` |
| **Create droplets** | `droplet:create`, `project:update`, `actions:read`, `tag:create` |
| **List droplets** | `droplet:read`, `snapshot:read`, `tag:read` |
| **Show droplet info** | `droplet:read` |
| **Destroy droplets** | `droplet:delete`, `snapshot:delete` |
| **Rename droplets** | `droplet:update` |
| **Resize droplets** | `droplet:update`, `sizes:read`, `actions:read` |
| **Power on/off** | `droplet:update`, `actions:read` |
| **Hibernate** | `droplet:update`, `droplet:delete`, `snapshot:create`, `actions:read`, `tag:create` |
| **Wake** | `droplet:create`, `snapshot:read`, `snapshot:delete` |
| **Manage SSH keys** | `ssh_key:read`, `ssh_key:create`, `ssh_key:update`, `ssh_key:delete` |

For more information, see the [DigitalOcean API Token Scopes documentation](https://docs.digitalocean.com/reference/api/scopes/).
