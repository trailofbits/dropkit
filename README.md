# tobcloud

A command-line tool for managing DigitalOcean droplets with automated setup, SSH configuration, and lifecycle management.

## Features

- 🚀 **Quick droplet creation** with cloud-init automation
- 🔑 **Automatic SSH configuration** - just run `ssh tobcloud.<droplet-name>`
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

## Installation

### Install uv (if not already installed)

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or with Homebrew
brew install uv
```

### Install tobcloud

```bash
# Based on what you have configured on your machine, use one or the other, so you do not have to insert any username/password
uv tool install git+https://github.com/trailofbits/tobcloud.git
uv tool install git+ssh://git@github.com/trailofbits/tobcloud.git
```

This installs `tobcloud` as a global command-line tool.

## Upgrading

To upgrade to the latest version:

```bash
uv tool upgrade tobcloud
```

Or reinstall from the latest git version:

```bash
uv tool uninstall tobcloud
uv tool install git+https://github.com/trailofbits/tobcloud.git
```

## Quick Start

### 1. Initialize Configuration

Run the initialization wizard:

```bash
tobcloud init
```

This will validate your DigitalOcean API token, detect SSH keys, register them with DigitalOcean, and let you choose defaults (type `?` for help to see available options).

### 2. Create Your First Droplet

```bash
# Interactive mode - prompts for name, region, size, image (type ? for help)
tobcloud create

# Or specify the name and use defaults
tobcloud create my-first-droplet

# Assign to a specific project (by name or ID)
tobcloud create my-droplet --project "My Project"
```

The tool will create the droplet, wait for it to become active, add SSH configuration automatically, and wait for cloud-init to complete.

### 3. Connect via SSH

```bash
ssh tobcloud.my-first-droplet
```

Your user account is already set up with your SSH keys.

## Available Commands

```
Usage: tobcloud [OPTIONS] COMMAND [ARGS]...

Manage DigitalOcean droplets for ToB engineers

Commands:
  init             Initialize tobcloud configuration.
  create           Create a new DigitalOcean droplet with cloud-init configuration.
  list             List droplets and hibernated snapshots tagged with owner:<username>.
  config-ssh       Configure SSH for an existing droplet.
  info             Show detailed information about a droplet.
  destroy          Destroy a droplet or hibernated snapshot (DESTRUCTIVE).
  resize           Resize a droplet (causes downtime - requires power off).
  on               Power on a droplet.
  off              Power off a droplet (requires confirmation).
  hibernate        Hibernate a droplet (snapshot and destroy to save costs).
  wake             Wake a hibernated droplet (restore from snapshot).
  list-ssh-keys    List SSH keys registered via tobcloud.
  add-ssh-key      Add or import an SSH public key to DigitalOcean.
  delete-ssh-key   Delete an SSH key registered via tobcloud.
  version          Show the version of tobcloud.
```

Use `tobcloud <command> --help` for detailed help on any command.

## Configuration

Configuration files are stored in `~/.config/tobcloud/`:

- **`config.yaml`** - Main configuration (API token, defaults, SSH keys)
- **`cloud-init.yaml`** - Cloud-init template (customizable)

### Default Tags

All droplets are automatically tagged with:

- `owner:<username>` - Your DigitalOcean account username (derived from email)
- `firewall` - For security group identification

### Projects

Organize your droplets into DigitalOcean projects:

- **Set default project** during `tobcloud init` - all new droplets will be assigned to this project
  - The init wizard will suggest your DigitalOcean default project if you have one
  - Just press Enter to accept it, or type a different project name/ID
- **Override per-droplet** using `--project <name>` flag with `tobcloud create`
- Project assignment happens automatically after droplet creation
- **Tab completion** available for project names when using shell completion

You can specify projects by name (e.g., `--project "My Project"`) or by UUID. Type `?` during the init wizard to see all available projects.

### SSH Hostname Convention

All SSH config entries use the prefix `tobcloud.<droplet-name>`:

- Connect with: `ssh tobcloud.my-droplet`

### Shell Completion

Enable tab completion for droplet names in your shell:

**Zsh (recommended):**
```bash
tobcloud --install-completion zsh
```

**Bash:**
```bash
tobcloud --install-completion bash
```

After installation, restart your shell or source your configuration file. You can then use tab completion with commands that accept droplet names:

```bash
tobcloud info <TAB>        # Shows your droplets
tobcloud destroy <TAB>     # Shows your droplets
tobcloud resize <TAB>      # Shows your droplets
tobcloud on <TAB>          # Shows your droplets
tobcloud off <TAB>         # Shows your droplets
tobcloud config-ssh <TAB>  # Shows your droplets
```

The completion dynamically fetches your droplets from DigitalOcean, showing only those tagged with your username.

### Hibernate and Wake (Cost Saving)

DigitalOcean charges for stopped droplets at the full hourly rate. To avoid this, use hibernate/wake:

```bash
# Hibernate: snapshot the droplet and destroy it (stops billing)
tobcloud hibernate my-droplet

# Wake: restore the droplet from the snapshot
tobcloud wake my-droplet

# Delete a hibernated snapshot without restoring
tobcloud destroy my-droplet
```

**How it works:**
1. `hibernate` powers off the droplet, creates a snapshot (`tobcloud-<name>`), then destroys the droplet
2. `wake` creates a new droplet from the snapshot with the same region and size
3. Snapshots are tagged with `owner:<username>` and `size:<size-slug>` for tracking
4. After waking, you're prompted to delete the snapshot (default: yes)

**Note:** Snapshots are billed at $0.06/GB/month, which is typically much cheaper than keeping a droplet running.

### Cloud-Init Customization

Edit `~/.config/tobcloud/cloud-init.yaml` to customize user setup, package installation, firewall rules, and shell configuration. The template uses Jinja2 syntax with variables `{{ username }}` and `{{ ssh_keys }}`.

## Troubleshooting

### "Config not found. Run 'tobcloud init' first"

Initialize the configuration:

```bash
tobcloud init
```

### Cloud-init failed or timeout

Check cloud-init status manually:

```bash
ssh tobcloud.my-droplet 'sudo cloud-init status'
ssh tobcloud.my-droplet 'sudo cat /var/log/cloud-init.log'
```

Use `--verbose` flag to see detailed output:

```bash
tobcloud create my-droplet --verbose
```

### "Droplet not found with tag owner:<username>"

The droplet might belong to someone else. List your droplets:

```bash
tobcloud list
```

## Development

### Setup Development Environment

```bash
git clone https://github.com/trailofbits/tobcloud.git
cd tobcloud
uv sync
```

### Running Tests

```bash
uv run pytest              # Run all tests
uv run pytest -v           # Verbose output
uv run pytest -k "test_*"  # Run specific tests
```

**Test Coverage**: 134 tests covering API client, configuration validation, SSH config management, and helper functions.

### Code Quality

```bash
./lint.sh              # Run all linting (ruff + mypy)
uv run ruff format .   # Format code
uv run ruff check .    # Lint code
uv run mypy tobcloud   # Type check
```

## Technology Stack

- **CLI Framework**: [Typer](https://typer.tiangolo.com/) - Modern CLI framework
- **UI/Display**: [Rich](https://rich.readthedocs.io/) - Terminal formatting
- **API Client**: [requests](https://requests.readthedocs.io/) - HTTP library
- **Configuration**: [Pydantic](https://docs.pydantic.dev/) - Data validation
- **Templating**: [Jinja2](https://jinja.palletsprojects.com/) - Cloud-init templates
- **Package Manager**: [uv](https://github.com/astral-sh/uv) - Fast Python package manager
- **Code Quality**: Ruff (linter/formatter) + Mypy (type checker)

## Appendix: API Token Permissions

### Understanding DigitalOcean API Token Scopes

DigitalOcean uses **custom scopes** to control what actions an API token can perform. When creating your API token, you can choose between:
- **Full Access** (all permissions) - simpler but less secure
- **Custom Scopes** (specific permissions) - more secure, recommended

### Required Scopes for tobcloud

To use all features of tobcloud, your DigitalOcean API token needs these **21 specific scopes**:

#### Account (Read-Only)
- `account:read` - View account details (used to fetch your email for username)

#### Actions (Read-Only)
- `actions:read` - View action status (monitor resize/power operations)

#### Droplets (Full Management)
- `droplet:read` - View droplets (list, get info)
- `droplet:create` - Create droplets
- `droplet:update` - Modify droplets (resize, power on/off)
- `droplet:delete` - Delete droplets

#### Images (Read-Only)
- `image:read` - View images (for interactive prompts)

#### Projects (Read + Update)
- `project:read` - View projects (list, get default project)
- `project:update` - Modify projects (assign droplets to projects)

#### Regions (Read-Only)
- `regions:read` - View data center regions (for interactive prompts)

#### Sizes (Read-Only)
- `sizes:read` - View droplet plan sizes (for interactive prompts)

#### Snapshots (Full Management)
- `snapshot:read` - View snapshots (list, get info for hibernate/wake)
- `snapshot:create` - Create snapshots (for hibernate command)
- `snapshot:delete` - Delete snapshots (for wake command cleanup)

#### SSH Keys (Full Management)
- `ssh_key:read` - View SSH keys (list, check if exists)
- `ssh_key:create` - Upload SSH keys
- `ssh_key:update` - Modify SSH keys (update names)
- `ssh_key:delete` - Delete SSH keys

#### Tags (Create + Read)
- `tag:read` - Filter droplets by tags (for owner-based filtering)
- `tag:create` - Create tags when creating droplets (owner, firewall tags)

#### VPC (Read-Only)
- `vpc:read` - View VPC networks (required by other DigitalOcean operations)

### How to Create Your Token

#### Option 1: Custom Scopes (Recommended - Most Secure)

1. Go to [DigitalOcean API Tokens](https://cloud.digitalocean.com/account/api/tokens)
2. Click **Generate New Token**
3. Give it a descriptive name (e.g., "tobcloud-cli")
4. Select **Custom Scopes**
5. Check all 19 scopes listed above
6. Set expiration period (or no expiration)
7. Click **Generate Token**

#### Option 2: Full Access (Simpler)

1. Go to [DigitalOcean API Tokens](https://cloud.digitalocean.com/account/api/tokens)
2. Click **Generate New Token**
3. Give it a descriptive name (e.g., "tobcloud-cli")
4. Select **Full Access** or **Read and Write**
5. Set expiration period
6. Click **Generate Token**

### Scope Reference by Feature

| Feature | Required Scopes |
|---------|----------------|
| **Initialize config** | `account:read`, `regions:read`, `sizes:read`, `image:read`, `ssh_key:read`, `ssh_key:create`, `project:read` |
| **Create droplets** | `droplet:create`, `project:update`, `actions:read`, `tag:create` |
| **List droplets** | `droplet:read`, `snapshot:read`, `tag:read` |
| **Show droplet info** | `droplet:read` |
| **Destroy droplets** | `droplet:delete`, `snapshot:delete` |
| **Resize droplets** | `droplet:update`, `sizes:read`, `actions:read` |
| **Power on/off** | `droplet:update`, `actions:read` |
| **Hibernate** | `droplet:update`, `droplet:delete`, `snapshot:create`, `actions:read`, `tag:create` |
| **Wake** | `droplet:create`, `snapshot:read`, `snapshot:delete` |
| **Manage SSH keys** | `ssh_key:read`, `ssh_key:create`, `ssh_key:update`, `ssh_key:delete` |

For more information, see the [DigitalOcean API Token Scopes documentation](https://docs.digitalocean.com/reference/api/scopes/).

## License

[Add your license here]

## Support

- **Issues**: [GitHub Issues](https://github.com/trailofbits/tobcloud/issues)
- **Documentation**: See [CLAUDE.md](CLAUDE.md) for detailed development documentation

## Credits

Developed by Trail of Bits for internal infrastructure management.
