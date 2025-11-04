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
  list             List droplets tagged with owner:<username>.
  config-ssh       Configure SSH for an existing droplet.
  info             Show detailed information about a droplet.
  destroy          Destroy a droplet (DESTRUCTIVE - requires confirmation).
  resize           Resize a droplet (causes downtime - requires power off).
  on               Power on a droplet.
  off              Power off a droplet (requires confirmation).
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

**Test Coverage**: 81 tests covering API client, configuration validation, and SSH config management.

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

## License

[Add your license here]

## Support

- **Issues**: [GitHub Issues](https://github.com/trailofbits/tobcloud/issues)
- **Documentation**: See [CLAUDE.md](CLAUDE.md) for detailed development documentation

## Credits

Developed by Trail of Bits for internal infrastructure management.
