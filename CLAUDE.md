# tobcloud

A CLI tool for managing DigitalOcean droplets for Trail of Bits engineers.

## Project Overview

`tobcloud` simplifies creating and managing DigitalOcean droplets with:
- Pre-configured cloud-init templates (user creation, SSH keys, firewall, zsh setup)
- **Tailscale VPN integration** for secure remote access (enabled by default)
- Automatic tagging for security and billing
- SSH config management
- Easy droplet lifecycle management (create, list, destroy, resize, hibernate/wake)

## Technology Stack

- **Python 3.11+**
- **Package Manager**: `uv` (NOT pip)
- **CLI Framework**: Typer with Rich for beautiful terminal output
- **API**: Raw REST API calls to DigitalOcean (requests library)
- **Config**: YAML configuration files in `~/.config/tobcloud/` with **Pydantic validation**
- **Templating**: Jinja2 for cloud-init templates
- **Validation**: Pydantic 2.x for type safety and data validation
- **Code Quality**: Ruff (linter + formatter) and Mypy (type checker)

## Project Structure

```
tobcloud/
├── pyproject.toml              # Project dependencies and metadata
├── CLAUDE.md                   # This file
├── README.md                   # User documentation
├── lint.sh                     # Linting script (ruff + mypy)
├── tobcloud/
│   ├── __init__.py
│   ├── main.py                 # Typer CLI entry point
│   ├── config.py               # Config management with SSH key validation
│   ├── api.py                  # DigitalOcean REST API wrapper
│   ├── cloudinit.py            # Cloud-init template rendering
│   ├── ssh_config.py           # SSH config manipulation
│   └── templates/
│       └── default-cloud-init.yaml  # Default cloud-init template
└── tests/
    ├── test_api.py             # API client tests (email sanitization, validation)
    ├── test_config.py          # Config and validation tests
    ├── test_main_helpers.py    # Helper function tests (snapshot names, tags)
    └── test_ssh_config.py      # SSH config manipulation tests
```

## Development Workflow

### Package Management with uv

**Always use `uv` for all Python operations:**

```bash
# Add dependencies
uv add <package>

# Add dev dependencies
uv add --dev <package>

# Install project in development mode
uv sync

# Run commands
uv run tobcloud <command>

# Run Python scripts
uv run python <script>
```

### Linting and Type Checking

**Code quality tools:**

```bash
# Run all linting (ruff format + ruff check + mypy)
./lint.sh

# Run ruff formatter
uv run ruff format .

# Run ruff linter
uv run ruff check .

# Auto-fix ruff issues
uv run ruff check --fix .

# Run mypy type checker
uv run mypy tobcloud
```

**Ruff Configuration:**
- Target Python 3.11+
- Modern syntax enforced: `| None` instead of `Optional`, `list` instead of `List`
- Selected rules: pycodestyle, pyflakes, isort, pyupgrade, bugbear, simplify, comprehensions
- Line length: 100 characters

**Mypy Configuration:**
- Strict type checking enabled for production code
- Tests have relaxed type checking for easier testing

### Testing

**Running tests:**

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_ssh_config.py

# Run with verbose output
uv run pytest -v

# Run specific test
uv run pytest tests/test_ssh_config.py::TestAddSSHHost::test_empty_file

# Run tests matching a pattern
uv run pytest -k "validate_ssh_public_key"
```

**Test Coverage (243 tests total):**
- `tests/test_api.py` - 15 tests for DigitalOcean API client
  - Email sanitization for username generation
  - Special character handling, number prefixes, empty email fallback
  - Positive integer validation for IDs
  - Droplet URN generation
- `tests/test_ssh_config.py` - 37 comprehensive tests for SSH config management
  - Tests for `add_ssh_host`: edge cases, similar names, updates, backup creation
  - Tests for `remove_ssh_host`: removal, edge cases, backup creation
  - Tests for `get_ssh_host_ip`: valid/missing hosts, Tailscale IPs, multiple hosts
  - All tests verify backup functionality and permission preservation
- `tests/test_config.py` - 48 comprehensive tests for Pydantic configuration validation
  - Tests for each Pydantic model: DigitalOceanConfig, DefaultsConfig, CloudInitConfig, SSHConfig, TobcloudConfig
  - Tests for Config manager: load/save, validation errors, SSH key detection
  - **SSH key validation tests**: Valid keys (RSA, ED25519, ECDSA), private key rejection, empty files, invalid content
  - **Username property tests**: Configured username, fallback to system username, before config loaded
  - Tests empty fields, missing fields, extra fields, type validation, nested validation
- `tests/test_main_helpers.py` - 33 tests for main module helper functions
  - Tests for `get_snapshot_name()`: simple names, hyphens, numbers
  - Tests for `get_droplet_name_from_snapshot()`: valid/invalid snapshot names
  - Tests for `get_ssh_hostname()`, `get_user_tag()`, `build_droplet_tags()`
  - Tests for `is_droplet_tailscale_locked()`: Tailscale vs public IPs
  - Tests for `add_temporary_ssh_rule()`: success, failure, timeout
  - Tests for `prepare_for_hibernate()`: Tailscale lockdown detection and handling

### Manual Testing Commands

```bash
# Initialize configuration
uv run tobcloud init
uv run tobcloud init --force  # Overwrite existing config

# Create a droplet
uv run tobcloud create                    # Interactive mode - prompts for all values
uv run tobcloud create test-droplet       # Specify name, uses defaults for rest
uv run tobcloud create test-droplet --verbose  # Show debug output including cloud-init template
uv run tobcloud create test-droplet --region sfo3 --size s-1vcpu-1gb
uv run tobcloud create test-droplet --tags "production,webserver"  # Extends default tags

# List droplets
uv run tobcloud list

# Show detailed droplet information
uv run tobcloud info test-droplet

# Configure SSH for existing droplet
uv run tobcloud config-ssh test-droplet
uv run tobcloud config-ssh test-droplet --user ubuntu --identity-file ~/.ssh/id_rsa

# Destroy a droplet (requires double confirmation)
uv run tobcloud destroy test-droplet

# Resize a droplet (interactive or with flags)
uv run tobcloud resize test-droplet                    # Interactive - prompts for size
uv run tobcloud resize test-droplet --size s-4vcpu-8gb  # With size specified
uv run tobcloud resize test-droplet --size s-4vcpu-8gb --no-disk  # Without disk resize

# Power on/off droplets
uv run tobcloud on test-droplet   # Power on a droplet
uv run tobcloud off test-droplet  # Power off a droplet (requires confirmation)

# Hibernate/wake droplets (cost-saving)
uv run tobcloud hibernate test-droplet              # Snapshot and destroy (stops billing)
uv run tobcloud hibernate --continue test-droplet   # Resume timed-out hibernate
uv run tobcloud wake test-droplet                   # Restore from snapshot
uv run tobcloud destroy test-droplet                # Also works for hibernated snapshots

# SSH key management
uv run tobcloud list-ssh-keys                    # List registered SSH keys
uv run tobcloud add-ssh-key ~/.ssh/id_ed25519.pub  # Add/import SSH key
uv run tobcloud delete-ssh-key <key-id>          # Delete SSH key by ID

# Show help
uv run tobcloud --help
uv run tobcloud create --help
uv run tobcloud info --help
uv run tobcloud destroy --help
uv run tobcloud resize --help
```

## Configuration

User configuration is stored in `~/.config/tobcloud/`:
- `config.yaml` - Main configuration (API token, defaults, SSH keys)
- `cloud-init.yaml` - Cloud-init template (user-editable)

### Username from DigitalOcean Account

The username for droplets is automatically derived from your DigitalOcean account email:

1. **Fetching**: The `config.username` property fetches your account email from the DigitalOcean API
2. **Sanitization**: The email is sanitized to create a valid Linux username:
   - Removes `@trailofbits.com` suffix (case insensitive)
   - For other domains, takes the part before `@`
   - Replaces special characters (`.`, `-`, `+`, etc.) with underscores
   - Converts to lowercase
   - Ensures it starts with a letter (prepends `u` if it starts with a number)
   - Falls back to `"user"` if sanitization results in empty string

3. **Usage**: The username is used for:
   - Creating users on droplets during cloud-init
   - Tagging droplets: `owner:<username>`
   - Default SSH user

**Example:**
- `john.doe@trailofbits.com` → `john_doe`
- `jane-smith@example.com` → `jane_smith`
- `123user@trailofbits.com` → `u123user`

**Access pattern:**
```python
# Get system username (from $USER env var, used as fallback)
system_user = Config.get_system_username()

# Get droplet username (from DigitalOcean account email)
config_manager = Config()
config_manager.load()
droplet_user = config_manager.username  # Fetches and sanitizes from DO API

# Sanitize email manually
username = Config.sanitize_email_for_username("john.doe@trailofbits.com")
# Returns: "john_doe"
```

## Key Design Decisions

1. **Username**:
   - **Automatically derived from DigitalOcean account email**
   - Not stored in configuration file
   - Fetched from DO API on demand using `/v2/account` endpoint
   - Sanitized for Linux compatibility (removes `@trailofbits.com`, replaces special chars)
   - Used for droplet user creation, SSH access, and tagging
   - Falls back to `$USER` environment variable during init if API fetch fails

2. **SSH Keys**:
   - Auto-detect common keys (id_ed25519.pub, id_rsa.pub, id_ecdsa.pub)
   - **Strict validation**: Only accepts public keys (*.pub files)
   - Validates key format (must start with ssh-rsa, ssh-ed25519, ecdsa-sha2-*, etc.)
   - Prevents accidental private key upload with clear error messages
   - Allow manual override in config

3. **Tags**:
   - Default tags: `owner:<username>` and `firewall`
   - Additional tags **extend** defaults (don't replace)
   - Used for filtering, billing, and security

4. **API**: Direct REST API calls (no python-digitalocean library)

5. **Security**:
   - Config files have restrictive permissions (0600/0700)
   - Private key upload prevention
   - SSH config backups created before modifications

6. **Validation**:
   - Pydantic models ensure type safety and configuration validity
   - Modern type hints (PEP 604): `str | None` instead of `Optional[str]`
   - Builtin generics: `list[str]` instead of `List[str]`

7. **Cloud-init Status**:
   - Uses JSON format output from `cloud-init status --format=json --wait`
   - **Always parses JSON regardless of subprocess return code** (important: cloud-init may return non-zero on error but still output valid JSON)
   - Checks `status` field for completion:
     - `"done"` - Successful completion
     - `"error"` - Cloud-init failed, shows error details and investigation commands
     - `"running"` - Still in progress, continues polling
   - Handles three states: success, error, and timeout
   - Only treats as "SSH not ready" if JSON parsing fails or output is empty
   - Verbose mode shows intermediate status values and error details

8. **Debugging**:
   - `--verbose` flag shows rendered cloud-init template, API requests, SSH attempts
   - Helps troubleshoot droplet creation and initialization issues

9. **SSH Hostname Convention**:
   - All SSH config entries use the prefix `tobcloud.` (e.g., `tobcloud.my-droplet`)
   - Centralized in `get_ssh_hostname()` helper function for easy modification
   - Makes it easy to identify droplets managed by tobcloud in SSH config

10. **Code Organization - Helper Functions**:
   The codebase uses helper functions to eliminate duplication and centralize logic:
   - `load_config_and_api()` - Loads configuration and creates API client (used by all commands)
   - `find_user_droplet()` - Finds droplet by name with user tag filtering
   - `find_project_by_name_or_id()` - Resolves project name or UUID to (id, name) tuple
   - `get_ssh_hostname()` - Converts droplet name to SSH hostname (`tobcloud.<name>`)
   - `get_snapshot_name()` - Converts droplet name to snapshot name (`tobcloud-<name>`)
   - `get_droplet_name_from_snapshot()` - Extracts droplet name from snapshot name
   - `get_user_tag()` - Generates user tag (`owner:<username>`)
   - `build_droplet_tags()` - Builds complete tag list with mandatory + extra tags
   - `register_ssh_keys_with_do()` - Handles SSH key detection, validation, and registration (~120 lines)
   - `wait_for_cloud_init()` - Polls cloud-init status via SSH (~159 lines)
   - `complete_droplet_name()` - Shell completion function for droplet names
   - `complete_project_name()` - Shell completion function for project names
   - `_destroy_hibernated_snapshot()` - Handles snapshot deletion flow (used by destroy command)
   - `find_snapshot_action()` - Finds most recent snapshot action for a droplet
   - `_complete_hibernate()` - Completes hibernate after snapshot (tag, destroy, cleanup)
   - `setup_tailscale()` - Full Tailscale setup flow (auth, SSH config, firewall lockdown)
   - `check_local_tailscale()` - Checks if Tailscale is running locally
   - `check_tailscale_installed()` - Checks if Tailscale is installed on a droplet
   - `install_tailscale_on_droplet()` - Installs Tailscale on droplet via SSH
   - `run_tailscale_up()` - Runs `tailscale up` on droplet, extracts auth URL
   - `tailscale_logout()` - Logs out from Tailscale before destroy/hibernate (cleans up admin console)
   - `wait_for_tailscale_ip()` - Polls for Tailscale IP after authentication
   - `lock_down_to_tailscale()` - Resets UFW to only allow tailscale0 traffic
   - `verify_tailscale_ssh()` - Verifies SSH access works via Tailscale IP
   - `is_droplet_tailscale_locked()` - Checks if droplet SSH config points to Tailscale IP
   - `add_temporary_ssh_rule()` - Adds temp UFW rule for SSH on eth0 (for hibernate)
   - `prepare_for_hibernate()` - Handles Tailscale lockdown preparation before hibernate
   - `get_ssh_host_ip()` (in ssh_config.py) - Gets IP address from SSH config for a host

   **Benefits**: Single source of truth, easier maintenance, reduced code duplication

11. **Shell Completion**:
   - Dynamic tab completion for droplet names using Typer's autocompletion feature
   - `complete_droplet_name()` function fetches droplet names from DO API
   - Filters droplets by current user's tag (`owner:<username>`)
   - Silently fails on errors to prevent breaking the CLI
   - Supports case-insensitive prefix matching
   - Used by commands: `info`, `destroy`, `config-ssh`, `resize`, `on`, `off`, `enable-tailscale`
   - Enabled via `tobcloud --install-completion zsh` (or bash/fish)

   **Implementation details**:
   - Completion function accepts `incomplete: str` parameter (partial text from user)
   - Returns `list[str]` of matching droplet names
   - Connected to arguments via `autocompletion=complete_droplet_name` parameter
   - Typer/Click handle shell integration automatically

12. **Project Assignment**:
   - Droplets can be assigned to DigitalOcean projects for organization
   - Optional default project can be set in config (`defaults.project_id` stores UUID)
   - Override per-droplet using `--project` flag on `tobcloud create` (accepts name or UUID)
   - Project assignment happens after droplet becomes active
   - Uses DigitalOcean Projects API:
     - `GET /v2/projects` - List available projects
     - `POST /v2/projects/{project_id}/resources` - Assign droplet to project
     - Resource URN format: `do:droplet:{droplet_id}`
   - Graceful degradation: If project assignment fails, droplet creation continues
   - `display_projects()` UI function shows project table (ID, name, purpose, description)

   **Implementation details**:
   - `api.list_projects()` - Fetch all projects (paginated, used for listing/search)
   - `api.get_project(project_id)` - Get specific project by UUID (efficient, returns None if 404)
   - `api.get_default_project()` - Get default project (returns None if no default)
   - `api.assign_resources_to_project(project_id, [urn])` - Assign droplet to project
   - `api.get_droplet_urn(droplet_id)` - Generate URN for droplet
   - `find_project_by_name_or_id(api, name_or_id)` - Resolve project name or UUID to (id, name)
     - **Optimized**: If input looks like UUID (36 chars, 4 hyphens), uses `get_project()` directly
     - Only lists all projects if searching by name (case-insensitive)
   - `complete_project_name(incomplete)` - Shell completion for project names
   - Project UUID stored in `DefaultsConfig.project_id` (config stores UUID for stability)
   - Init command:
     - Fetches and displays DigitalOcean default project if available
     - Offers default project name as prompt default
     - Prompts for project name or ID (optional, with `?` for help)
   - Create command accepts project name or UUID via `--project` flag (with autocompletion)
   - Name resolution is case-insensitive, matches by name first

13. **Tailscale VPN Integration**:
   - **Enabled by default** for all new droplets
   - Provides secure VPN access without exposing public SSH
   - Disable with `--no-tailscale` flag on `tobcloud create`

   **Setup flow**:
   1. Cloud-init installs Tailscale via official install script
   2. After cloud-init completes, tobcloud SSHes to droplet via public IP
   3. Runs `sudo tailscale up` and extracts auth URL
   4. Displays auth URL to user terminal for browser authentication
   5. Polls for Tailscale IP (100.x.x.x) after user authenticates
   6. Updates SSH config with Tailscale IP
   7. Locks down UFW to only allow traffic on tailscale0 interface
   8. Verifies SSH access works via Tailscale

   **Configuration** (`config.tailscale`):
   ```yaml
   tailscale:
     enabled: true             # Enable Tailscale by default
     lock_down_firewall: true  # Reset UFW to tailscale0 only
     auth_timeout: 300         # Seconds to wait for authentication
   ```

   **UFW lockdown** (blocks ALL public traffic):
   ```bash
   sudo ufw --force reset
   sudo ufw allow in on tailscale0
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw --force enable
   ```

   **Safety features**:
   - Verifies local Tailscale is running before locking down firewall
   - If local Tailscale not running, keeps public SSH open
   - Shows manual lockdown command if skipped
   - Auth timeout keeps public IP in SSH config with manual instructions

   **Prerequisite**: Tailscale must be installed on your local machine

### Pydantic Configuration Models

The configuration system uses Pydantic `BaseModel` for strict validation:

- **`DigitalOceanConfig`**: Validates API token (non-empty, strips whitespace)
- **`DefaultsConfig`**: Validates region, size, image slugs (non-empty strings)
- **`CloudInitConfig`**: Validates template path and SSH keys (min 1 key required)
- **`SSHConfig`**: Validates SSH config path and identity file
- **`TailscaleConfig`**: Tailscale VPN settings (enabled, lock_down_firewall, auth_timeout)
- **`TobcloudConfig`**: Main config that composes all sub-configs with `extra='forbid'`

**Benefits:**
- Automatic type checking and validation on load
- Clear error messages for invalid configurations
- Prevents typos and missing required fields
- IDE autocomplete support for config access
- Runtime guarantees that loaded config is valid

**Usage Example:**
```python
config_manager = Config()
config_manager.load()  # Validates config file

# Type-safe access with IDE autocomplete
token = config_manager.config.digitalocean.token  # str
region = config_manager.config.defaults.region     # str
tags = config_manager.config.defaults.tags         # List[str]
```

## Commands (Current & Planned)

- [x] `tobcloud init` - Initialize configuration
  - Validates API token immediately
  - Fetches available regions and sizes from DO API (with pagination support)
  - Interactive prompts with `?` for help:
    - User can type `?` to see available regions/sizes
    - Shows formatted tables with all options
    - Re-prompts after displaying help
  - Auto-detects and validates SSH keys (public keys only)
  - Fetches DigitalOcean account email to generate default tags
  - Creates config with secure permissions
  - **Note**: Username is derived from DO account email, not configured

- [x] `tobcloud create [name]` - Create droplet with cloud-init
  - **Interactive mode**: If name/region/size/image not provided, prompts interactively
  - Uses `prompt_with_help()` with `?` for help (shows available regions/sizes/images)
  - Renders Jinja2 cloud-init template with username and SSH keys
  - Validates SSH keys before upload
  - Creates droplet via DigitalOcean API
  - Waits for droplet to become active
  - Automatically adds SSH config entry (uses hostname alias)
  - Waits for cloud-init completion (checks JSON status == "done")
  - **Tailscale VPN** (enabled by default):
    - Installs Tailscale during cloud-init
    - Runs `tailscale up` and displays auth URL for browser login
    - Updates SSH config with Tailscale IP after authentication
    - Locks down firewall to only allow traffic on tailscale0 interface
    - Use `--no-tailscale` to skip Tailscale setup
  - Supports custom region, size, image, user via CLI flags
  - `--verbose` flag shows debug output and rendered cloud-init
  - `--tags` extends default tags instead of replacing
  - `--no-tailscale` flag disables Tailscale VPN setup

- [x] `tobcloud list` - List droplets and hibernated snapshots
  - Filters by `owner:<username>` tag
  - **Droplets section**: name, status, IP address, region, size, SSH config status (✓/✗)
  - **Hibernated section**: name, size (GB), region for tobcloud snapshots
  - Shows summary: "Total: X droplet(s), Y hibernated"
  - Displays results in formatted tables

- [x] `tobcloud config-ssh <droplet-name>` - Configure SSH for existing droplet
  - Finds droplet by name (filtered by user tag)
  - Prompts for username and identity file (or accepts via flags)
  - Supports `--user` and `--identity-file` flags
  - Updates existing entries with confirmation
  - Adds host entry to SSH config

- [x] `tobcloud info <droplet-name>` - Show detailed droplet information
  - Displays comprehensive information in organized sections
  - Basic info: ID, name, status (colored), creation date
  - Network: Public/private IPv4 and IPv6 addresses
  - Configuration: Region, size, vCPUs, memory, disk, transfer, price
  - Image: Distribution, name, slug
  - Tags and features
  - SSH access status with connection instructions
  - Suggests `config-ssh` if not in SSH config

- [x] `tobcloud destroy <droplet-name>` - Delete droplet or hibernated snapshot (DESTRUCTIVE)
  - **Safety features**: Double confirmation required for droplets
  - First prompt: "Are you sure you want to destroy this droplet?" (yes/no, defaults to "no")
  - Second prompt: "Type the droplet name to confirm deletion" (must match exactly)
  - Shows comprehensive droplet information before deletion
  - Only allows deletion of resources tagged with `owner:<username>`
  - **Tailscale cleanup**: If droplet is Tailscale-locked, logs out from Tailscale before deletion (removes device from admin console)
  - **Smart fallback**: If no droplet found, checks for hibernated snapshot with same name
  - For hibernated snapshots: Single yes/no confirmation (simpler flow)
  - Deletes resource via DigitalOcean API
  - Automatically removes SSH config entry (`tobcloud.<droplet-name>`)
  - Clear success/error messages and cancellation handling

- [x] `tobcloud list-ssh-keys` - List SSH keys registered via tobcloud
  - Shows all SSH keys registered in DigitalOcean account
  - Displays: ID, name, fingerprint (MD5 format)
  - Formatted table output

- [x] `tobcloud add-ssh-key <path>` - Add or import SSH public key
  - Upload a new SSH key to DigitalOcean account
  - Validates key is a public key (*.pub file)
  - Computes fingerprint and checks if key already exists
  - Updates key name if fingerprint matches existing key
  - Adds new key if not found
  - Used to import additional SSH keys after initialization

- [x] `tobcloud delete-ssh-key <key-id>` - Delete SSH key from DigitalOcean
  - Removes SSH key from DigitalOcean account by ID
  - Requires confirmation before deletion
  - Only deletes keys registered via tobcloud
  - Get key ID from `list-ssh-keys` command

- [x] `tobcloud resize <droplet-name>` - Resize droplet (causes downtime)
  - **Interactive size selection**: If `--size` not provided, prompts with `?` for help (shows all available sizes)
  - Changes droplet's vCPUs, memory, and optionally disk size
  - **Safety features**:
    - Only allows resizing droplets tagged with `owner:<username>`
    - Shows comprehensive comparison: current size vs new size vs changes
    - Displays price difference (+$X.XX/month or -$X.XX/month)
    - Requires confirmation before proceeding
    - Prevents resizing to the same size
  - **Warnings displayed**:
    - Downtime warning (droplet will be powered off during resize)
    - Disk resize warning (permanent and cannot be undone) if `--disk` is used
    - Note about disk not being resized if `--no-disk` is used
  - **Options**:
    - `--size` / `-s` - Specify new size slug (e.g., s-4vcpu-8gb)
    - `--disk` / `--no-disk` - Resize disk (default: True, permanent if enabled)
  - Initiates resize action via DigitalOcean API
  - Polls action status until complete (10 minute timeout)
  - Shows success message with new size

- [x] `tobcloud on <droplet-name>` - Power on a droplet
  - Only allows powering on droplets tagged with `owner:<username>`
  - Checks if droplet is already active (skips if yes)
  - Shows current status before powering on
  - Initiates power on action via DigitalOcean API
  - Polls action status until complete (2 minute timeout)
  - Shows success message

- [x] `tobcloud off <droplet-name>` - Power off a droplet
  - Only allows powering off droplets tagged with `owner:<username>`
  - Checks if droplet is already off (skips if yes)
  - Shows current status before powering off
  - **Shows billing warning**: Reminds user DO bills for stopped droplets
  - Suggests `tobcloud hibernate` as cost-saving alternative
  - **Requires confirmation** before proceeding (yes/no, defaults to no)
  - Initiates power off action via DigitalOcean API
  - Polls action status until complete (2 minute timeout)
  - Shows success message

- [x] `tobcloud hibernate <droplet-name>` - Hibernate droplet (cost-saving)
  - Only allows hibernating droplets tagged with `owner:<username>`
  - **Workflow**:
    1. Detect Tailscale lockdown (if SSH config points to Tailscale IP)
    2. If Tailscale locked: add temp SSH rule for eth0 (must succeed)
    3. If temp rule succeeded: logout from Tailscale (cleans up admin console)
    4. Update SSH config to public IP
    5. Power off droplet (if not already off)
    6. Create snapshot named `tobcloud-<droplet-name>`
    7. Tag snapshot with `owner:<username>`, `size:<size-slug>`, and optionally `tailscale-lockdown`
    8. Destroy droplet
    9. Remove SSH config entry
  - **Tailscale lockdown handling**: Automatically detected and handled
    - Adds temporary UFW rule to allow SSH on eth0 (safety - ensures fallback access)
    - Logs out from Tailscale to remove device from admin console
    - Tags snapshot with `tailscale-lockdown` so wake knows to re-setup Tailscale
  - **Existing snapshot handling**: Prompts to overwrite if snapshot already exists
  - **Error recovery**: If snapshot fails, droplet remains powered off but intact
  - **--continue flag**: Resume a timed-out hibernate operation
    - Finds in-progress snapshot action and waits for completion
    - Then continues with tagging, destroying, and cleanup
    - Use when snapshot creation times out (60 min limit)
  - Shows snapshot creation time and size on completion
  - Suggests `tobcloud wake <name>` for restoration

- [x] `tobcloud wake <droplet-name>` - Wake hibernated droplet
  - Checks no droplet with same name exists (error if yes)
  - Finds hibernated snapshot `tobcloud-<name>` by owner tag
  - Reads region from snapshot metadata, size from `size:*` tag
  - Checks for `tailscale-lockdown` tag on snapshot
  - Creates new droplet from snapshot image
  - Waits for droplet to become active
  - Adds SSH config entry (with public IP)
  - **Tailscale re-setup** (if `tailscale-lockdown` tag present):
    - Automatically runs `tailscale up` and displays auth URL
    - Updates SSH config with Tailscale IP after authentication
    - Locks down firewall to Tailscale only
  - **Options**:
    - `--no-tailscale` - Skip Tailscale re-setup (keep public SSH access)
  - **Prompts to delete snapshot** (default: yes) to save storage costs
  - Shows connection instructions on completion

- [x] `tobcloud enable-tailscale <droplet-name>` - Enable Tailscale VPN on existing droplet
  - Only allows modifying droplets tagged with `owner:<username>`
  - Droplet must be active (powered on)
  - Installs Tailscale if not already installed via official script
  - Runs `tailscale up` and displays auth URL for browser login
  - Polls for Tailscale IP after authentication
  - Updates SSH config with Tailscale IP
  - Optionally locks down firewall to Tailscale only
  - **Options**:
    - `--no-lockdown` - Skip firewall lockdown (keep public SSH access)
    - `--verbose` / `-v` - Show debug output

## DigitalOcean API Endpoints

Base URL: `https://api.digitalocean.com/v2`
Auth: `Authorization: Bearer <token>`

Key endpoints:
- `GET /v2/account` - Get account information (includes email for username derivation)
- `GET /v2/regions` - List all regions (paginated)
- `GET /v2/sizes` - List all droplet sizes (paginated)
- `GET /v2/images` - List all images (paginated)
- `POST /v2/droplets` - Create droplet
- `GET /v2/droplets` - List droplets
- `GET /v2/droplets?tag_name=X` - Filter by tag
- `GET /v2/droplets/{id}` - Get droplet info
- `DELETE /v2/droplets/{id}` - Delete droplet
- `POST /v2/droplets/{id}/actions` - Perform action (resize, power_on, power_off, etc.)
- `GET /v2/actions/{id}` - Check action status (used for polling resize completion)
- `GET /v2/account/keys` - List SSH keys (paginated)
- `GET /v2/account/keys/{fingerprint}` - Get SSH key by fingerprint
- `POST /v2/account/keys` - Add new SSH key
- `PUT /v2/account/keys/{id}` - Update SSH key name
- `DELETE /v2/account/keys/{id}` - Delete SSH key
- `GET /v2/projects` - List all projects (paginated)
- `GET /v2/projects/{project_id}` - Get a specific project by UUID
- `GET /v2/projects/default` - Get the default project for the account
- `POST /v2/projects/{project_id}/resources` - Assign resources to a project (body: `{"resources": ["do:droplet:12345"]}`)
- `GET /v2/snapshots` - List snapshots (paginated, filter by `resource_type=droplet`)
- `GET /v2/snapshots/{snapshot_id}` - Get snapshot by ID
- `DELETE /v2/snapshots/{snapshot_id}` - Delete snapshot
- `POST /v2/tags` - Create tag
- `POST /v2/tags/{tag_name}/resources` - Tag a resource (body: `{"resources": [{"resource_id": "123", "resource_type": "image"}]}`)

**Pagination**: The API uses pagination with `page` and `per_page` query parameters (max 200/page). The `api.py` module automatically handles pagination by following the `links.pages.next` URLs until all results are fetched.

## Important Notes

- **Never use `pip` - always use `uv`** for all Python operations
- **Always run `./lint.sh`** before committing to ensure code quality
- **Always update README.md** when adding new commands or major features
  - Update the "Available Commands" section with new commands
  - Keep README.md in sync with CLAUDE.md and actual functionality
- Config files contain sensitive data (API tokens) - handle with care
- Cloud-init template uses Jinja2 for variable substitution
- **SSH Key Security**:
  - Only public keys (*.pub files) are accepted
  - Private keys are rejected with clear error messages
  - Validation happens at multiple checkpoints (init, create)
  - Supports RSA, ED25519, ECDSA, and security keys
- SSH config updates preserve existing entries and create automatic backups
  - Backup created at `~/.ssh/config.bak` before any modification
  - Backup has same permissions as original file
  - Each backup overwrites the previous one
- All droplets are tagged with `owner:<username>` for filtering
- Additional tags extend defaults (don't replace them)
- **SSH hostname convention**: All SSH entries use `tobcloud.<droplet-name>` format
- **Droplet deletion safety**:
  - Requires double confirmation (yes/no + type droplet name)
  - Only allows deletion of droplets owned by the user (`owner:<username>` tag)
  - Shows full droplet information before deletion
  - Automatically removes SSH config entry on successful deletion
- **Droplet resizing**:
  - Interactive size selection with `?` for help (shows all available sizes)
  - Shows comprehensive comparison and price differences
  - Causes downtime (droplet powered off during resize)
  - Disk resize is permanent and cannot be undone (use `--no-disk` to avoid)
  - Requires confirmation before proceeding
  - Action polling with 10 minute timeout
- **Cloud-init completion**: Checked via JSON status field
  - Success: `status == "done"`
  - Failure: `status == "error"` with error details and log file locations
  - Timeout: Shows warning if status check times out
- **Debugging**: Use `--verbose` flag to see detailed output including cloud-init errors
- Comprehensive test suite: **134 tests** covering all functionality
- **Type hints**: Modern Python 3.11+ syntax (`str | None`, `list[str]`)
- **Code quality**: Ruff (linter + formatter) + Mypy (type checker)
