"""Comprehensive tests for SSH config management."""

from pathlib import Path

import pytest

from tobcloud.ssh_config import add_ssh_host, get_ssh_host_ip, remove_ssh_host


@pytest.fixture
def temp_ssh_dir(tmp_path):
    """Create a temporary SSH directory for testing."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    yield ssh_dir
    # Cleanup is automatic with tmp_path


@pytest.fixture
def temp_config(temp_ssh_dir):
    """Create a temporary SSH config file path."""
    config_path = temp_ssh_dir / "config"
    return str(config_path)


class TestAddSSHHost:
    """Tests for add_ssh_host function."""

    def test_empty_file(self, temp_config):
        """Test adding host to empty SSH config file."""
        # Create empty file
        Path(temp_config).touch(mode=0o600)

        add_ssh_host(temp_config, "myhost", "192.168.1.1", "ubuntu")

        content = Path(temp_config).read_text()
        assert "Host myhost" in content
        assert "HostName 192.168.1.1" in content
        assert "User ubuntu" in content

    def test_non_existent_file(self, temp_config):
        """Test creating new file and directory if they don't exist."""
        # Ensure file doesn't exist
        assert not Path(temp_config).exists()

        add_ssh_host(temp_config, "myhost", "192.168.1.1", "ubuntu", "~/.ssh/id_ed25519")

        assert Path(temp_config).exists()
        content = Path(temp_config).read_text()
        assert "Host myhost" in content
        assert "IdentityFile ~/.ssh/id_ed25519" in content

    def test_simple_addition(self, temp_config):
        """Test adding host to config with existing unrelated hosts."""
        # Create config with existing host
        existing = """Host other-server
    HostName 10.0.0.1
    User admin

Host another-host
    HostName 10.0.0.2
    User root
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "myhost", "192.168.1.1", "ubuntu")

        content = Path(temp_config).read_text()
        assert "Host other-server" in content
        assert "Host another-host" in content
        assert "Host myhost" in content
        # Count "Host " with space to avoid matching "HostName"
        assert content.count("Host ") == 3

    def test_update_existing_host(self, temp_config):
        """Test replacing existing host entry without duplication."""
        # Create config with existing host
        existing = """Host myhost
    HostName 10.0.0.1
    User old_user

Host other-host
    HostName 10.0.0.2
    User admin
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "myhost", "192.168.1.1", "new_user")

        content = Path(temp_config).read_text()
        assert content.count("Host myhost") == 1  # Should not duplicate
        assert "HostName 192.168.1.1" in content
        assert "User new_user" in content
        assert "old_user" not in content
        assert "10.0.0.1" not in content
        assert "Host other-host" in content  # Other hosts preserved

    def test_host_with_similar_names(self, temp_config):
        """Test that similar host names don't interfere."""
        existing = """Host myhost
    HostName 10.0.0.1
    User user1

Host myhost-dev
    HostName 10.0.0.2
    User user2

Host myhost-prod
    HostName 10.0.0.3
    User user3
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "myhost", "192.168.1.1", "newuser")

        content = Path(temp_config).read_text()
        assert "Host myhost-dev" in content
        assert "10.0.0.2" in content
        assert "Host myhost-prod" in content
        assert "10.0.0.3" in content
        # myhost should be updated
        lines = content.split("\n")
        myhost_line = [i for i, line in enumerate(lines) if line.strip() == "Host myhost"][-1]
        # Check that the next few lines after myhost contain the new values
        section = "\n".join(lines[myhost_line : myhost_line + 5])
        assert "192.168.1.1" in section
        assert "newuser" in section

    def test_host_as_substring(self, temp_config):
        """Test that substring hosts are handled correctly."""
        existing = """Host prod-server
    HostName 10.0.0.1
    User admin

Host prod
    HostName 10.0.0.2
    User root
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "prod", "192.168.1.1", "ubuntu")

        content = Path(temp_config).read_text()
        assert "Host prod-server" in content
        assert "10.0.0.1" in content
        # prod should be updated
        assert content.count("Host prod\n") >= 1

    def test_multiple_blank_lines(self, temp_config):
        """Test handling config with various blank lines."""
        existing = """Host server1
    HostName 10.0.0.1
    User admin


Host server2
    HostName 10.0.0.2
    User root



Host server3
    HostName 10.0.0.3
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "newhost", "192.168.1.1", "user")

        content = Path(temp_config).read_text()
        assert "Host server1" in content
        assert "Host server2" in content
        assert "Host server3" in content
        assert "Host newhost" in content

    def test_comments_in_config(self, temp_config):
        """Test preserving comments in config."""
        existing = """# This is a comment
Host server1
    HostName 10.0.0.1
    User admin
    # Another comment

# Global settings
Host server2
    HostName 10.0.0.2
    User root
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "newhost", "192.168.1.1", "user")

        content = Path(temp_config).read_text()
        assert "# This is a comment" in content
        assert "# Another comment" in content
        assert "# Global settings" in content

    def test_mixed_indentation(self, temp_config):
        """Test handling tabs and spaces."""
        existing = """Host server1
	HostName 10.0.0.1
	User admin

Host server2
    HostName 10.0.0.2
    User root
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "newhost", "192.168.1.1", "user")

        content = Path(temp_config).read_text()
        # Original hosts should be preserved
        assert "Host server1" in content
        assert "Host server2" in content
        # New host should be added
        assert "Host newhost" in content

    def test_host_at_beginning(self, temp_config):
        """Test updating a host that's the first entry."""
        existing = """Host first-host
    HostName 10.0.0.1
    User admin

Host second-host
    HostName 10.0.0.2
    User root
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "first-host", "192.168.1.1", "newuser")

        content = Path(temp_config).read_text()
        assert content.count("Host first-host") == 1
        assert "192.168.1.1" in content
        assert "10.0.0.1" not in content
        assert "Host second-host" in content

    def test_host_at_end(self, temp_config):
        """Test updating a host that's the last entry."""
        existing = """Host first-host
    HostName 10.0.0.1
    User admin

Host last-host
    HostName 10.0.0.2
    User root
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "last-host", "192.168.1.1", "newuser")

        content = Path(temp_config).read_text()
        assert "Host first-host" in content
        assert content.count("Host last-host") == 1
        assert "192.168.1.1" in content
        assert "10.0.0.2" not in content

    def test_host_in_middle(self, temp_config):
        """Test updating a host between others."""
        existing = """Host first-host
    HostName 10.0.0.1
    User admin

Host middle-host
    HostName 10.0.0.2
    User root

Host last-host
    HostName 10.0.0.3
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "middle-host", "192.168.1.1", "newuser")

        content = Path(temp_config).read_text()
        assert "Host first-host" in content
        assert "Host last-host" in content
        assert content.count("Host middle-host") == 1
        assert "192.168.1.1" in content
        assert "10.0.0.2" not in content

    def test_complex_host_entries(self, temp_config):
        """Test host with many configuration options."""
        existing = """Host complex-host
    HostName 10.0.0.1
    User admin
    Port 2222
    ForwardAgent yes
    ProxyJump bastion
    IdentityFile ~/.ssh/custom_key
    StrictHostKeyChecking no
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "complex-host", "192.168.1.1", "newuser", "~/.ssh/new_key")

        content = Path(temp_config).read_text()
        assert content.count("Host complex-host") == 1
        assert "192.168.1.1" in content
        assert "newuser" in content
        # Old complex options should be replaced
        assert "Port 2222" not in content

    def test_host_with_extra_spaces(self, temp_config):
        """Test host declaration with multiple spaces."""
        existing = """Host    server-with-spaces
    HostName 10.0.0.1
    User admin
"""
        Path(temp_config).write_text(existing)

        # This won't match because our check is exact
        add_ssh_host(temp_config, "server-with-spaces", "192.168.1.1", "newuser")

        content = Path(temp_config).read_text()
        # Should add a new entry since "Host    server-with-spaces" != "Host server-with-spaces"
        assert "Host server-with-spaces" in content

    def test_host_patterns(self, temp_config):
        """Test existing wildcard hosts."""
        existing = """Host *.example.com
    User admin
    IdentityFile ~/.ssh/example_key

Host myserver
    HostName 10.0.0.1
    User root
"""
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "newhost", "192.168.1.1", "ubuntu")

        content = Path(temp_config).read_text()
        assert "Host *.example.com" in content
        assert "Host myserver" in content
        assert "Host newhost" in content

    def test_no_trailing_newline(self, temp_config):
        """Test config file without final newline."""
        existing = """Host myhost
    HostName 10.0.0.1
    User admin"""  # No trailing newline
        Path(temp_config).write_text(existing)

        add_ssh_host(temp_config, "newhost", "192.168.1.1", "ubuntu")

        content = Path(temp_config).read_text()
        assert "Host myhost" in content
        assert "Host newhost" in content
        # Verify Host newhost is on its own line (not concatenated to previous line)
        lines = content.split("\n")
        host_lines = [line for line in lines if "Host newhost" in line]
        assert len(host_lines) == 1
        assert host_lines[0].strip() == "Host newhost"

    def test_permissions_preserved(self, temp_config):
        """Test that file permissions are set correctly."""
        Path(temp_config).touch(mode=0o644)

        add_ssh_host(temp_config, "myhost", "192.168.1.1", "ubuntu")

        # File should now have 0600 permissions
        mode = Path(temp_config).stat().st_mode & 0o777
        assert mode == 0o600

    def test_backup_created(self, temp_config):
        """Test that backup file is created."""
        existing = """Host oldhost
    HostName 10.0.0.1
    User admin
"""
        Path(temp_config).write_text(existing)
        Path(temp_config).chmod(0o600)

        add_ssh_host(temp_config, "newhost", "192.168.1.1", "ubuntu")

        backup_path = Path(temp_config).parent / "config.bak"
        assert backup_path.exists()

        backup_content = backup_path.read_text()
        assert "Host oldhost" in backup_content
        assert "Host newhost" not in backup_content

        # Check backup has same permissions
        backup_mode = backup_path.stat().st_mode & 0o777
        assert backup_mode == 0o600


class TestRemoveSSHHost:
    """Tests for remove_ssh_host function."""

    def test_non_existent_file(self, temp_config):
        """Test removing from non-existent config."""
        assert not Path(temp_config).exists()
        result = remove_ssh_host(temp_config, "myhost")
        assert result is False

    def test_host_doesnt_exist(self, temp_config):
        """Test removing host that's not in config."""
        existing = """Host server1
    HostName 10.0.0.1
    User admin
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "nonexistent")

        assert result is False
        content = Path(temp_config).read_text()
        assert "Host server1" in content  # Should be unchanged

    def test_remove_first_host(self, temp_config):
        """Test removing the first host entry."""
        existing = """Host first-host
    HostName 10.0.0.1
    User admin

Host second-host
    HostName 10.0.0.2
    User root

Host third-host
    HostName 10.0.0.3
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "first-host")

        assert result is True
        content = Path(temp_config).read_text()
        assert "Host first-host" not in content
        assert "Host second-host" in content
        assert "Host third-host" in content

    def test_remove_last_host(self, temp_config):
        """Test removing the last host entry."""
        existing = """Host first-host
    HostName 10.0.0.1
    User admin

Host second-host
    HostName 10.0.0.2
    User root

Host last-host
    HostName 10.0.0.3
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "last-host")

        assert result is True
        content = Path(temp_config).read_text()
        assert "Host first-host" in content
        assert "Host second-host" in content
        assert "Host last-host" not in content

    def test_remove_middle_host(self, temp_config):
        """Test removing a host between others."""
        existing = """Host first-host
    HostName 10.0.0.1
    User admin

Host middle-host
    HostName 10.0.0.2
    User root

Host last-host
    HostName 10.0.0.3
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "middle-host")

        assert result is True
        content = Path(temp_config).read_text()
        assert "Host first-host" in content
        assert "Host middle-host" not in content
        assert "Host last-host" in content

    def test_remove_only_host(self, temp_config):
        """Test removing the only host in config."""
        existing = """Host only-host
    HostName 10.0.0.1
    User admin
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "only-host")

        assert result is True
        content = Path(temp_config).read_text()
        assert "Host only-host" not in content
        # File should be essentially empty or just whitespace
        assert content.strip() == "" or "Host" not in content

    def test_remove_similar_host_names(self, temp_config):
        """Test removing specific host when similar names exist."""
        existing = """Host myhost
    HostName 10.0.0.1
    User user1

Host myhost-dev
    HostName 10.0.0.2
    User user2

Host myhost-prod
    HostName 10.0.0.3
    User user3
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "myhost")

        assert result is True
        content = Path(temp_config).read_text()
        assert "Host myhost\n" not in content
        assert "10.0.0.1" not in content
        assert "Host myhost-dev" in content
        assert "10.0.0.2" in content
        assert "Host myhost-prod" in content
        assert "10.0.0.3" in content

    def test_remove_host_with_many_options(self, temp_config):
        """Test removing host with many configuration lines."""
        existing = """Host simple-host
    HostName 10.0.0.1
    User admin

Host complex-host
    HostName 10.0.0.2
    User root
    Port 2222
    ForwardAgent yes
    ProxyJump bastion
    IdentityFile ~/.ssh/custom_key
    StrictHostKeyChecking no
    LocalForward 8080 localhost:80

Host another-host
    HostName 10.0.0.3
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "complex-host")

        assert result is True
        content = Path(temp_config).read_text()
        assert "Host simple-host" in content
        assert "Host complex-host" not in content
        assert "Port 2222" not in content
        assert "ProxyJump bastion" not in content
        assert "Host another-host" in content

    def test_backup_created_on_remove(self, temp_config):
        """Test that backup is created when removing host."""
        existing = """Host myhost
    HostName 10.0.0.1
    User admin

Host otherhost
    HostName 10.0.0.2
    User root
"""
        Path(temp_config).write_text(existing)
        Path(temp_config).chmod(0o600)

        remove_ssh_host(temp_config, "myhost")

        backup_path = Path(temp_config).parent / "config.bak"
        assert backup_path.exists()

        backup_content = backup_path.read_text()
        assert "Host myhost" in backup_content
        assert "Host otherhost" in backup_content

        # Check backup has same permissions
        backup_mode = backup_path.stat().st_mode & 0o777
        assert backup_mode == 0o600

    def test_remove_preserves_comments(self, temp_config):
        """Test that comments are preserved when removing host."""
        existing = """# Global comment
Host keephost
    HostName 10.0.0.1
    User admin

# This host will be removed
Host removehost
    HostName 10.0.0.2
    User root

# Another comment
Host anotherhost
    HostName 10.0.0.3
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = remove_ssh_host(temp_config, "removehost")

        assert result is True
        content = Path(temp_config).read_text()
        assert "# Global comment" in content
        assert "# Another comment" in content
        assert "Host keephost" in content
        assert "Host removehost" not in content
        assert "Host anotherhost" in content


class TestGetSSHHostIP:
    """Tests for get_ssh_host_ip function."""

    def test_valid_host(self, temp_config):
        """Test getting IP for existing host."""
        existing = """Host myhost
    HostName 192.168.1.100
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = get_ssh_host_ip(temp_config, "myhost")
        assert result == "192.168.1.100"

    def test_host_not_found(self, temp_config):
        """Test getting IP for non-existent host."""
        existing = """Host otherhost
    HostName 192.168.1.100
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = get_ssh_host_ip(temp_config, "myhost")
        assert result is None

    def test_missing_hostname_field(self, temp_config):
        """Test host entry without HostName field."""
        existing = """Host myhost
    User ubuntu
    IdentityFile ~/.ssh/id_rsa
"""
        Path(temp_config).write_text(existing)

        result = get_ssh_host_ip(temp_config, "myhost")
        assert result is None

    def test_non_existent_file(self, temp_config):
        """Test with non-existent config file."""
        result = get_ssh_host_ip(temp_config, "myhost")
        assert result is None

    def test_tailscale_ip(self, temp_config):
        """Test getting Tailscale IP address."""
        existing = """Host tobcloud.myhost
    HostName 100.80.123.45
    User ubuntu
    ForwardAgent yes
"""
        Path(temp_config).write_text(existing)

        result = get_ssh_host_ip(temp_config, "tobcloud.myhost")
        assert result == "100.80.123.45"

    def test_multiple_hosts(self, temp_config):
        """Test getting IP from config with multiple hosts."""
        existing = """Host firsthost
    HostName 10.0.0.1
    User admin

Host targethost
    HostName 192.168.1.50
    User ubuntu

Host thirdhost
    HostName 10.0.0.3
    User root
"""
        Path(temp_config).write_text(existing)

        result = get_ssh_host_ip(temp_config, "targethost")
        assert result == "192.168.1.50"

    def test_host_with_extra_whitespace(self, temp_config):
        """Test HostName with extra whitespace."""
        existing = """Host myhost
    HostName   192.168.1.100
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        result = get_ssh_host_ip(temp_config, "myhost")
        assert result == "192.168.1.100"

    def test_multiple_hosts_on_same_line(self, temp_config):
        """Test host with multiple aliases on same line."""
        existing = """Host myhost myalias anotherhost
    HostName 192.168.1.100
    User ubuntu
"""
        Path(temp_config).write_text(existing)

        # Should work for any of the aliases
        assert get_ssh_host_ip(temp_config, "myhost") == "192.168.1.100"
        assert get_ssh_host_ip(temp_config, "myalias") == "192.168.1.100"
        assert get_ssh_host_ip(temp_config, "anotherhost") == "192.168.1.100"

    def test_hostname_vs_host(self, temp_config):
        """Test that we distinguish between Host directive and HostName option."""
        existing = """Host realhost
    HostName 192.168.1.100
    User ubuntu

Host anotherreal
    HostName 10.0.0.1
    User admin
"""
        Path(temp_config).write_text(existing)

        # Should not find HostName as a host alias
        assert get_ssh_host_ip(temp_config, "192.168.1.100") is None
        # Should find the actual hosts
        assert get_ssh_host_ip(temp_config, "realhost") == "192.168.1.100"
