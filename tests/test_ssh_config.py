"""Comprehensive tests for SSH config management."""

from pathlib import Path

import pytest

from tobcloud.ssh_config import add_ssh_host, remove_ssh_host


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
