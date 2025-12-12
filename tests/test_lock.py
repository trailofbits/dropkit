"""Tests for file-based locking mechanism."""

import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from tobcloud.lock import (
    DEFAULT_TIMEOUT,
    LOCK_FILE,
    LockError,
    LockInfo,
    operation_lock,
    requires_lock,
)


@pytest.fixture
def temp_lock_file(tmp_path):
    """Use a temporary lock file for testing."""
    test_lock = tmp_path / "tobcloud.lock"
    with patch("tobcloud.lock.LOCK_FILE", test_lock):
        yield test_lock


class TestLockInfo:
    """Tests for LockInfo class."""

    def test_to_json(self):
        """Test serialization to JSON."""
        info = LockInfo(pid=12345, command="create")
        json_str = info.to_json()
        assert '"pid": 12345' in json_str
        assert '"command": "create"' in json_str

    def test_from_file_valid(self, tmp_path):
        """Test reading valid lock info from file."""
        lock_file = tmp_path / "test.lock"
        lock_file.write_text('{"pid": 99999, "command": "destroy"}')
        info = LockInfo.from_file(lock_file)
        assert info is not None
        assert info.pid == 99999
        assert info.command == "destroy"

    def test_from_file_invalid_json(self, tmp_path):
        """Test reading invalid JSON returns None."""
        lock_file = tmp_path / "test.lock"
        lock_file.write_text("not valid json")
        info = LockInfo.from_file(lock_file)
        assert info is None

    def test_from_file_empty(self, tmp_path):
        """Test reading empty file returns None."""
        lock_file = tmp_path / "test.lock"
        lock_file.write_text("")
        info = LockInfo.from_file(lock_file)
        assert info is None

    def test_from_file_nonexistent(self, tmp_path):
        """Test reading nonexistent file returns None."""
        nonexistent = tmp_path / "does_not_exist.lock"
        info = LockInfo.from_file(nonexistent)
        assert info is None

    def test_is_process_alive_current_process(self):
        """Test that current process is detected as alive."""
        info = LockInfo(pid=os.getpid(), command="test")
        assert info.is_process_alive() is True

    def test_is_process_alive_dead_process(self):
        """Test that non-existent PID is detected as dead."""
        # Use a very high PID unlikely to exist
        info = LockInfo(pid=9999999, command="test")
        assert info.is_process_alive() is False


class TestOperationLock:
    """Tests for operation_lock context manager."""

    def test_basic_lock_acquire_release(self, temp_lock_file):
        """Test basic lock acquisition and release."""
        with operation_lock("test"):
            # Lock should be held
            assert temp_lock_file.exists()
            content = temp_lock_file.read_text()
            assert str(os.getpid()) in content
            assert "test" in content

    def test_lock_info_cleared_on_exit(self, temp_lock_file):
        """Test lock info is cleared after context exits."""
        with operation_lock("test"):
            pass
        # Lock file should exist but be empty (truncated)
        assert temp_lock_file.exists()
        content = temp_lock_file.read_text()
        assert content == ""

    def test_lock_released_on_exception(self, temp_lock_file):
        """Test lock is released when exception is raised."""
        with pytest.raises(ValueError), operation_lock("test"):
            raise ValueError("test error")

        # Lock should be released - can acquire again immediately
        with operation_lock("test"):
            pass  # Should not raise

    def test_lock_with_empty_command_name(self, temp_lock_file):
        """Test lock with empty command name."""
        with operation_lock(""):
            content = temp_lock_file.read_text()
            assert '"command": ""' in content

    def test_lock_with_special_characters(self, temp_lock_file):
        """Test lock with special characters in command name."""
        with operation_lock("enable-tailscale"):
            content = temp_lock_file.read_text()
            assert "enable-tailscale" in content


class TestConcurrentLock:
    """Tests for concurrent lock behavior using subprocess."""

    def test_concurrent_lock_blocks(self, tmp_path):
        """Test that second process waits for first to release lock."""
        test_lock = tmp_path / "tobcloud.lock"
        results_file = tmp_path / "results.txt"

        # Script that holds lock and logs events
        holder_script = f'''
import sys
import fcntl
import os
import time
lock_path = "{test_lock}"
results_path = "{results_file}"
fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
with open(results_path, "a") as f:
    f.write("first_acquired\\n")
    f.flush()
time.sleep(1)
with open(results_path, "a") as f:
    f.write("first_released\\n")
fcntl.flock(fd, fcntl.LOCK_UN)
os.close(fd)
'''

        waiter_script = f'''
import sys
import fcntl
import os
import time
lock_path = "{test_lock}"
results_path = "{results_file}"
fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)  # Will block until holder releases
with open(results_path, "a") as f:
    f.write("second_acquired\\n")
fcntl.flock(fd, fcntl.LOCK_UN)
os.close(fd)
'''

        # Start holder first
        p1 = subprocess.Popen([sys.executable, "-c", holder_script])
        time.sleep(0.3)  # Let holder acquire lock

        # Start waiter
        p2 = subprocess.Popen([sys.executable, "-c", waiter_script])

        p1.wait(timeout=10)
        p2.wait(timeout=10)

        # Read results
        events = results_file.read_text().strip().split("\n")

        # First should acquire before second
        assert "first_acquired" in events
        assert "second_acquired" in events
        assert events.index("first_acquired") < events.index("second_acquired")

    def test_timeout_raises_lock_error(self, tmp_path):
        """Test that timeout raises LockError."""
        test_lock = tmp_path / "tobcloud.lock"
        ready_file = tmp_path / "ready"

        # Script that holds lock indefinitely until killed
        holder_script = f'''
import fcntl
import os
import time
from pathlib import Path
lock_path = "{test_lock}"
ready_path = "{ready_file}"
fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
Path(ready_path).touch()  # Signal we have the lock
time.sleep(30)  # Hold lock
'''

        p = subprocess.Popen([sys.executable, "-c", holder_script])

        try:
            # Wait for holder to acquire lock
            for _ in range(50):
                if ready_file.exists():
                    break
                time.sleep(0.1)
            else:
                pytest.fail("Holder did not acquire lock in time")

            # Now try to acquire with short timeout
            with patch("tobcloud.lock.LOCK_FILE", test_lock):
                with pytest.raises(LockError) as exc_info:  # noqa: SIM117
                    with operation_lock("waiter", timeout=1):
                        pass

                error_msg = str(exc_info.value)
                assert (
                    "Another tobcloud operation is in progress" in error_msg
                    or "Could not acquire lock" in error_msg
                )
        finally:
            p.terminate()
            p.wait()

    def test_stale_lock_cleanup(self, tmp_path):
        """Test that stale locks from dead processes are handled."""
        test_lock = tmp_path / "tobcloud.lock"
        # Write stale lock info with dead PID
        test_lock.write_text('{"pid": 9999999, "command": "stale"}')

        # Should still be able to acquire lock
        with patch("tobcloud.lock.LOCK_FILE", test_lock), operation_lock("new_command"):
            content = test_lock.read_text()
            assert "new_command" in content


class TestRequiresLockDecorator:
    """Tests for requires_lock decorator."""

    def test_decorator_acquires_lock(self, temp_lock_file):
        """Test decorator acquires and releases lock."""

        @requires_lock("decorated")
        def my_func():
            content = temp_lock_file.read_text()
            assert "decorated" in content
            return "success"

        result = my_func()
        assert result == "success"

    def test_decorator_preserves_metadata(self):
        """Test decorator preserves function metadata."""

        @requires_lock("test")
        def my_function_with_doc():
            """My docstring."""
            pass

        assert my_function_with_doc.__name__ == "my_function_with_doc"
        assert my_function_with_doc.__doc__ == "My docstring."

    def test_decorator_passes_arguments(self, temp_lock_file):
        """Test decorator passes args and kwargs correctly."""

        @requires_lock("test")
        def func_with_args(a, b, c=None):
            return (a, b, c)

        result = func_with_args(1, 2, c=3)
        assert result == (1, 2, 3)

    def test_decorator_handles_lock_error(self, tmp_path):
        """Test decorator handles LockError and exits."""
        import typer

        test_lock = tmp_path / "tobcloud.lock"
        ready_file = tmp_path / "ready"

        # Script that holds lock
        holder_script = f'''
import fcntl
import os
import time
from pathlib import Path
lock_path = "{test_lock}"
ready_path = "{ready_file}"
fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
Path(ready_path).touch()
time.sleep(30)
'''

        p = subprocess.Popen([sys.executable, "-c", holder_script])

        try:
            # Wait for holder to acquire lock
            for _ in range(50):
                if ready_file.exists():
                    break
                time.sleep(0.1)
            else:
                pytest.fail("Holder did not acquire lock in time")

            with (
                patch("tobcloud.lock.LOCK_FILE", test_lock),
                patch("tobcloud.lock.DEFAULT_TIMEOUT", 0.5),
            ):

                @requires_lock("blocked")
                def blocked_func():
                    return "should not reach"

                # Should raise typer.Exit due to LockError
                with pytest.raises(typer.Exit) as exc_info:
                    blocked_func()

                assert exc_info.value.exit_code == 1
        finally:
            p.terminate()
            p.wait()


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_default_timeout_value(self):
        """Test default timeout is 30 seconds."""
        assert DEFAULT_TIMEOUT == 30.0

    def test_lock_file_path(self):
        """Test lock file path is /tmp/tobcloud.lock."""
        assert Path("/tmp/tobcloud.lock") == LOCK_FILE

    def test_lock_file_created_with_permissions(self, tmp_path):
        """Test lock file is created with restrictive permissions."""
        test_lock = tmp_path / "tobcloud.lock"
        with patch("tobcloud.lock.LOCK_FILE", test_lock):
            with operation_lock("test"):
                pass
            # Check permissions (0o600 = owner read/write only)
            mode = test_lock.stat().st_mode & 0o777
            assert mode == 0o600

    def test_multiple_sequential_locks(self, temp_lock_file):
        """Test acquiring lock multiple times sequentially."""
        for i in range(5):
            with operation_lock(f"command_{i}"):
                content = temp_lock_file.read_text()
                assert f"command_{i}" in content
