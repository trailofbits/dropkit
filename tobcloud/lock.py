"""File-based locking to prevent concurrent tobcloud write operations."""

import fcntl
import json
import os
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from functools import wraps
from pathlib import Path

import typer
from rich.console import Console

# Lock file location
LOCK_FILE = Path("/tmp/tobcloud.lock")

# Default timeout for acquiring lock (seconds)
DEFAULT_TIMEOUT = 30.0

# Polling interval when waiting for lock (seconds)
POLL_INTERVAL = 0.5

console = Console()


class LockError(Exception):
    """Raised when lock acquisition fails."""

    pass


class LockInfo:
    """Information about the current lock holder."""

    def __init__(self, pid: int, command: str):
        self.pid = pid
        self.command = command

    @classmethod
    def from_file(cls, lock_file: Path) -> "LockInfo | None":
        """Read lock info from file, returns None if unreadable."""
        try:
            if lock_file.exists():
                content = lock_file.read_text().strip()
                if content:
                    data = json.loads(content)
                    return cls(pid=data.get("pid", 0), command=data.get("command", "unknown"))
        except (json.JSONDecodeError, OSError, KeyError):
            pass
        return None

    def to_json(self) -> str:
        """Serialize lock info to JSON."""
        return json.dumps({"pid": self.pid, "command": self.command})

    def is_process_alive(self) -> bool:
        """Check if the lock holder process is still running."""
        try:
            os.kill(self.pid, 0)  # Signal 0 checks existence without killing
            return True
        except OSError:
            return False


def _write_lock_info(lock_fd: int, command: str) -> None:
    """Write lock holder information to the lock file."""
    info = LockInfo(pid=os.getpid(), command=command)
    content = info.to_json().encode()
    os.ftruncate(lock_fd, 0)
    os.lseek(lock_fd, 0, os.SEEK_SET)
    os.write(lock_fd, content)


def _clear_lock_info(lock_fd: int) -> None:
    """Clear lock holder information (on release)."""
    with suppress(OSError):
        os.ftruncate(lock_fd, 0)


@contextmanager
def operation_lock(
    command: str,
    timeout: float | None = None,
) -> Generator[None, None, None]:
    """
    Context manager that acquires an exclusive lock for tobcloud operations.

    Uses fcntl.flock() which automatically releases the lock when:
    - The context manager exits normally
    - An exception is raised
    - The process crashes or is killed

    Args:
        command: Name of the command acquiring the lock (for debugging)
        timeout: Maximum seconds to wait for lock (default: 30)

    Raises:
        LockError: If lock cannot be acquired within timeout

    Example:
        with operation_lock("create"):
            # Exclusive operation here
            pass
    """
    # Resolve default timeout at runtime (allows patching in tests)
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    # Ensure parent directory exists (should always exist for /tmp)
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Open file for reading and writing (creates if doesn't exist)
    lock_fd = os.open(str(LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o600)

    try:
        start_time = time.monotonic()
        acquired = False

        while time.monotonic() - start_time < timeout:
            try:
                # Try non-blocking exclusive lock
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                # Lock is held by another process, wait and retry
                time.sleep(POLL_INTERVAL)

        if not acquired:
            # Timeout - read lock info for error message
            lock_info = LockInfo.from_file(LOCK_FILE)
            if lock_info and lock_info.is_process_alive():
                raise LockError(
                    f"Another tobcloud operation is in progress.\n"
                    f"  Command: {lock_info.command}\n"
                    f"  PID: {lock_info.pid}\n"
                    f"Wait for it to complete or check if it's stuck."
                )
            else:
                # Stale lock - try one more time (blocking briefly)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except OSError:
                    raise LockError(
                        f"Could not acquire lock after {timeout} seconds.\nLock file: {LOCK_FILE}"
                    )

        # Write lock holder info
        _write_lock_info(lock_fd, command)

        yield  # Execute the protected code

    finally:
        # Clear lock info and release lock
        _clear_lock_info(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def requires_lock(command_name: str):
    """
    Decorator that wraps a function with operation_lock and handles errors.

    Args:
        command_name: Name of the command (for lock info)

    Example:
        @app.command()
        @requires_lock("create")
        def create(...):
            pass
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                with operation_lock(command_name):
                    return func(*args, **kwargs)
            except LockError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)

        return wrapper

    return decorator
