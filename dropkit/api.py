"""DigitalOcean API client using raw REST API calls.

API Reference
=============

Base URL: https://api.digitalocean.com/v2
Auth: Authorization: Bearer <token>

Key Endpoints
-------------

Account & SSH Keys:
    GET  /account                       Account info (includes email for username)
    GET  /account/keys                  List SSH keys (paginated)
    GET  /account/keys/{fingerprint}    Get SSH key by fingerprint
    POST /account/keys                  Add new SSH key
    PUT  /account/keys/{id}             Update SSH key name
    DELETE /account/keys/{id}           Delete SSH key

Droplets:
    POST   /droplets                    Create droplet
    GET    /droplets                    List droplets
    GET    /droplets?tag_name=X         Filter by tag
    GET    /droplets/{id}               Get droplet info
    DELETE /droplets/{id}               Delete droplet
    POST   /droplets/{id}/actions       Perform action (resize, power_on, power_off, snapshot)

Metadata:
    GET /regions                        List regions (paginated)
    GET /sizes                          List droplet sizes (paginated)
    GET /images                         List images (paginated)

Actions:
    GET /actions/{id}                   Check action status

Projects:
    GET  /projects                      List projects (paginated)
    GET  /projects/{project_id}         Get project by UUID
    GET  /projects/default              Get default project
    POST /projects/{project_id}/resources   Assign resources (body: {"resources": ["do:droplet:123"]})

Snapshots:
    GET    /snapshots                   List snapshots (filter: resource_type=droplet)
    GET    /snapshots/{id}              Get snapshot
    DELETE /snapshots/{id}              Delete snapshot

Tags:
    POST /tags                          Create tag
    POST /tags/{name}/resources         Tag a resource

Pagination
----------
Uses `page` and `per_page` query params (max 200/page).
This module auto-handles pagination by following `links.pages.next` URLs.
"""

import re
from typing import Any

import requests


class DigitalOceanAPIError(Exception):
    """Exception raised for DigitalOcean API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)


PROTECTED_TAGS = {"owner", "firewall"}


class DigitalOceanAPI:
    """Client for DigitalOcean REST API."""

    def __init__(self, token: str):
        """Initialize API client with authentication token."""
        self.token = token
        self.base_url = "https://api.digitalocean.com/v2"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        )

    def get_account(self) -> dict[str, Any]:
        """
        Get account information.

        Returns:
            Account object with details like email, droplet_limit, status, etc.
        """
        response = self._request("GET", "/account")
        return response.get("account", {})

    def get_username(self) -> str:
        """
        Get username from DigitalOcean account email.

        Fetches the account information and sanitizes the email address
        to create a valid Linux username.

        Returns:
            Sanitized username from DigitalOcean account

        Raises:
            DigitalOceanAPIError: If account email cannot be fetched or is empty
        """
        account = self.get_account()
        email = account.get("email", "")

        if not email:
            raise DigitalOceanAPIError("No email found in DigitalOcean account")

        return self._sanitize_email_for_username(email)

    @staticmethod
    def _sanitize_email_for_username(email: str) -> str:
        """
        Sanitize email address to create a valid Linux username.

        Extracts the local part (before @) and replaces special characters
        with underscores. Ensures the result is a valid Linux username.

        Args:
            email: Email address from DigitalOcean account

        Returns:
            Sanitized username suitable for Linux user creation
        """
        # Extract local part (before @)
        username = email.split("@")[0]

        # Replace dots, hyphens, and other special characters with underscores
        username = re.sub(r"[^a-z0-9_]", "_", username.lower())

        # Remove leading/trailing underscores
        username = username.strip("_")

        # Ensure it starts with a letter (Linux username requirement)
        if username and not username[0].isalpha():
            username = "u" + username

        # Fallback if sanitization results in empty string
        if not username:
            username = "user"

        return username

    @staticmethod
    def _validate_positive_int(value: int, name: str) -> None:
        """
        Validate that an integer ID is positive.

        Args:
            value: The integer to validate
            name: Name of the parameter (for error message)

        Raises:
            ValueError: If the value is not positive
        """
        if value <= 0:
            raise ValueError(f"{name} must be a positive integer, got: {value}")

    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Make an API request."""
        url = f"{self.base_url}{endpoint}"

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            if response.status_code == 204 and response.text == "":
                return {}

            return response.json()
        except requests.exceptions.HTTPError as e:
            error_msg = f"API request failed: {e}"
            if e.response is not None:
                try:
                    error_data = e.response.json()
                    if "message" in error_data:
                        error_msg = f"API error: {error_data['message']}"
                except ValueError:
                    pass
                raise DigitalOceanAPIError(error_msg, e.response.status_code)
            raise DigitalOceanAPIError(error_msg) from e
        except requests.exceptions.RequestException as e:
            raise DigitalOceanAPIError(f"Network error: {e}") from e

    def _get_paginated(
        self,
        endpoint: str,
        key: str,
        per_page: int = 200,
        extra_params: dict[str, str] | None = None,
        max_pages: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Fetch all pages of a paginated API endpoint.

        Args:
            endpoint: API endpoint to fetch
            key: Key in response containing the items (e.g., 'regions', 'sizes')
            per_page: Number of items per page (default 200, max 200)
            extra_params: Additional query parameters to include (safely encoded)
            max_pages: Maximum number of pages to fetch (default 1000, prevents DoS)

        Returns:
            List of all items across all pages

        Raises:
            DigitalOceanAPIError: If max_pages limit is reached
        """
        all_items = []
        page = 1

        while True:
            # Build params dict safely
            params: dict[str, str | int] = {"page": page, "per_page": per_page}
            if extra_params:
                params.update(extra_params)

            response = self._request("GET", endpoint, params=params)

            items = response.get(key, [])
            all_items.extend(items)

            # Check if there are more pages
            links = response.get("links", {})
            pages = links.get("pages", {})

            # If there's no "next" link, we're done
            if "next" not in pages:
                break

            # Safety: prevent infinite pagination
            if page >= max_pages:
                raise DigitalOceanAPIError(
                    f"Pagination limit reached: {max_pages} pages. "
                    "This may indicate an API issue or misconfiguration."
                )

            page += 1

        return all_items

    def get_regions(self) -> list[dict[str, Any]]:
        """
        Fetch all available regions (handles pagination).

        Returns:
            List of region objects with slug, name, available, features, etc.
        """
        return self._get_paginated("/regions", "regions")

    def get_sizes(self) -> list[dict[str, Any]]:
        """
        Fetch all available droplet sizes (handles pagination).

        Returns:
            List of size objects with slug, memory, vcpus, disk, price, etc.
        """
        return self._get_paginated("/sizes", "sizes")

    def get_available_regions(self) -> list[dict[str, Any]]:
        """Get only available regions."""
        regions = self.get_regions()
        return [r for r in regions if r.get("available", False)]

    def get_available_sizes(self) -> list[dict[str, Any]]:
        """Get only available sizes."""
        sizes = self.get_sizes()
        return [s for s in sizes if s.get("available", False)]

    def get_images(self, image_type: str = "distribution") -> list[dict[str, Any]]:
        """
        Fetch all available images (handles pagination).

        Args:
            image_type: Filter by image type ('distribution', 'application', or 'all')

        Returns:
            List of image objects with slug, name, distribution, etc.
        """
        if image_type == "all":
            return self._get_paginated("/images", "images")
        else:
            # Use extra_params to safely pass query parameters
            return self._get_paginated("/images", "images", extra_params={"type": image_type})

    def get_available_images(self, image_type: str = "distribution") -> list[dict[str, Any]]:
        """
        Get only available distribution images.

        Args:
            image_type: Filter by image type ('distribution', 'application', or 'all')

        Returns:
            List of available image objects
        """
        images = self.get_images(image_type)
        # Filter for public images that are available
        return [
            img for img in images if img.get("public", False) and img.get("status") == "available"
        ]

    def create_droplet(
        self,
        name: str,
        region: str,
        size: str,
        image: str,
        user_data: str,
        tags: list[str],
        ssh_keys: list[int] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new droplet.

        Args:
            name: Droplet name
            region: Region slug (e.g., 'nyc3')
            size: Size slug (e.g., 's-2vcpu-4gb')
            image: Image slug (e.g., 'ubuntu-25-04-x64')
            user_data: Cloud-init user data
            tags: List of tags to apply
            ssh_keys: List of SSH key IDs for root access (optional)

        Returns:
            Droplet object from API response
        """
        payload: dict[str, Any] = {
            "name": name,
            "region": region,
            "size": size,
            "image": image,
            "user_data": user_data,
            "tags": tags,
        }

        if ssh_keys:
            payload["ssh_keys"] = ssh_keys

        response = self._request("POST", "/droplets", json=payload)
        return response.get("droplet", {})

    def get_droplet(self, droplet_id: int) -> dict[str, Any]:
        """
        Get droplet information by ID.

        Args:
            droplet_id: Droplet ID

        Returns:
            Droplet object

        Raises:
            ValueError: If droplet_id is not positive
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        response = self._request("GET", f"/droplets/{droplet_id}")
        return response.get("droplet", {})

    def list_droplets(self, tag_name: str | None = None) -> list[dict[str, Any]]:
        """
        List all droplets, optionally filtered by tag.

        Args:
            tag_name: Optional tag to filter by (e.g., 'owner:myname')

        Returns:
            List of droplet objects
        """
        if tag_name:
            # Use tag-based filtering with safe parameter encoding
            return self._get_paginated("/droplets", "droplets", extra_params={"tag_name": tag_name})
        else:
            # Get all droplets
            return self._get_paginated("/droplets", "droplets")

    def wait_for_droplet_active(
        self,
        droplet_id: int,
        timeout: int = 300,
        poll_interval: int = 5,
    ) -> dict[str, Any]:
        """
        Wait for droplet to become active.

        Args:
            droplet_id: Droplet ID
            timeout: Maximum time to wait in seconds (default 300)
            poll_interval: Time between polls in seconds (default 5)

        Returns:
            Final droplet object

        Raises:
            ValueError: If droplet_id is not positive
            DigitalOceanAPIError: If timeout is reached or droplet enters error state
        """
        import time

        self._validate_positive_int(droplet_id, "droplet_id")
        start_time = time.time()

        while True:
            droplet = self.get_droplet(droplet_id)
            status = droplet.get("status", "")

            if status == "active":
                return droplet
            elif status == "error":
                raise DigitalOceanAPIError(
                    f"Droplet entered error state: {droplet.get('name', droplet_id)}"
                )

            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise DigitalOceanAPIError(
                    f"Timeout waiting for droplet to become active (waited {elapsed:.0f}s)"
                )

            time.sleep(poll_interval)

    def list_ssh_keys(self) -> list[dict[str, Any]]:
        """
        List all SSH keys in the account.

        Returns:
            List of SSH key objects with id, fingerprint, public_key, name
        """
        return self._get_paginated("/account/keys", "ssh_keys")

    def get_ssh_key_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        """
        Get SSH key by fingerprint.

        Args:
            fingerprint: SSH key fingerprint (MD5 format: aa:bb:cc:...)

        Returns:
            SSH key object if found, None if not found
        """
        try:
            response = self._request("GET", f"/account/keys/{fingerprint}")
            return response.get("ssh_key", {})
        except DigitalOceanAPIError as e:
            # 404 means key doesn't exist
            if e.status_code == 404:
                return None
            raise

    def add_ssh_key(self, name: str, public_key: str) -> dict[str, Any]:
        """
        Add a new SSH key to the account.

        Args:
            name: Name for the SSH key
            public_key: The full SSH public key content

        Returns:
            SSH key object from API response
        """
        payload = {
            "name": name,
            "public_key": public_key,
        }

        response = self._request("POST", "/account/keys", json=payload)
        return response.get("ssh_key", {})

    def update_ssh_key(self, key_id: int, name: str) -> dict[str, Any]:
        """
        Update an SSH key name.

        Args:
            key_id: The SSH key ID to update
            name: New name for the SSH key

        Returns:
            Updated SSH key object from API response

        Raises:
            ValueError: If key_id is not positive
            DigitalOceanAPIError: If update fails
        """
        self._validate_positive_int(key_id, "key_id")
        payload = {"name": name}
        response = self._request("PUT", f"/account/keys/{key_id}", json=payload)
        return response.get("ssh_key", {})

    def delete_ssh_key(self, key_id: int) -> None:
        """
        Delete an SSH key from the account.

        Args:
            key_id: The SSH key ID to delete

        Raises:
            ValueError: If key_id is not positive
            DigitalOceanAPIError: If deletion fails
        """
        self._validate_positive_int(key_id, "key_id")
        self._request("DELETE", f"/account/keys/{key_id}")

    def delete_droplet(self, droplet_id: int) -> None:
        """
        Delete a droplet by ID.

        Args:
            droplet_id: Droplet ID to delete

        Raises:
            ValueError: If droplet_id is not positive
            DigitalOceanAPIError: If deletion fails
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        self._request("DELETE", f"/droplets/{droplet_id}")

    def rename_droplet(self, droplet_id: int, new_name: str) -> dict[str, Any]:
        """
        Rename a droplet.

        Args:
            droplet_id: Droplet ID
            new_name: New name for the droplet

        Returns:
            Action object with id, status, etc.

        Raises:
            ValueError: If droplet_id is not positive
            DigitalOceanAPIError: If rename fails
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        payload = {"type": "rename", "name": new_name}
        response = self._request("POST", f"/droplets/{droplet_id}/actions", json=payload)
        return response.get("action", {})

    def resize_droplet(self, droplet_id: int, size: str, disk: bool = True) -> dict[str, Any]:
        """
        Resize a droplet (requires power off, causes downtime).

        Args:
            droplet_id: Droplet ID
            size: New size slug (e.g., 's-4vcpu-8gb')
            disk: Whether to resize disk (permanent, cannot be undone). Default: True

        Returns:
            Action object with id, status, etc.

        Raises:
            ValueError: If droplet_id is not positive
            DigitalOceanAPIError: If resize fails
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        payload = {
            "type": "resize",
            "size": size,
            "disk": disk,
        }

        response = self._request("POST", f"/droplets/{droplet_id}/actions", json=payload)
        return response.get("action", {})

    def power_on_droplet(self, droplet_id: int) -> dict[str, Any]:
        """
        Power on a droplet.

        Args:
            droplet_id: Droplet ID

        Returns:
            Action object with id, status, etc.

        Raises:
            ValueError: If droplet_id is not positive
            DigitalOceanAPIError: If power on fails
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        payload = {"type": "power_on"}
        response = self._request("POST", f"/droplets/{droplet_id}/actions", json=payload)
        return response.get("action", {})

    def power_off_droplet(self, droplet_id: int) -> dict[str, Any]:
        """
        Power off a droplet.

        Args:
            droplet_id: Droplet ID

        Returns:
            Action object with id, status, etc.

        Raises:
            ValueError: If droplet_id is not positive
            DigitalOceanAPIError: If power off fails
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        payload = {"type": "power_off"}
        response = self._request("POST", f"/droplets/{droplet_id}/actions", json=payload)
        return response.get("action", {})

    def get_action(self, action_id: int) -> dict[str, Any]:
        """
        Get action status by ID.

        Args:
            action_id: Action ID

        Returns:
            Action object with id, status, type, etc.

        Raises:
            ValueError: If action_id is not positive
            DigitalOceanAPIError: If request fails
        """
        self._validate_positive_int(action_id, "action_id")
        response = self._request("GET", f"/actions/{action_id}")
        return response.get("action", {})

    def list_droplet_actions(self, droplet_id: int) -> list[dict[str, Any]]:
        """
        List all actions for a droplet.

        Args:
            droplet_id: Droplet ID

        Returns:
            List of action objects (most recent first)

        Raises:
            ValueError: If droplet_id is not positive
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        return self._get_paginated(f"/droplets/{droplet_id}/actions", "actions")

    def wait_for_action_complete(
        self,
        action_id: int,
        timeout: int = 300,
        poll_interval: int = 5,
    ) -> dict[str, Any]:
        """
        Wait for action to complete.

        Args:
            action_id: Action ID
            timeout: Maximum time to wait in seconds (default 300)
            poll_interval: Time between polls in seconds (default 5)

        Returns:
            Final action object

        Raises:
            ValueError: If action_id is not positive
            DigitalOceanAPIError: If timeout is reached or action enters error state
        """
        import time

        self._validate_positive_int(action_id, "action_id")
        start_time = time.time()

        while True:
            action = self.get_action(action_id)
            status = action.get("status", "")

            if status == "completed":
                return action
            elif status == "errored":
                raise DigitalOceanAPIError(
                    f"Action failed: {action.get('type', 'unknown')} (ID: {action_id})"
                )

            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise DigitalOceanAPIError(
                    f"Timeout waiting for action to complete (waited {elapsed:.0f}s)"
                )

            time.sleep(poll_interval)

    def list_projects(self) -> list[dict[str, Any]]:
        """
        List all projects in the account.

        Returns:
            List of project objects with id, name, description, purpose, etc.
        """
        return self._get_paginated("/projects", "projects")

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        """
        Get a specific project by ID.

        Args:
            project_id: Project UUID

        Returns:
            Project object if found, None if not found (404)

        Raises:
            DigitalOceanAPIError: If request fails (non-404 errors)
        """
        try:
            response = self._request("GET", f"/projects/{project_id}")
            return response.get("project", {})
        except DigitalOceanAPIError as e:
            # 404 means project doesn't exist
            if e.status_code == 404:
                return None
            raise

    def get_default_project(self) -> dict[str, Any] | None:
        """
        Get the default project for the account.

        Returns:
            Project object if default project exists, None if not found

        Raises:
            DigitalOceanAPIError: If request fails (non-404 errors)
        """
        try:
            response = self._request("GET", "/projects/default")
            return response.get("project", {})
        except DigitalOceanAPIError as e:
            # 404 means no default project
            if e.status_code == 404:
                return None
            raise

    def assign_resources_to_project(
        self, project_id: str, resource_urns: list[str]
    ) -> dict[str, Any]:
        """
        Assign resources to a project.

        Args:
            project_id: Project UUID
            resource_urns: List of resource URNs (e.g., ["do:droplet:12345"])

        Returns:
            Response with assigned resources

        Raises:
            DigitalOceanAPIError: If assignment fails
        """
        payload = {"resources": resource_urns}
        response = self._request("POST", f"/projects/{project_id}/resources", json=payload)
        return response

    @staticmethod
    def get_droplet_urn(droplet_id: int) -> str:
        """
        Get the URN (Uniform Resource Name) for a droplet.

        Args:
            droplet_id: Droplet ID

        Returns:
            URN string in format "do:droplet:{id}"
        """
        return f"do:droplet:{droplet_id}"

    # Snapshot methods

    def create_snapshot(self, droplet_id: int, name: str) -> dict[str, Any]:
        """
        Create a snapshot of a droplet.

        Args:
            droplet_id: Droplet ID to snapshot
            name: Name for the snapshot

        Returns:
            Action object with id, status, etc.

        Raises:
            ValueError: If droplet_id is not positive
            DigitalOceanAPIError: If snapshot creation fails
        """
        self._validate_positive_int(droplet_id, "droplet_id")
        payload = {
            "type": "snapshot",
            "name": name,
        }
        response = self._request("POST", f"/droplets/{droplet_id}/actions", json=payload)
        return response.get("action", {})

    def list_snapshots(self, tag: str | None = None) -> list[dict[str, Any]]:
        """
        List snapshots, optionally filtered by tag.

        Args:
            tag: Optional tag to filter by (e.g., 'owner:myname')

        Returns:
            List of snapshot objects
        """
        extra_params: dict[str, str] = {"resource_type": "droplet"}
        if tag:
            extra_params["tag_name"] = tag
        return self._get_paginated("/snapshots", "snapshots", extra_params=extra_params)

    def get_snapshot(self, snapshot_id: int) -> dict[str, Any] | None:
        """
        Get a snapshot by ID.

        Args:
            snapshot_id: Snapshot ID

        Returns:
            Snapshot object if found, None if not found (404)

        Raises:
            ValueError: If snapshot_id is not positive
            DigitalOceanAPIError: If request fails (non-404 errors)
        """
        self._validate_positive_int(snapshot_id, "snapshot_id")
        try:
            response = self._request("GET", f"/snapshots/{snapshot_id}")
            return response.get("snapshot", {})
        except DigitalOceanAPIError as e:
            if e.status_code == 404:
                return None
            raise

    def get_snapshot_by_name(self, name: str, tag: str | None = None) -> dict[str, Any] | None:
        """
        Find a snapshot by exact name.

        Args:
            name: Exact snapshot name to search for
            tag: Optional tag to filter by

        Returns:
            Snapshot object if found, None if not found
        """
        snapshots = self.list_snapshots(tag=tag)
        for snapshot in snapshots:
            if snapshot.get("name") == name:
                return snapshot
        return None

    def delete_snapshot(self, snapshot_id: int) -> None:
        """
        Delete a snapshot by ID.

        Args:
            snapshot_id: Snapshot ID to delete

        Raises:
            ValueError: If snapshot_id is not positive
            DigitalOceanAPIError: If deletion fails
        """
        self._validate_positive_int(snapshot_id, "snapshot_id")
        self._request("DELETE", f"/snapshots/{snapshot_id}")

    def tag_resource(self, tag_name: str, resource_id: str, resource_type: str) -> None:
        """
        Add a tag to a resource.

        Args:
            tag_name: Tag name to apply
            resource_id: Resource ID (string for snapshots/images)
            resource_type: Resource type ('image' for snapshots, 'droplet', etc.)

        Raises:
            DigitalOceanAPIError: If tagging fails
        """
        payload = {"resources": [{"resource_id": resource_id, "resource_type": resource_type}]}
        self._request("POST", f"/tags/{tag_name}/resources", json=payload)

    def untag_resource(self, tag_name: str, resource_id: str, resource_type: str) -> None:
        """
        Remove a tag from a resource.

        Args:
            tag_name: Tag name to remove
            resource_id: Resource ID (string for snapshots/images)
            resource_type: Resource type ('image' for snapshots, 'droplet', etc.)

        Raises:
            ValueError: If tag is protected (owner or firewall)
            DigitalOceanAPIError: If untagging fails
        """
        if tag_name.split(":")[0] in PROTECTED_TAGS:
            raise ValueError(f"Cannot remove protected tag: {tag_name}")
        payload = {"resources": [{"resource_id": resource_id, "resource_type": resource_type}]}
        self._request("DELETE", f"/tags/{tag_name}/resources", json=payload)

    def create_tag(self, tag_name: str) -> dict[str, Any]:
        """
        Create a tag if it doesn't exist.

        Args:
            tag_name: Tag name to create

        Returns:
            Tag object from API response

        Raises:
            DigitalOceanAPIError: If creation fails (ignores 422 for existing tags)
        """
        payload = {"name": tag_name}
        try:
            response = self._request("POST", "/tags", json=payload)
            return response.get("tag", {})
        except DigitalOceanAPIError as e:
            # 422 means tag already exists, which is fine
            if e.status_code == 422:
                return {"name": tag_name}
            raise

    def create_droplet_from_snapshot(
        self,
        name: str,
        region: str,
        size: str,
        snapshot_id: int,
        tags: list[str],
        ssh_keys: list[int] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new droplet from a snapshot image.

        Args:
            name: Droplet name
            region: Region slug (e.g., 'nyc3')
            size: Size slug (e.g., 's-2vcpu-4gb')
            snapshot_id: Snapshot ID to restore from
            tags: List of tags to apply
            ssh_keys: List of SSH key IDs for root access (optional)

        Returns:
            Droplet object from API response

        Raises:
            ValueError: If snapshot_id is not positive
            DigitalOceanAPIError: If droplet creation fails
        """
        self._validate_positive_int(snapshot_id, "snapshot_id")
        payload: dict[str, Any] = {
            "name": name,
            "region": region,
            "size": size,
            "image": snapshot_id,  # Snapshot ID as the image
            "tags": tags,
        }

        if ssh_keys:
            payload["ssh_keys"] = ssh_keys

        response = self._request("POST", "/droplets", json=payload)
        return response.get("droplet", {})
