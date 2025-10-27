"""DigitalOcean API client using raw REST API calls."""

import re
from typing import Any

import requests


class DigitalOceanAPIError(Exception):
    """Exception raised for DigitalOcean API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)


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
        Sanitize email address to create a valid username.

        Removes @trailofbits.com suffix and replaces special characters.

        Args:
            email: Email address from DigitalOcean account

        Returns:
            Sanitized username suitable for Linux user creation
        """
        # Remove @trailofbits.com suffix (case insensitive)
        username = re.sub(r"@trailofbits\.com$", "", email, flags=re.IGNORECASE)

        # If no @trailofbits.com, just take the part before @
        if "@" in username:
            username = username.split("@")[0]

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
    ) -> list[dict[str, Any]]:
        """
        Fetch all pages of a paginated API endpoint.

        Args:
            endpoint: API endpoint to fetch
            key: Key in response containing the items (e.g., 'regions', 'sizes')
            per_page: Number of items per page (default 200, max 200)

        Returns:
            List of all items across all pages
        """
        all_items = []
        page = 1

        while True:
            params = {"page": page, "per_page": per_page}
            response = self._request("GET", endpoint, params=params)

            items = response.get(key, [])
            all_items.extend(items)

            # Check if there are more pages
            links = response.get("links", {})
            pages = links.get("pages", {})

            # If there's no "next" link, we're done
            if "next" not in pages:
                break

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
            return self._get_paginated(f"/images?type={image_type}", "images")

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
        """
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
            # Use tag-based filtering
            return self._get_paginated(f"/droplets?tag_name={tag_name}", "droplets")
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
            DigitalOceanAPIError: If timeout is reached or droplet enters error state
        """
        import time

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
            DigitalOceanAPIError: If update fails
        """
        payload = {"name": name}
        response = self._request("PUT", f"/account/keys/{key_id}", json=payload)
        return response.get("ssh_key", {})

    def delete_ssh_key(self, key_id: int) -> None:
        """
        Delete an SSH key from the account.

        Args:
            key_id: The SSH key ID to delete

        Raises:
            DigitalOceanAPIError: If deletion fails
        """
        self._request("DELETE", f"/account/keys/{key_id}")

    def delete_droplet(self, droplet_id: int) -> None:
        """
        Delete a droplet by ID.

        Args:
            droplet_id: Droplet ID to delete

        Raises:
            DigitalOceanAPIError: If deletion fails
        """
        self._request("DELETE", f"/droplets/{droplet_id}")

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
            DigitalOceanAPIError: If resize fails
        """
        payload = {
            "type": "resize",
            "size": size,
            "disk": disk,
        }

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
            DigitalOceanAPIError: If request fails
        """
        response = self._request("GET", f"/actions/{action_id}")
        return response.get("action", {})

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
            DigitalOceanAPIError: If timeout is reached or action enters error state
        """
        import time

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
