"""UI utilities for tobcloud - display functions and prompts."""

from collections.abc import Callable
from typing import Any

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

console = Console()


def display_regions(regions: list[dict[str, Any]]) -> None:
    """Display available regions in a table, sorted alphabetically by slug."""
    table = Table(title="Available Regions", show_header=True)
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Features", style="dim")

    # Sort regions alphabetically by slug
    sorted_regions = sorted(regions, key=lambda r: r.get("slug", ""))

    for region in sorted_regions:
        slug = region.get("slug", "")
        name = region.get("name", "")
        features = ", ".join(region.get("features", [])[:3])  # Show first 3 features
        if len(region.get("features", [])) > 3:
            features += "..."

        table.add_row(slug, name, features)

    console.print(table)


def display_sizes(sizes: list[dict[str, Any]]) -> None:
    """Display available droplet sizes in a table, sorted by price."""
    table = Table(title="Available Droplet Sizes", show_header=True)
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Memory", style="white", justify="right")
    table.add_column("vCPUs", style="white", justify="right")
    table.add_column("Disk", style="white", justify="right")
    table.add_column("Transfer", style="white", justify="right")
    table.add_column("Price/mo", style="green", justify="right")

    # Sort sizes by price (monthly) ascending
    sorted_sizes = sorted(sizes, key=lambda s: s.get("price_monthly", 0))

    for size in sorted_sizes:
        slug = size.get("slug", "")
        memory = f"{size.get('memory', 0)} MB"
        vcpus = str(size.get("vcpus", 0))
        disk = f"{size.get('disk', 0)} GB"
        transfer = f"{size.get('transfer', 0)} TB"
        price = f"${size.get('price_monthly', 0):.2f}"

        table.add_row(slug, memory, vcpus, disk, transfer, price)

    console.print(table)


def display_images(images: list[dict[str, Any]]) -> None:
    """Display available images in a table, sorted by distribution and name."""
    table = Table(title="Available Images", show_header=True)
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Distribution", style="dim")

    # Sort images by distribution, then by name
    sorted_images = sorted(
        images, key=lambda img: (img.get("distribution", ""), img.get("name", ""))
    )

    for image in sorted_images:
        slug = image.get("slug", "")
        name = image.get("name", "")
        distribution = image.get("distribution", "")

        # Only show images with slugs (not snapshots)
        if slug:
            table.add_row(slug, name, distribution)

    console.print(table)


def prompt_with_help(
    prompt_text: str,
    default: str,
    display_func: Callable[[list[dict[str, Any]]], None] | None = None,
    data: list[dict[str, Any]] | None = None,
) -> str:
    """
    Prompt user for input with optional help via '?'.

    Args:
        prompt_text: The prompt to display (without the default/? part)
        default: Default value
        display_func: Function to call when user enters '?'
        data: Data to pass to display_func

    Returns:
        User's input value
    """
    while True:
        value = Prompt.ask(
            f"[cyan]{prompt_text} (? for help)[/cyan]",
            default=default,
        )

        if value == "?":
            if display_func and data is not None:
                console.print()
                display_func(data)
                console.print()
            else:
                console.print("[yellow]No help available[/yellow]")
        else:
            return value
