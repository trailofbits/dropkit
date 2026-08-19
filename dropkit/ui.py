"""UI utilities for dropkit - display functions and prompts."""

import operator
import re
from collections.abc import Callable
from typing import Any

try:
    # Importing readline is what gives input() line editing and history.
    import readline
except ImportError:  # pragma: no cover
    readline = None  # type: ignore[assignment]

from rich.console import Console
from rich.markup import escape
from rich.prompt import Prompt
from rich.table import Table

console = Console()

# Filter field -> key in the API objects, ordered like the size table's columns.
_FILTER_FIELDS: dict[str, str] = {
    "mem": "memory",
    "cpu": "vcpus",
    "disk": "disk",
    "transfer": "transfer",
    "price": "price_monthly",
}

_FILTER_OPS: dict[str, Callable[[Any, Any], bool]] = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
    "=": operator.eq,
}

# Multiplier from a written unit to the API's unit; empty means unitless.
_FIELD_UNITS: dict[str, dict[str, float]] = {
    "memory": {"mb": 1, "gb": 1024, "tb": 1024 * 1024},  # API reports MB
    "disk": {"mb": 1 / 1024, "gb": 1, "tb": 1024},  # API reports GB
    "transfer": {"mb": 1 / (1024 * 1024), "gb": 1 / 1024, "tb": 1},  # API reports TB
    "vcpus": {},
    "price_monthly": {},
}

# Matches 'field op value'; two-character operators come first so '>=' wins.
_FILTER_TERM_RE = re.compile(
    r"(?P<field>[a-z_]+)\s*(?P<op>>=|<=|=|>|<)\s*(?P<value>\S+)",
    re.IGNORECASE,
)

# No slug contains an operator, so input with one is a filter, '?' or not.
_LOOKS_LIKE_FILTER_RE = re.compile(r"[a-z_]+\s*(>=|<=|=|>|<)", re.IGNORECASE)

# Shown above the prompt as a copyable example.
_FILTER_EXAMPLE = "cpu>=4 mem>=16 price<=150"


class FilterError(ValueError):
    """Raised when a '?<filter>' expression cannot be parsed."""


# \001..\002 tells readline the enclosed bytes take up no columns.
_ANSI_ESCAPE_RE = re.compile(r"(\x1b\[[0-9;]*[A-Za-z])")


def _readline_prompt(prompt: Any) -> str:
    """Render a Rich prompt to ANSI, marking escapes zero-width so readline can measure it."""
    with console.capture() as capture:
        console.print(prompt, end="")
    return _ANSI_ESCAPE_RE.sub("\001\\1\002", capture.get())


class EditablePrompt(Prompt):
    """Rich prompt that hands its text to readline, so line editing redraws right."""

    @classmethod
    def get_input(cls, console: Console, prompt: Any, password: bool, stream: Any = None) -> str:
        # Passwords must not echo, and a stream is not a terminal.
        if password or stream is not None or readline is None:
            return super().get_input(console, prompt, password, stream)
        return input(_readline_prompt(prompt))


def _parse_filter_value(field_key: str, raw: str) -> float:
    """Parse a term's value into the API's unit; a bare mem number under 1024 means GB."""
    text = raw.replace(",", "").strip().lower()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([a-z]*)", text)
    if not match:
        raise FilterError(f"'{raw}' is not a number")

    number = float(match.group(1))
    unit = match.group(2)
    units = _FIELD_UNITS[field_key]

    if not unit:
        if field_key == "memory" and number < 1024:
            return number * 1024
        return number

    if unit not in units:
        allowed = " ".join(sorted(units)) if units else "no unit"
        raise FilterError(f"'{raw}' has an invalid unit for this field (use {allowed})")

    return number * units[unit]


def parse_filter(text: str) -> list[tuple[str, str, float]]:
    """
    Parse a filter expression like 'cpu>=4 mem>=16' into ANDed terms.

    Raises:
        FilterError: On an unknown field, a bad value, or unparseable text.
    """
    terms: list[tuple[str, str, float]] = []
    spans: list[tuple[int, int]] = []

    for match in _FILTER_TERM_RE.finditer(text):
        alias = match.group("field").lower()
        if alias not in _FILTER_FIELDS:
            raise FilterError(f"unknown field '{match.group('field')}'")
        key = _FILTER_FIELDS[alias]
        terms.append((key, match.group("op"), _parse_filter_value(key, match.group("value"))))
        spans.append(match.span())

    # Unconsumed text is a typo or a bare word; echo it rather than ignore it.
    leftover = text
    for start, end in reversed(spans):
        leftover = leftover[:start] + leftover[end:]
    if leftover.strip():
        raise FilterError(f"could not parse '{leftover.strip()}'")

    if not terms:
        raise FilterError("filter is empty")

    return terms


def apply_filter(
    rows: list[dict[str, Any]], terms: list[tuple[str, str, float]]
) -> list[dict[str, Any]]:
    """Return the rows satisfying every term; rows with no numeric value are excluded."""
    matched = []
    for row in rows:
        for key, op, value in terms:
            actual = row.get(key)
            if not isinstance(actual, int | float) or isinstance(actual, bool):
                break
            if not _FILTER_OPS[op](actual, value):
                break
        else:
            matched.append(row)
    return matched


def display_regions(regions: list[dict[str, Any]], caption: str | None = None) -> None:
    """Display available regions in a table, sorted alphabetically by slug."""
    table = Table(
        title="Available Regions", show_header=True, caption=caption, caption_justify="left"
    )
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


def display_sizes(sizes: list[dict[str, Any]], caption: str | None = None) -> None:
    """Display available droplet sizes in a table, sorted by price."""
    table = Table(
        title="Available Droplet Sizes", show_header=True, caption=caption, caption_justify="left"
    )
    table.add_column("Slug", style="cyan", no_wrap=True)
    table.add_column("Memory", style="white", justify="right")
    table.add_column("vCPUs", style="white", justify="right")
    table.add_column("Disk", style="white", justify="right")
    table.add_column("Transfer", style="white", justify="right")
    table.add_column("Price/mo", style="green", justify="right")
    table.add_column("Type", style="magenta")

    # Sort sizes by price (monthly) ascending
    sorted_sizes = sorted(sizes, key=lambda s: s.get("price_monthly", 0))

    for size in sorted_sizes:
        slug = size.get("slug", "")
        description = size.get("description", "")
        memory = f"{size.get('memory', 0)} MB"
        vcpus = str(size.get("vcpus", 0))
        disk = f"{size.get('disk', 0)} GB"
        transfer = f"{size.get('transfer', 0)} TB"
        price = f"${size.get('price_monthly', 0):.2f}"

        table.add_row(slug, memory, vcpus, disk, transfer, price, description)

    console.print(table)


def display_images(images: list[dict[str, Any]], caption: str | None = None) -> None:
    """Display available images in a table, sorted by distribution and name."""
    table = Table(
        title="Available Images", show_header=True, caption=caption, caption_justify="left"
    )
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


def display_projects(projects: list[dict[str, Any]], caption: str | None = None) -> None:
    """Display available projects in a table, sorted alphabetically by name."""
    table = Table(
        title="Available Projects", show_header=True, caption=caption, caption_justify="left"
    )
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Name", style="cyan")
    table.add_column("Purpose", style="white")
    table.add_column("Description", style="dim")

    # Sort projects alphabetically by name
    sorted_projects = sorted(projects, key=lambda p: p.get("name", "").lower())

    for project in sorted_projects:
        project_id = project.get("id", "")
        name = project.get("name", "")
        purpose = project.get("purpose", "")
        description = project.get("description", "")

        # Truncate description if too long
        if len(description) > 50:
            description = description[:47] + "..."

        table.add_row(project_id, name, purpose, description)

    console.print(table)


def _filterable_fields(data: list[dict[str, Any]] | None) -> list[str]:
    """Fields present in this data, in table order, so a region prompt offers none."""
    if not data:
        return []
    present = {key for row in data for key in row}
    return [name for name, key in _FILTER_FIELDS.items() if key in present]


def _keyword_reference(fields: list[str]) -> str:
    """Filter vocabulary for the caption under a table, where the eye lands after scrolling."""
    return (
        f"[dim]filter fields:[/dim] {' '.join(fields)}\n"
        f"[dim]operators:[/dim] >= <= > < =\n"
        f"[dim]units:[/dim] gb mb tb"
    )


def prompt_with_help(
    prompt_text: str,
    default: str,
    display_func: Callable[..., None] | None = None,
    data: list[dict[str, Any]] | None = None,
) -> str:
    """
    Prompt for input, where '?' lists the choices and 'cpu>=4 mem>=16' narrows them.

    Filtering only changes what is displayed; the typed value is returned for the
    caller to validate.

    Args:
        prompt_text: The prompt to display (without the default/? part)
        default: Default value
        display_func: Function to call to list choices; must accept a caption kwarg
        data: Data to pass to display_func

    Returns:
        User's input value
    """
    can_list = display_func is not None and data is not None
    fields = _filterable_fields(data) if can_list else []

    if not can_list:
        hint = "? for help"
    elif fields:
        hint = "? to list, ?<filter> to narrow"
        console.print(f"[dim]  narrow with[/dim] ? {_FILTER_EXAMPLE}")
        console.print(f"[dim]  fields:[/dim] {'  '.join(fields)}   [dim]ops:[/dim] >=  <=  >  <  =")
    else:
        hint = "? to list"

    while True:
        value = EditablePrompt.ask(
            f"[cyan]{prompt_text} ({hint})[/cyan]",
            default=default,
        )

        # Without this a missing '?' sends 'mem>16' back as a slug and the caller aborts.
        looks_like_filter = bool(fields) and _LOOKS_LIKE_FILTER_RE.search(value) is not None

        if not value.startswith("?") and not looks_like_filter:
            return value

        if display_func is None or data is None:
            console.print("[yellow]No help available[/yellow]")
            continue

        expression = value.lstrip("?").strip()

        # Bare '?' lists everything, as it always has
        if not expression:
            console.print()
            # The longest table, so the one that most needs the keywords under it.
            unfiltered_caption = None
            if fields:
                unfiltered_caption = (
                    f"{len(data)} shown · ?<filter> to narrow\n{_keyword_reference(fields)}"
                )
            display_func(data, caption=unfiltered_caption)
            console.print()
            continue

        try:
            terms = parse_filter(expression)
        except FilterError as e:
            # escape(): the echoed input may contain Rich markup characters
            console.print(f"[red]Invalid filter:[/red] {escape(str(e))}")
            console.print(f"[dim]  fields:[/dim] {'  '.join(fields)}   [dim]ops:[/dim] >= <= > < =")
            continue

        matches = apply_filter(data, terms)
        if not matches:
            console.print(f"[yellow]No matches for:[/yellow] {escape(expression)}")
            console.print(f"[dim]{len(data)} available · ? to reset[/dim]")
            continue

        console.print()
        caption = f"{len(matches)} of {len(data)} shown · filter: {escape(expression)} · ? to reset"
        if fields:
            caption += f"\n{_keyword_reference(fields)}"
        display_func(matches, caption=caption)
        console.print()
