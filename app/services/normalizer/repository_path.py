"""Validate scanner paths against the clone, preserving repository structure."""

import re
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit


class InvalidFindingPath(ValueError):
    pass


def repository_relative_path(value: str, repo_root: str | Path) -> str:
    if not value or "\x00" in value:
        raise InvalidFindingPath("missing or invalid file path")
    value = value.replace("\\", "/")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value) or value.startswith("//"):
        raise InvalidFindingPath("unsupported URI, drive or network path")
    root = Path(repo_root).absolute()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        # Resolve before collapsing '..' so symlink traversal cannot hide an escape.
        resolved_relative = candidate.resolve().relative_to(root.resolve())
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            # Accept the canonical clone root spelling, never an unrelated symlink
            # outside the clone merely because its target points back inside.
            relative = candidate.relative_to(root.resolve())
    except (ValueError, OSError, RuntimeError) as exc:
        raise InvalidFindingPath("path or symlink escapes repository") from exc
    parts: list[str] = []
    traversed = root
    through_symlink = False
    for part in relative.parts:
        traversed = traversed / part
        try:
            if traversed.is_symlink():
                through_symlink = True
                traversed.resolve(strict=True).relative_to(root.resolve())
            traversed.resolve().relative_to(root.resolve())
        except (ValueError, OSError, RuntimeError) as exc:
            raise InvalidFindingPath("path traverses outside repository") from exc
        if part == "..":
            if not parts:
                raise InvalidFindingPath("relative traversal escapes repository")
            parts.pop()
        elif part != ".":
            parts.append(part)
    if not parts:
        raise InvalidFindingPath("path refers to repository root")
    if through_symlink and ".." in relative.parts:
        if not resolved_relative.parts:
            raise InvalidFindingPath("path refers to repository root")
        return resolved_relative.as_posix()
    return "/".join(parts)


def sarif_artifact_path(artifact: dict, bases: dict) -> str:
    def resolve(location: dict, seen: frozenset[str]) -> str:
        uri = location.get("uri")
        if not isinstance(uri, str) or not uri:
            raise InvalidFindingPath("missing artifact URI (index-only locations unsupported)")
        if any(ord(char) < 32 for char in uri):
            raise InvalidFindingPath("URI contains control characters")
        base_id = location.get("uriBaseId")
        if base_id is not None:
            if not isinstance(base_id, str) or base_id in seen or len(seen) >= 64:
                raise InvalidFindingPath("invalid or cyclic URI base")
            base = bases.get(base_id)
            if not isinstance(base, dict):
                raise InvalidFindingPath("unknown URI base")
            base_uri = resolve(base, seen | {base_id})
            if not urlsplit(base_uri).scheme or not base_uri.endswith("/"):
                raise InvalidFindingPath("URI base requires an absolute directory URI")
            uri = urljoin(base_uri, uri)
        return uri

    try:
        uri = resolve(artifact, frozenset())
        parsed = urlsplit(uri)
    except ValueError as exc:
        raise InvalidFindingPath(str(exc)) from exc
    if parsed.scheme not in ("", "file") or parsed.netloc not in ("", "localhost"):
        raise InvalidFindingPath("unsupported URI scheme or authority")
    if parsed.query or parsed.fragment or (parsed.scheme == "file" and not parsed.path.startswith("/")):
        raise InvalidFindingPath("unsupported URI query, fragment or relative file URI")
    if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path):
        raise InvalidFindingPath("malformed URI percent encoding")
    try:
        return unquote(parsed.path, encoding="utf-8", errors="strict")
    except UnicodeError as exc:
        raise InvalidFindingPath("invalid URI UTF-8 encoding") from exc
