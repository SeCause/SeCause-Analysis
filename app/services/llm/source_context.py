"""Read bounded source context from the checked-out repository."""

from dataclasses import dataclass
from pathlib import Path

from app.services.normalizer.repository_path import InvalidFindingPath, repository_relative_path


@dataclass(frozen=True)
class SourceContext:
    text: str | None
    reason: str | None = None
    finding_code: str | None = None


def read_source_context(
    repo_root: str | Path,
    file_path: str,
    line_start: int | None,
    line_end: int | None = None,
    *,
    surrounding_lines: int = 15,
    max_file_bytes: int = 256 * 1024,
    max_chars: int = 6000,
) -> SourceContext:
    """Return numbered lines, or a reason without leaking file contents to logs."""
    if surrounding_lines < 0 or max_file_bytes <= 0 or max_chars <= 0:
        raise ValueError("Source context limits must be positive (surrounding_lines may be zero)")
    if line_start is None or line_start < 1 or (line_end is not None and line_end < line_start):
        return SourceContext(None, "invalid_line_range")
    try:
        relative = repository_relative_path(file_path, repo_root)
        path = (Path(repo_root) / relative).resolve(strict=True)
        path.relative_to(Path(repo_root).resolve(strict=True))
        if not path.is_file():
            return SourceContext(None, "not_regular_file")
        if path.stat().st_size > max_file_bytes:
            return SourceContext(None, "file_too_large")
        with path.open("rb") as source:
            data = source.read(max_file_bytes + 1)
        if len(data) > max_file_bytes:
            return SourceContext(None, "file_too_large")
        if b"\x00" in data:
            return SourceContext(None, "binary_file")
        lines = data.decode("utf-8-sig").splitlines()
    except UnicodeError:
        return SourceContext(None, "unsupported_encoding")
    except (InvalidFindingPath, ValueError, RuntimeError):
        return SourceContext(None, "invalid_path")
    except OSError:
        return SourceContext(None, "file_unavailable")
    end = line_end if line_end is not None else line_start
    if end > len(lines):
        return SourceContext(None, "invalid_line_range")

    # Prefix lengths let us measure any contiguous window in constant time.
    first = max(1, line_start - surrounding_lines)
    last = min(len(lines), end + surrounding_lines)
    lengths = [0]
    for number in range(first, last + 1):
        lengths.append(lengths[-1] + len(str(number)) + 3 + len(lines[number - 1]) + 1)

    def window_chars(left: int, right: int) -> int:
        return lengths[right - first + 1] - lengths[left - first] - 1

    # Never drop part of the finding just to fit surrounding context.
    if window_chars(line_start, end) > max_chars:
        return SourceContext(None, "finding_range_too_long")

    left, right = first, last
    while window_chars(left, right) > max_chars:
        # Remove the farthest surrounding line; keep a single continuous window.
        if line_start - left >= right - end and left < line_start:
            left += 1
        else:
            right -= 1

    text = "\n".join(f"{number} | {lines[number - 1]}" for number in range(left, right + 1))
    finding_code = "\n".join(lines[line_start - 1:end])
    return SourceContext(text, "truncated" if (left, right) != (first, last) else None, finding_code)
