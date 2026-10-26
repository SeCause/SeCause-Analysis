"""Token comparison without configuration or HTTP policy dependencies."""

import hmac


def internal_token_matches(provided: str | None, configured: str) -> bool:
    """Compare UTF-8 tokens in constant time; callers decide missing-config policy."""
    return provided is not None and hmac.compare_digest(
        provided.encode("utf-8"), configured.encode("utf-8"),
    )
