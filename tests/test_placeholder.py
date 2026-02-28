"""Placeholder test to verify the package imports correctly."""

import piepy


def test_version() -> None:
    """piepy exposes __version__."""
    assert piepy.__version__ == "0.0.1"
