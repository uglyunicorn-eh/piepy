"""Tests for piepy.utils."""

from piepy.utils import bytes_to_base64url


def test_bytes_to_base64url_empty() -> None:
    """Empty bytes encodes to empty string."""
    assert bytes_to_base64url(b"") == ""


def test_bytes_to_base64url_no_padding() -> None:
    """Bytes whose base64 is a multiple of 4 have no padding; output has no trailing =."""
    assert bytes_to_base64url(b"hello") == "aGVsbG8"


def test_bytes_to_base64url_strips_padding() -> None:
    """Trailing = padding is stripped."""
    assert bytes_to_base64url(b"a") == "YQ"
    assert bytes_to_base64url(b"ab") == "YWI"


def test_bytes_to_base64url_plus_to_minus() -> None:
    """Standard base64 + is replaced with - (base64url)."""
    # b64encode(b'\xfb') -> b'+w==' -> after strip 'Yw' no wait, +w. So + becomes -
    assert bytes_to_base64url(b"\xfb") == "-w"


def test_bytes_to_base64url_slash_to_underscore() -> None:
    """Standard base64 / is replaced with _ (base64url)."""
    # b64encode(b'\xff\xff') -> b'//8=' -> //8
    assert bytes_to_base64url(b"\xff\xff") == "__8"


def test_bytes_to_base64url_binary() -> None:
    """Arbitrary binary encodes to base64url without + or / and no trailing =."""
    data = bytes(range(256))
    out = bytes_to_base64url(data)
    assert "+" not in out
    assert "/" not in out
    assert "=" not in out
    assert isinstance(out, str)
