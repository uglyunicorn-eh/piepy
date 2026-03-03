"""Tests for piepy.crypto seal_envelope, open_envelope, and envelope_context."""

import pytest
from pydantic import BaseModel, ValidationError

from piepy.crypto import create_cipher_suite, envelope_context, open_envelope, seal_envelope

TEST_KEY = b"ylQcrQJlfa-BxdTtWZDLpGKZ3X0XwxCuVBeiCG2q06U"


class Payload(BaseModel):
    """Simple schema for tests."""

    message: str
    n: int


class EmptyPayload(BaseModel):
    """Schema with no required fields for empty roundtrip."""

    pass


@pytest.fixture
def key_pair():
    """Derive a deterministic key pair from TEST_KEY."""
    suite = create_cipher_suite()
    return suite.kem.derive_key_pair(TEST_KEY)


def test_seal_envelope_returns_ct_and_enc(key_pair) -> None:
    """seal_envelope returns a dict with base64url 'ct' and 'enc'."""
    data = Payload(message="bar", n=0)
    envelope = seal_envelope(Payload, data, key_pair.public_key)
    assert "ct" in envelope
    assert "enc" in envelope
    assert isinstance(envelope["ct"], str)
    assert isinstance(envelope["enc"], str)


def test_seal_and_open_roundtrip(key_pair) -> None:
    """Data sealed with public key can be opened with private key."""
    data = Payload(message="hello", n=42)
    envelope = seal_envelope(Payload, data, key_pair.public_key)
    opened = open_envelope(Payload, envelope, key_pair.private_key)
    assert opened == data


def test_seal_envelope_different_data_produces_different_ct(key_pair) -> None:
    """Different plaintexts produce different ciphertexts (nonce/enc)."""
    data = Payload(message="a", n=1)
    env1 = seal_envelope(Payload, data, key_pair.public_key)
    env2 = seal_envelope(Payload, data, key_pair.public_key)
    # enc and ct should differ each time (ephemeral key + nonce)
    assert env1["enc"] != env2["enc"] or env1["ct"] != env2["ct"]


def test_seal_envelope_empty_model(key_pair) -> None:
    """seal_envelope accepts empty model and roundtrips."""
    data = EmptyPayload()
    envelope = seal_envelope(EmptyPayload, data, key_pair.public_key)
    opened = open_envelope(EmptyPayload, envelope, key_pair.private_key)
    assert opened == data


def test_open_envelope_wrong_schema_raises_validation_error(key_pair) -> None:
    """open_envelope validates decrypted JSON against schema; wrong shape raises ValidationError."""

    class OtherPayload(BaseModel):
        message: str
        count: int  # sealed payload has "n", not "count"

    data = Payload(message="hello", n=42)
    envelope = seal_envelope(Payload, data, key_pair.public_key)
    with pytest.raises(ValidationError):
        open_envelope(OtherPayload, envelope, key_pair.private_key)


def test_open_envelope_missing_required_field_raises_validation_error(key_pair) -> None:
    """open_envelope raises ValidationError when schema requires a field not in sealed data."""
    data = Payload(message="x", n=1)
    envelope = seal_envelope(Payload, data, key_pair.public_key)

    class StrictPayload(BaseModel):
        message: str
        n: int
        required_extra: str  # not present in sealed data

    with pytest.raises(ValidationError):
        open_envelope(StrictPayload, envelope, key_pair.private_key)


# --- envelope_context tests ---


def test_envelope_context_none_opts_returns_piepy_none() -> None:
    """envelope_context(None) returns context with ~piepy: None."""
    ctx = envelope_context(None)
    assert ctx["~piepy"] is None


def test_envelope_context_empty_opts_returns_piepy_none() -> None:
    """envelope_context(empty dict) returns context with ~piepy: None."""
    ctx = envelope_context({})
    assert ctx["~piepy"] is None


def test_envelope_context_public_key_only_has_seal(key_pair) -> None:
    """envelope_context with only public_key provides seal, no open."""
    ctx = envelope_context({"public_key": key_pair.public_key})
    piepy = ctx["~piepy"]
    assert piepy is not None
    assert "seal" in piepy
    assert "open" not in piepy
    envelope = piepy["seal"](Payload, Payload(message="hi", n=1))
    assert "ct" in envelope and "enc" in envelope


def test_envelope_context_private_key_only_has_open(key_pair) -> None:
    """envelope_context with only private_key provides open, no seal."""
    ctx = envelope_context({"private_key": key_pair.private_key})
    piepy = ctx["~piepy"]
    assert piepy is not None
    assert "open" in piepy
    assert "seal" not in piepy
    envelope = seal_envelope(Payload, Payload(message="hi", n=1), key_pair.public_key)
    opened = piepy["open"](Payload, envelope)
    assert opened == Payload(message="hi", n=1)


def test_envelope_context_both_keys_has_seal_and_open(key_pair) -> None:
    """envelope_context with both keys provides seal and open; roundtrip works."""
    ctx = envelope_context(
        {
            "private_key": key_pair.private_key,
            "public_key": key_pair.public_key,
        }
    )
    piepy = ctx["~piepy"]
    assert piepy is not None
    assert "seal" in piepy
    assert "open" in piepy
    data = Payload(message="roundtrip", n=99)
    envelope = piepy["seal"](Payload, data)
    opened = piepy["open"](Payload, envelope)
    assert opened == data
