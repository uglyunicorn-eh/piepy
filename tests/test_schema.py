"""Tests for piepy.schema Envelope and EnvelopeField."""

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from piepy.crypto import create_cipher_suite, envelope_context, open_envelope, seal_envelope
from piepy.schema import Envelope

TEST_KEY = b"ylQcrQJlfa-BxdTtWZDLpGKZ3X0XwxCuVBeiCG2q06U"


class Payload(BaseModel):
    message: str
    n: int


@pytest.fixture
def key_pair():
    suite = create_cipher_suite()
    return suite.kem.derive_key_pair(TEST_KEY)


# --- Envelope class ---


def test_envelope_class_getitem_returns_annotated() -> None:
    """Envelope[Payload] returns Annotated[Any, EnvelopeField(Payload)]."""
    ann = Envelope[Payload]
    assert getattr(ann, "__metadata__", None) is not None or hasattr(ann, "__origin__")


# --- No context: validate as inner type ---


def test_envelope_field_no_context_validates_as_inner_type() -> None:
    """With no context, Envelope[Payload] validates value as Payload."""
    adapter = TypeAdapter(Envelope[Payload])
    result = adapter.validate_python({"message": "hi", "n": 42})
    assert isinstance(result, Payload)
    assert result.message == "hi"
    assert result.n == 42


def test_envelope_field_no_context_invalid_value_raises() -> None:
    """With no context, invalid value for inner type raises ValidationError."""
    adapter = TypeAdapter(Envelope[Payload])
    with pytest.raises(ValidationError):
        adapter.validate_python({"wrong": "shape"})


def test_envelope_field_context_without_open_or_seal_validates_as_envelope() -> None:
    """With context that has neither open nor seal, value is validated as EnvelopeData."""
    ctx = {"~piepy": {}}
    adapter = TypeAdapter(Envelope[Payload])
    result = adapter.validate_python({"ct": "YQ", "enc": "Yg"}, context=ctx)
    assert result == {"ct": "YQ", "enc": "Yg"}


# --- Context with seal only ---


def test_envelope_field_seal_context_seals_validated_data(key_pair) -> None:
    """With seal-only context, valid inner data is sealed and returns envelope."""
    ctx = envelope_context({"public_key": key_pair.public_key})
    adapter = TypeAdapter(Envelope[Payload])
    result = adapter.validate_python(
        {"message": "secret", "n": 1},
        context=ctx,
    )
    assert isinstance(result, dict)
    assert "ct" in result and "enc" in result


# --- Context with open only ---


def test_envelope_field_open_context_opens_envelope(key_pair) -> None:
    """With open-only context, envelope value is opened and returns inner type."""
    envelope = seal_envelope(Payload, Payload(message="opened", n=99), key_pair.public_key)
    ctx = envelope_context({"private_key": key_pair.private_key})
    adapter = TypeAdapter(Envelope[Payload])
    result = adapter.validate_python(envelope, context=ctx)
    assert isinstance(result, Payload)
    assert result.message == "opened"
    assert result.n == 99


# --- Context with both open and seal (retranslate) ---


def test_envelope_field_both_context_envelope_opens_then_reseals(key_pair) -> None:
    """With both open and seal, envelope is opened then re-sealed (retranslate)."""
    envelope = seal_envelope(Payload, Payload(message="retranslate", n=0), key_pair.public_key)
    ctx = envelope_context({
        "private_key": key_pair.private_key,
        "public_key": key_pair.public_key,
    })
    adapter = TypeAdapter(Envelope[Payload])
    result = adapter.validate_python(envelope, context=ctx)
    assert isinstance(result, dict)
    assert "ct" in result and "enc" in result
    # Re-sealed envelope should open to same payload
    opened = open_envelope(Payload, result, key_pair.private_key)
    assert opened.message == "retranslate"
    assert opened.n == 0


# --- Pre-sealed Identity envelope (decrypt via model) ---

def test_decrypt_encrypted_identity_with_schema(key_pair) -> None:
    """Decrypt the pre-sealed Identity envelope via model definition; assert exact plaintext."""

    class Identity(BaseModel):
        name: str
        email: str

    class PayloadWithIdentity(BaseModel):
        identity: Envelope[Identity]

    decipher_ctx = envelope_context({"private_key": key_pair.private_key})
    payload = PayloadWithIdentity.model_validate(
        {
            "identity": {
                "ct": "aVihXqC2c7z1M1RPA7OohhV8P8u_Cpz8JyhcA9M4_HAjGneSSwYj6nR1auoGzgU7J4Uq6jCk1LHz1KM2HcyQTJct",
                "enc": "BBS9xqkLD5hC0y663NL3INhtC64s3AuwsrIrSjDvitLAGb-EDd-9YRdFa4zJSVYo9P_o5JB2PhUBlY4SjJ3NwNw",
            },
        },
        context=decipher_ctx,
    )
    assert payload.identity == Identity(name="John Doe", email="john.doe@example.com")


# --- UserProfile with Sealed[Identity] and Sealed[str] (via RootModel[str]) ---


def test_user_profile_seal_open_passthrough(key_pair) -> None:
    """UserProfile with Sealed[Identity] and Sealed[str]: seal (encrypt), open (decrypt), no context (passthrough)."""
    class Identity(BaseModel):
        name: str
        email: str

    class UserProfile(BaseModel):
        identity: Envelope[Identity]
        timezone: str

    cipher_ctx = envelope_context({"public_key": key_pair.public_key})
    decipher_ctx = envelope_context({"private_key": key_pair.private_key})

    # Seal (encrypt)
    sealed = UserProfile.model_validate(
        {"identity": {"name": "Alice", "email": "a@b.com"}, "timezone": "UTC"},
        context=cipher_ctx,
    )
    assert "ct" in sealed.identity and "enc" in sealed.identity

    # Open (decrypt)
    opened = UserProfile.model_validate(
        sealed.model_dump(),
        context=decipher_ctx,
    )
    assert opened.identity == Identity(name="Alice", email="a@b.com")
    assert opened.timezone == "UTC"

    # No context → passthrough (useful in tests)
    plain = UserProfile.model_validate(
        {"identity": {"name": "Alice", "email": "a@b.com"}, "timezone": "UTC"},
    )
    assert plain.identity == Identity(name="Alice", email="a@b.com")
    assert plain.timezone == "UTC"
