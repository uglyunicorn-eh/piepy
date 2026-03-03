# πpy

[![codecov](https://codecov.io/gh/uglyunicorn-eh/piepy/graph/badge.svg?token=lxB7bhdFhM)](https://codecov.io/gh/uglyunicorn-eh/piepy)

Schema-validated envelopes using HPKE in Python now.

## Installation

```bash
pip install piepy
```

## Usage

Use the `Envelope` annotation on a Pydantic field to seal (encrypt) or open (decrypt) it depending on context. You need a key pair from the cipher suite; then pass `envelope_context({"public_key": pk})` when validating to seal, or `envelope_context({"private_key": sk})` to open.

```python
from pydantic import BaseModel
from piepy import create_cipher_suite, envelope_context, Envelope

class Identity(BaseModel):
    name: str
    email: str

class Payload(BaseModel):
    identity: Envelope[Identity]

suite = create_cipher_suite()
key_pair = suite.kem.derive_key_pair(b"your-secret-key-material")

# Seal: validate with plain data + public key → field becomes encrypted envelope
ctx_seal = envelope_context({"public_key": key_pair.public_key})
sealed = Payload.model_validate(
    {"identity": {"name": "Alice", "email": "alice@example.com"}},
    context=ctx_seal,
)
# sealed.identity is now {"ct": "...", "enc": "..."}

# Open: validate with envelope + private key → field becomes decrypted Identity
ctx_open = envelope_context({"private_key": key_pair.private_key})
opened = Payload.model_validate(sealed.model_dump(), context=ctx_open)
assert opened.identity == Identity(name="Alice", email="alice@example.com")
```

Without context, `Envelope[T]` fields validate as plain `T` (useful for tests or when encryption is optional).

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
# Create virtual environment and install dependencies (including dev)
uv sync

# Run checks
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest  # collects coverage, outputs lcov.info; requires 100% coverage

# Coverage is uploaded to Codecov on CI. Add CODECOV_TOKEN to GitHub secrets.
```
