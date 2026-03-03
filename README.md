# πpy

[![codecov](https://codecov.io/gh/uglyunicorn-eh/piepy/graph/badge.svg?token=lxB7bhdFhM)](https://codecov.io/gh/uglyunicorn-eh/piepy)

Schema-validated envelopes using HPKE in Python now.

## Installation

Install from a [GitHub Release](https://github.com/uglyunicorn-eh/piepy/releases) (wheel or sdist):

```bash
pip install https://github.com/uglyunicorn-eh/piepy/releases/download/v0.7.1/piepy-0.7.1-py3-none-any.whl
```

Replace the version in the URL with the release you want.

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

## Releasing

Merging a PR into `main` triggers a GitHub Action that builds the package and creates a [GitHub Release](https://github.com/uglyunicorn-eh/piepy/releases) with tag `v{VERSION}` and attached wheel/sdist. Bump the `version` in [pyproject.toml](pyproject.toml) in your PR before merging; the workflow will skip if the tag for that version already exists.

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
```
