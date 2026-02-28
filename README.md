# πpy

Schema-validated envelopes using HPKE in Python now.

## Installation

```bash
pip install piepy
```

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
# Create virtual environment and install dependencies (including dev)
uv sync

# Run checks
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest  # collects coverage, outputs lcov.info
```
