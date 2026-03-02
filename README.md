# πpy

[![codecov](https://codecov.io/gh/uglyunicorn-eh/piepy/graph/badge.svg?token=lxB7bhdFhM)](https://codecov.io/gh/uglyunicorn-eh/piepy)

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
uv run pytest  # collects coverage, outputs lcov.info; requires 100% coverage

# Coverage is uploaded to Codecov on CI. Add CODECOV_TOKEN to GitHub secrets.
```
