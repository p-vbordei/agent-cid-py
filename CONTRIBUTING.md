# Contributing

Thanks for the interest. This is a port — the contract lives in the [TypeScript reference](https://github.com/p-vbordei/agent-cid).

## Dev setup

```bash
git clone https://github.com/p-vbordei/agent-cid-py
cd agent-cid-py
uv sync --extra dev
uv run pytest -v
uv run ruff check src tests
```

Optional type check:

```bash
uv run mypy src
```

## What can change here vs. upstream

- **Wire format is fixed.** Conformance vectors in `vectors/` are the contract. Any change to manifest fields, canonical encoding, signature scope, or CID computation MUST be proposed in the TS reference first; the vectors are regenerated there and copied here verbatim. PRs that change wire output will be rejected.
- **Idiomatic Python is welcome.** Type hints, dataclasses, async patterns, ergonomic helpers — go for it, as long as the public surface stays close to the TS API and the conformance suite passes byte-identical.
- **New deps need justification.** This port deliberately keeps deps small (`cryptography`, `jcs`, `base58`, `httpx`). Adding one needs a one-line rationale in the PR.

## PR rules

1. Open the PR against `main`.
2. `uv run pytest -v` must pass — all conformance vectors green.
3. `uv run ruff check src tests` must pass.
4. Include a short note in `CHANGELOG.md` under `[Unreleased]`.
5. Commits in the form `Subject line (≤72 chars)` + optional body explaining the why.

## Releasing

1. Bump `version` in `pyproject.toml`.
2. Move `[Unreleased]` notes under a new `## [x.y.z] — YYYY-MM-DD` heading in `CHANGELOG.md`.
3. Tag `vx.y.z` and push. CI publishes to PyPI.
