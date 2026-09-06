# Releasing

Installs come straight from the tagged GitHub repo, so a release is a tag.

## 1. Tag

    python tests/smoke.py          # every case must pass
    git tag -a vX.Y.Z -m "vX.Y.Z"
    git push origin vX.Y.Z

The tag push builds the image, pushes it to ghcr.io and registers the version with the MCP registry
(`.github/workflows/publish-registry.yml`). The install lines in the README pin the tag; bump them in
the same commit.

## 2. The directories people browse

- **Glama** indexes public repos on its own.
- **awesome-mcp-servers** — one line under Networking (or Security), with the Glama badge.

## Version bumps

`pyproject.toml`, `server.json` (version AND the image tag in `identifier`), and the README install lines
all carry the version. Bump them together, re-run the tests, tag.
