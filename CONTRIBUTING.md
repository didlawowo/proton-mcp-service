# Contributing to proton-service

This repository is a published snapshot. Development happens in a private
repository, and each release arrives here as a single commit. No CI runs here,
and pull requests are not merged directly.

## How to contribute

- **Bugs and ideas:** open an issue with the version, your setup and the steps
  to reproduce.
- **Patches:** attach a diff or link a branch of your fork in an issue. After
  review, a maintainer applies it upstream and credits you in the commit.

## Check your change locally

```bash
go vet ./... && go build -o /dev/null ./cmd/server/ && go test ./...
uvx ruff format --check mcp_server.py test_mcp_server.py
uvx ruff check mcp_server.py test_mcp_server.py
uv run --with "mcp>=1.2,<2" --with httpx --with pytest pytest test_mcp_server.py -q
helm lint helm/proton-service
```

## Security

Please report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE) of this project.
