# Contributing to Microsoft Active Directory MCP Server

Thank you for your interest in contributing to this project!

## How to Contribute

1. **Fork the repository** on GitHub.
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. **Set up local development environment**:
   ```bash
   uv venv
   uv sync
   ```
4. **Make your changes**:
   - Ensure all tools maintain strict parameter validation and error handling.
   - Never execute arbitrary strings without proper parameterization.
   - Maintain the exactly 100 tools inventory unless a major version bump is planned.
5. **Run tests and linters**:
   ```bash
   pytest
   ruff check .
   ruff format .
   ```
6. **Submit a Pull Request** with a detailed description of your changes and test results.

## Coding Standards

- Python 3.11+ / 3.12+.
- Full type annotations on all functions.
- Every tool must return a valid `ToolResponse` model.
- All mutating tools must support `confirmation_token` and `dry_run` parameters.
- No plain-text passwords or credentials in code or tests.

