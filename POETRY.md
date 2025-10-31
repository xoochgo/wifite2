# Poetry Installation and Usage Guide for Wifite2

This guide explains how to install and use wifite2 with Poetry for development and testing.

## Prerequisites

- Python 3.9 or higher
- Poetry (install from https://python-poetry.org/docs/#installation)

## Quick Start

### 1. Install Poetry

If you don't have Poetry installed:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Or using pip:

```bash
pip install poetry
```

### 2. Install Dependencies

Clone the repository and install dependencies:

```bash
git clone https://github.com/kimocoder/wifite2.git
cd wifite2
poetry install
```

This will:
- Create a virtual environment
- Install all dependencies from `pyproject.toml`
- Install wifite2 in editable mode

### 3. Run Wifite2

Activate the Poetry shell:

```bash
poetry shell
```

Then run wifite:

```bash
wifite
```

Or run directly without activating the shell:

```bash
poetry run wifite
```

## Development

### Running Tests

Run all tests:

```bash
poetry run pytest
```

Run specific test file:

```bash
poetry run pytest tests/test_tui_integration.py
```

Run with coverage:

```bash
poetry run pytest --cov=wifite --cov-report=html
```

### Adding Dependencies

Add a runtime dependency:

```bash
poetry add package-name
```

Add a development dependency:

```bash
poetry add --group dev package-name
```

### Updating Dependencies

Update all dependencies:

```bash
poetry update
```

Update specific package:

```bash
poetry update package-name
```

### Show Installed Packages

```bash
poetry show
```

Show dependency tree:

```bash
poetry show --tree
```

## Building and Publishing

### Build Distribution

```bash
poetry build
```

This creates both wheel and source distributions in the `dist/` directory.

### Install from Built Package

```bash
pip install dist/wifite2-*.whl
```

## Troubleshooting

### Virtual Environment Location

Find where Poetry created the virtual environment:

```bash
poetry env info --path
```

### Remove Virtual Environment

```bash
poetry env remove python
```

### Clear Poetry Cache

```bash
poetry cache clear pypi --all
```

### Lock File Issues

If you encounter lock file issues:

```bash
poetry lock --no-update
```

## Configuration

Poetry configuration is stored in `pyproject.toml`. Key sections:

- `[tool.poetry]` - Project metadata
- `[tool.poetry.dependencies]` - Runtime dependencies
- `[tool.poetry.group.dev.dependencies]` - Development dependencies
- `[tool.poetry.scripts]` - Entry points (wifite command)
- `[tool.pytest.ini_options]` - Pytest configuration

## Comparison with setup.py

Poetry provides several advantages over traditional `setup.py`:

- **Dependency Resolution**: Poetry resolves dependencies and creates a lock file
- **Virtual Environment Management**: Automatic virtual environment creation
- **Modern Standards**: Uses `pyproject.toml` (PEP 518)
- **Reproducible Builds**: Lock file ensures consistent installations
- **Development Dependencies**: Separate dev dependencies from runtime

Both `setup.py` and Poetry can coexist in the project for compatibility.

## Additional Resources

- [Poetry Documentation](https://python-poetry.org/docs/)
- [Poetry Commands](https://python-poetry.org/docs/cli/)
- [Managing Dependencies](https://python-poetry.org/docs/managing-dependencies/)
