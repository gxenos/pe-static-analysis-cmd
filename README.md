# Triage - Static PE Analysis CLI

A command-line utility for static analysis of PE (Portable Executable) files.

## Installation

Install dependencies using uv:

```bash
uv sync
```

## Usage

Run commands using `uv run`:

```bash
uv run triage.py <command> <file>
```

### Available Commands

| Command | Description |
|---------|-------------|
| `hashes` | Calculate MD5, SHA256, SHA512 hashes |
| `iat` | Get Import Address Table |
| `eat` | Get Export Address Table |
| `sections` | Get PE sections with entropy |
| `metadata` | Get PE metadata (timestamp, architecture, etc.) |
| `die` | Run Detect-It-Easy |
| `capa` | Run capa capability analysis |
| `floss` | Run FLOSS string extraction |
| `help` | List available commands |

### Examples

```bash
# Get file hashes
uv run triage.py hashes malware.exe

# Get import table
uv run triage.py iat malware.exe

# Get PE metadata
uv run triage.py metadata malware.exe

# Run capa analysis
uv run triage.py capa malware.exe

# Run FLOSS
uv run triage.py floss malware.exe

# List all commands
uv run triage.py help
```

## External Tools

This script uses the following external tools (located at `/Users/george/Documents/malware-analyst/analysis-tools/`):

- [capa](https://github.com/mandiant/capa) - Capability detection
- [FLOSS](https://github.com/mandiant/FLOSS) - String deobfuscation
