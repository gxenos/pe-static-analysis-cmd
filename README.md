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
uv run triage.py <command> <file> [-o output.json]
```

### Available Commands

| Command | Description |
|---------|-------------|
| `hashes` | Calculate MD5, SHA256, SHA512 hashes |
| `iat` | Get Import Address Table |
| `eat` | Get Export Address Table |
| `sections` | Get PE sections with entropy |
| `metadata` | Get PE metadata (timestamp, architecture, etc.) |
| `capa` | Run capa capability analysis |
| `floss` | Run FLOSS string extraction |
| `die` | Run Detect-It-Easy (not available on macOS ARM64) |
| `full-analysis` | Run all analysis tools |
| `help` | List available commands |

### Options

| Option | Description |
|--------|-------------|
| `-o, --output` | Save output to JSON file (silent mode - no console output) |

### Examples

```bash
# Get file hashes
uv run triage.py hashes malware.exe

# Get import table
uv run triage.py iat malware.exe

# Get export table
uv run triage.py eat malware.exe

# Get PE sections with entropy
uv run triage.py sections malware.exe

# Get PE metadata
uv run triage.py metadata malware.exe

# Run capa analysis
uv run triage.py capa malware.exe

# Run FLOSS
uv run triage.py floss malware.exe

# Run full analysis
uv run triage.py full-analysis malware.exe

# Save results to file (silent - no console output)
uv run triage.py full-analysis malware.exe -o results.json

# List all commands
uv run triage.py help
```

## Output

- By default, results are printed to stdout as formatted JSON
- When using `-o`, results are saved to the specified file and no output is printed to console

## External Tools

This script uses the following external tools (located at `/Users/george/Documents/malware-analyst/analysis-tools/`):

- [capa](https://github.com/mandiant/capa) - Capability detection
- [FLOSS](https://github.com/mandiant/FLOSS) - String deobfuscation
- [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) - File type identification (not available on macOS ARM64)

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) for dependency management
- External tools: capa, floss (included in analysis-tools directory)
