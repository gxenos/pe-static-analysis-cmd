import os
import sys
import pefile
import ppdeep
import hashlib
import datetime
import math
import subprocess
import json
import argparse

# ============================================================
# CONFIGURATION - Update these paths for your environment
# ============================================================

# Path to FLOSS binary
# Set environment variable FLOSS_PATH to override
FLOSS_EXE_PATH = os.environ.get(
    "FLOSS_PATH", "/Users/george/Documents/malware-analyst/analysis-tools/floss"
)

# Path to capa binary
# Set environment variable CAPA_PATH to override
CAPA_EXE_PATH = os.environ.get(
    "CAPA_PATH", "/Users/george/Documents/malware-analyst/analysis-tools/capa"
)

# ============================================================


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def get_hashes(file_path: str) -> dict:
    hashes = {
        "md5": hashlib.md5(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)

    result = {k: v.hexdigest() for k, v in hashes.items()}

    # ssdeep fuzzy hash (pure-Python ppdeep, ssdeep-compatible). Best-effort:
    # a fuzzy-hash failure must not drop the cryptographic hashes.
    try:
        result["ssdeep"] = ppdeep.hash_from_file(file_path)
    except Exception:
        pass

    return result


def get_IAT(file_path: str) -> dict:
    pe = pefile.PE(file_path)
    iat = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return iat

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode()
        imports = []
        for imp in entry.imports:
            imp_name = imp.name.decode() if imp.name else f"ordinal_{imp.ordinal}"
            imports.append({"address": hex(imp.address), "name": imp_name})
        iat[dll_name] = imports
    return iat


def get_EAT(file_path: str) -> dict:
    pe = pefile.PE(file_path)
    eat = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return eat

    dll_name = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.name).decode()
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode() if exp.name else f"ordinal_{exp.ordinal}"
        exports.append(
            {"address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), "name": name}
        )
    eat[dll_name] = exports
    return eat


def get_sections(file_path: str) -> dict:
    pe = pefile.PE(file_path)
    sections_info = {}

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode(errors="ignore")
        data = section.get_data()
        sections_info[name] = {
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": hex(section.Misc_VirtualSize),
            "raw_size": hex(section.SizeOfRawData),
            "characteristics": hex(section.Characteristics),
            "entropy": round(calculate_entropy(data), 4),
        }

    return sections_info


def get_pe_metadata(file_path: str) -> dict:
    pe = pefile.PE(file_path)
    metadata = {}

    metadata["machine"] = hex(pe.FILE_HEADER.Machine)
    metadata["number_of_sections"] = pe.FILE_HEADER.NumberOfSections
    metadata["timestamp"] = (
        datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp, datetime.timezone.utc
        )
        .replace(tzinfo=None)
        .isoformat()
        + "Z"
    )
    metadata["characteristics"] = hex(pe.FILE_HEADER.Characteristics)

    metadata["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    metadata["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    metadata["subsystem"] = hex(pe.OPTIONAL_HEADER.Subsystem)
    metadata["dll_characteristics"] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
    metadata["architecture"] = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"

    try:
        rich_header = pe.parse_rich_header()
        metadata["rich_header"] = [
            {
                "tool_id": hex(entry["id"]),
                "version": entry["version"],
                "count": entry["count"],
            }
            for entry in rich_header["values"]
        ]
    except:
        metadata["rich_header"] = None

    metadata["original_filename"] = None
    metadata["certificate_present"] = False

    if hasattr(pe, "FileInfo"):
        for fileinfo in pe.FileInfo:
            if isinstance(fileinfo, list):
                for fi in fileinfo:
                    if hasattr(fi, "Key") and fi.Key == b"StringFileInfo":
                        for st in fi.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode(errors="ignore")
                                val = v.decode(errors="ignore")
                                metadata[key] = val
                                if key.lower() == "originalfilename":
                                    metadata["original_filename"] = val
            elif hasattr(fileinfo, "Key") and fileinfo.Key == b"StringFileInfo":
                for st in fileinfo.StringTable:
                    for k, v in st.entries.items():
                        key = k.decode(errors="ignore")
                        val = v.decode(errors="ignore")
                        metadata[key] = val
                        if key.lower() == "originalfilename":
                            metadata["original_filename"] = val

    for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if entry.name == "IMAGE_DIRECTORY_ENTRY_SECURITY" and entry.VirtualAddress != 0:
            metadata["certificate_present"] = True
            break

    return metadata


def run_die(file_path: str):
    return "Detect-It-Easy is not available on macOS ARM64"


def run_capa_scan(file_path: str):
    try:
        if os.path.isfile(CAPA_EXE_PATH):
            result = subprocess.run(
                [CAPA_EXE_PATH, "-q", file_path],
                stderr=subprocess.DEVNULL,
                encoding="utf-8",
                errors="replace",
                universal_newlines=True,
                stdout=subprocess.PIPE,
            )
            return result.stdout if result.stdout else "capa found no capabilities"
        else:
            return "capa not found"
    except Exception as e:
        return f"capa execution failed: {e}"


def run_floss(file_path: str):
    try:
        if os.path.isfile(FLOSS_EXE_PATH):
            result = subprocess.run(
                [FLOSS_EXE_PATH, file_path],
                stderr=subprocess.DEVNULL,
                encoding="utf-8",
                errors="replace",
                universal_newlines=True,
                stdout=subprocess.PIPE,
            )
            return result.stdout if result.stdout else "floss found no strings"
        else:
            return "floss not found"
    except Exception as e:
        return f"floss execution failed: {e}"


def main():
    parser = argparse.ArgumentParser(description="Static PE analysis CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    hashes_parser = subparsers.add_parser("hashes", help="Calculate file hashes")
    hashes_parser.add_argument("file", help="Path to file")
    hashes_parser.add_argument("-o", "--output", help="Output file path", default=None)

    iat_parser = subparsers.add_parser("iat", help="Get Import Address Table")
    iat_parser.add_argument("file", help="Path to PE file")
    iat_parser.add_argument("-o", "--output", help="Output file path", default=None)

    eat_parser = subparsers.add_parser("eat", help="Get Export Address Table")
    eat_parser.add_argument("file", help="Path to PE file")
    eat_parser.add_argument("-o", "--output", help="Output file path", default=None)

    sections_parser = subparsers.add_parser("sections", help="Get PE sections info")
    sections_parser.add_argument("file", help="Path to PE file")
    sections_parser.add_argument(
        "-o", "--output", help="Output file path", default=None
    )

    metadata_parser = subparsers.add_parser("metadata", help="Get PE metadata")
    metadata_parser.add_argument("file", help="Path to PE file")
    metadata_parser.add_argument(
        "-o", "--output", help="Output file path", default=None
    )

    die_parser = subparsers.add_parser("die", help="Run detect-it-easy")
    die_parser.add_argument("file", help="Path to file")
    die_parser.add_argument("-o", "--output", help="Output file path", default=None)

    capa_parser = subparsers.add_parser("capa", help="Run capa analysis")
    capa_parser.add_argument("file", help="Path to PE file")
    capa_parser.add_argument("-o", "--output", help="Output file path", default=None)

    floss_parser = subparsers.add_parser("floss", help="Run floss analysis")
    floss_parser.add_argument("file", help="Path to file")
    floss_parser.add_argument("-o", "--output", help="Output file path", default=None)

    full_analysis_parser = subparsers.add_parser(
        "full-analysis", help="Run all analysis tools"
    )
    full_analysis_parser.add_argument("file", help="Path to PE file")
    full_analysis_parser.add_argument(
        "-o", "--output", help="Output file path", default=None
    )

    subparsers.add_parser("help", help="List available commands")

    args = parser.parse_args()

    if not args.command or args.command == "help":
        parser.print_help()
        return

    if not os.path.isfile(args.file):
        print(json.dumps({"error": f"File not found: {args.file}"}))
        sys.exit(1)

    result = None
    try:
        if args.command == "hashes":
            result = get_hashes(args.file)
        elif args.command == "iat":
            result = get_IAT(args.file)
        elif args.command == "eat":
            result = get_EAT(args.file)
        elif args.command == "sections":
            result = get_sections(args.file)
        elif args.command == "metadata":
            result = get_pe_metadata(args.file)
        elif args.command == "die":
            result = run_die(args.file)
        elif args.command == "capa":
            result = run_capa_scan(args.file)
        elif args.command == "floss":
            result = run_floss(args.file)
        elif args.command == "full-analysis":
            result = {
                "hashes": get_hashes(args.file),
                "metadata": get_pe_metadata(args.file),
                "sections": get_sections(args.file),
                "iat": get_IAT(args.file),
                "eat": get_EAT(args.file),
                "die": run_die(args.file),
                "capa": run_capa_scan(args.file),
                "floss": run_floss(args.file),
            }
    except Exception as e:
        result = {"error": str(e)}

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
