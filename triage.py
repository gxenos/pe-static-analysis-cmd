import os
import sys
import die
import pefile
import hashlib
import datetime
import math
import subprocess
import json
import argparse

FLOSS_EXE_PATH = "/Users/george/Documents/malware-analyst/analysis-tools/floss"
CAPA_EXE_PATH = "/Users/george/Documents/malware-analyst/analysis-tools/capa"


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

    return {k: v.hexdigest() for k, v in hashes.items()}


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
        datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
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
            if fileinfo.Key == b"StringFileInfo":
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


def run_die(file_path: str) -> dict:
    return die.scan_file(
        file_path,
        die.ScanFlags.VERBOSE_FLAG
        | die.ScanFlags.DEEP_SCAN
        | die.ScanFlags.HEURISTIC_SCAN
        | die.ScanFlags.RECURSIVE_SCAN
        | die.ScanFlags.RESULT_AS_JSON,
        str(die.database_path / "db"),
    )


def run_capa_scan(file_path: str):
    try:
        if os.path.isfile(CAPA_EXE_PATH):
            output = subprocess.check_output(
                [CAPA_EXE_PATH, "-q", file_path],
                stderr=subprocess.DEVNULL,
                encoding="utf-8",
                errors="replace",
                universal_newlines=True,
            )
            return output
        else:
            return "capa not found"
    except subprocess.CalledProcessError:
        return "capa execution failed"
    except json.JSONDecodeError:
        return "invalid JSON output from capa"


def run_floss(file_path: str):
    try:
        if os.path.isfile(FLOSS_EXE_PATH):
            output = subprocess.check_output(
                [FLOSS_EXE_PATH, file_path],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            )
            return output
        else:
            return "floss not found"
    except subprocess.CalledProcessError:
        return "floss execution failed"
    except json.JSONDecodeError:
        return "invalid JSON output from floss"


def main():
    parser = argparse.ArgumentParser(description="Static PE analysis CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("hashes", help="Calculate file hashes").add_argument(
        "file", help="Path to file"
    )
    subparsers.add_parser("iat", help="Get Import Address Table").add_argument(
        "file", help="Path to PE file"
    )
    subparsers.add_parser("eat", help="Get Export Address Table").add_argument(
        "file", help="Path to PE file"
    )
    subparsers.add_parser("sections", help="Get PE sections info").add_argument(
        "file", help="Path to PE file"
    )
    subparsers.add_parser("metadata", help="Get PE metadata").add_argument(
        "file", help="Path to PE file"
    )
    subparsers.add_parser("die", help="Run detect-it-easy").add_argument(
        "file", help="Path to file"
    )
    subparsers.add_parser("capa", help="Run capa analysis").add_argument(
        "file", help="Path to PE file"
    )
    subparsers.add_parser("floss", help="Run floss analysis").add_argument(
        "file", help="Path to file"
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
    except Exception as e:
        result = {"error": str(e)}

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
