"""Map target types to optional tool command aliases."""

import argparse
import json
import os
import shlex
import shutil
import struct
from pathlib import Path


DEFAULT_CATALOG_PATH = Path(__file__).resolve().parents[1] / "tool_catalog.json.example"
LOCAL_CATALOG_PATH = Path(__file__).resolve().parents[1] / "tool_catalog.json"
SQUASHFS_MAGIC = (b"hsqs", b"sqsh", b"qshs", b"shsq")
IMAGE_SUFFIXES = {".img", ".bin", ".fw", ".rom", ".trx", ".ubi",
                  ".fat", ".ext4", ".sfs", ".sqfs", ".squashfs"}
HEXAGON_MACHINE = 164
XTENSA_MACHINE = 94
COMMAND_GUIDANCE_ALIASES = {"hexagon_disassemble", "xtensa_disassemble", "mbn_inspect"}
DISASSEMBLY_ALIASES = {"hexagon_disassemble", "xtensa_disassemble"}


def load_catalog() -> dict:
    catalog = json.loads(DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
    if LOCAL_CATALOG_PATH.is_file():
        overrides = json.loads(LOCAL_CATALOG_PATH.read_text(encoding="utf-8"))
        for group in ("aliases", "targets"):
            values = overrides.get(group) or {}
            if not isinstance(values, dict):
                raise ValueError(f"tool_catalog.json {group} must be an object")
            catalog[group].update(values)
    aliases = catalog.get("aliases")
    targets = catalog.get("targets")
    if not isinstance(aliases, dict) or not isinstance(targets, dict):
        raise ValueError("tool_catalog.json.example needs aliases and targets objects")
    for target, names in targets.items():
        if not isinstance(names, list) or any(name not in aliases for name in names):
            raise ValueError(f"Unknown tool alias in target {target}")
    return catalog


def resolve_alias(alias: str, catalog: dict | None = None) -> str | None:
    entry = (catalog or load_catalog())["aliases"][alias]
    binary = entry["binary"]
    candidates = [shutil.which(binary), *(entry.get("fallback_paths") or [])]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(Path(candidate).resolve())
    return None


def command_for(alias: str, *, input_file: str | Path,
                output_dir: str | Path | None = None,
                catalog: dict | None = None) -> list[str] | None:
    catalog = catalog or load_catalog()
    executable = resolve_alias(alias, catalog)
    if not executable:
        return None
    values = {"input_file": str(input_file), "output_dir": str(output_dir or "")}
    return [executable, *(arg.format_map(values) for arg in
                          catalog["aliases"][alias]["args"])]


def target_for_file(path: str | Path) -> str | None:
    file = Path(path)
    if not file.is_file() or file.is_symlink():
        return None
    try:
        with file.open("rb") as stream:
            header = stream.read(64)
    except OSError:
        return None
    if header[:4] in SQUASHFS_MAGIC:
        return "squashfs"
    if header[:4] == b"\x7fELF":
        if len(header) >= 20:
            endian = "<" if header[5] == 1 else ">" if header[5] == 2 else None
            if endian:
                machine = struct.unpack_from(endian + "H", header, 18)[0]
                if machine == HEXAGON_MACHINE:
                    return "hexagon_elf"
                if machine == XTENSA_MACHINE:
                    return "xtensa_elf"
        return "unidentified_elf"
    if file.suffix.lower() == ".mbn":
        return "mbn_image"
    if file.suffix.lower() in IMAGE_SUFFIXES:
        return "nested_image"
    return None


def available_for_target(target: str, catalog: dict | None = None) -> list[dict]:
    catalog = catalog or load_catalog()
    return [{"alias": name, "target": target, "path": resolve_alias(name, catalog),
             "purpose": catalog["aliases"][name]["purpose"],
             "mode": catalog["aliases"][name]["mode"]}
            for name in catalog["targets"].get(target, [])]


def guidance_for_files(paths: list[str]) -> str:
    catalog = load_catalog()
    entries = {}
    for path in paths:
        target = target_for_file(path)
        if target:
            for item in available_for_target(target, catalog):
                entries[(target, item["alias"])] = item
    if not entries:
        return "No target-specific optional tool is registered for these files."
    lines = []
    for item in entries.values():
        if item["path"] and item["mode"] == "automatic":
            lines.append(f"{item['target']}: {item['alias']} = {item['path']} ({item['purpose']}).")
        elif item["path"]:
            lines.append(f"{item['target']}: {item['alias']} = {item['path']} "
                         f"(manual; {item['purpose']}).")
        else:
            lines.append(f"{item['target']}: {item['alias']} is unavailable.")
    for path in paths:
        target = target_for_file(path)
        if not target:
            continue
        for item in available_for_target(target, catalog):
            if item["alias"] not in COMMAND_GUIDANCE_ALIASES or not item["path"]:
                continue
            command = command_for(item["alias"], input_file=path, catalog=catalog)
            if command:
                lines.append(f"{target} {item['alias']} command: {shlex.join(command)}")
    if any(item["alias"] in DISASSEMBLY_ALIASES and item["path"]
           for item in entries.values()):
        lines.append("Inspect the decoded instructions and their real addresses before treating a site "
                     "as verified. Unrecognized opcodes or an unknown ELF machine do not prove a flaw.")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="FBI optional tool alias registry")
    parser.add_argument("--target", help="Only show aliases for this target type")
    args = parser.parse_args()
    catalog = load_catalog()
    if args.target and args.target not in catalog["targets"]:
        parser.error(f"Unknown target: {args.target}")
    for target in ([args.target] if args.target else catalog["targets"]):
        for item in available_for_target(target, catalog):
            state = item["path"] or "unavailable"
            print(f"{target:16} {item['alias']:22} {state} [{item['mode']}]")


if __name__ == "__main__":
    main()
