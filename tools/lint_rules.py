#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from typing import Any

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    """PyYAML loader that rejects duplicate mapping keys."""


def construct_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping,
)

CLASSICAL_PREFIXES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "GEOSITE",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-GEOIP",
    "SRC-IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-PATH",
    "PROCESS-PATH-WILDCARD",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-NAME-REGEX",
    "UID",
    "NETWORK",
    "DSCP",
    "AND",
    "OR",
    "NOT",
}


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.load(fh, Loader=UniqueKeyLoader)


def validate_rule_file(path: Path, behavior: str) -> list[str]:
    errors: list[str] = []

    try:
        data = load_yaml(path)
    except Exception as exc:
        return [f"{path}: YAML parse failed: {exc}"]

    if not isinstance(data, dict):
        return [f"{path}: top level must be a mapping"]

    if set(data) != {"payload"}:
        errors.append(f"{path}: top level must contain only 'payload'; got {sorted(data)}")

    payload = data.get("payload")
    if not isinstance(payload, list):
        return errors + [f"{path}: payload must be a list"]

    seen: set[str] = set()
    for index, item in enumerate(payload, start=1):
        prefix = f"{path}: payload item {index}"

        if not isinstance(item, str):
            errors.append(f"{prefix}: must be a string, got {type(item).__name__}")
            continue

        item = item.strip()
        if not item:
            errors.append(f"{prefix}: empty rule")
            continue

        if "payload:" in item.lower():
            errors.append(f"{prefix}: contains accidental embedded 'payload:' text")

        if item in seen:
            errors.append(f"{prefix}: duplicate rule {item!r}")
        seen.add(item)

        if behavior == "classical":
            rule_type = item.split(",", 1)[0].upper()
            if rule_type not in CLASSICAL_PREFIXES:
                errors.append(
                    f"{prefix}: expected classical rule prefix, got {rule_type!r}"
                )

        elif behavior == "ipcidr":
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                errors.append(f"{prefix}: invalid CIDR {item!r}: {exc}")

        elif behavior == "domain":
            first = item.split(",", 1)[0].upper()
            if first in CLASSICAL_PREFIXES:
                errors.append(
                    f"{prefix}: classical syntax found in a domain provider; "
                    "use behavior classical or rewrite as bare domain patterns"
                )
            if any(ch.isspace() for ch in item):
                errors.append(f"{prefix}: domain pattern contains whitespace")

        else:
            errors.append(f"{path}: unsupported behavior in manifest: {behavior!r}")
            break

    return errors


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    manifest_path = repo / "rules-manifest.yaml"
    rules_dir = repo / "rules"

    try:
        manifest = load_yaml(manifest_path)
    except Exception as exc:
        print(f"{manifest_path}: manifest parse failed: {exc}", file=sys.stderr)
        return 1

    expected = manifest.get("rules") if isinstance(manifest, dict) else None
    if not isinstance(expected, dict):
        print(f"{manifest_path}: expected a 'rules' mapping", file=sys.stderr)
        return 1

    errors: list[str] = []

    actual_files = {
        p.name for p in rules_dir.glob("*.y*ml") if p.is_file()
    }
    manifest_files = set(expected)

    for missing in sorted(manifest_files - actual_files):
        errors.append(f"rules/{missing}: listed in manifest but file is missing")

    for unlisted in sorted(actual_files - manifest_files):
        errors.append(f"rules/{unlisted}: YAML file is not listed in rules-manifest.yaml")

    for filename, behavior in sorted(expected.items()):
        path = rules_dir / filename
        if path.exists():
            errors.extend(validate_rule_file(path, str(behavior)))

    if errors:
        print("Rule lint FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Rule lint OK: {len(expected)} files checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
