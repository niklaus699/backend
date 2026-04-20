"""
Parses dependency manifest files into a flat list of (name, version, ecosystem).
Each parser returns: [{"name": str, "version": str, "ecosystem": str}]
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET


def _dedupe_packages(packages: list[dict], unpinned: list[str]) -> tuple[list[dict], list[str]]:
    deduped_packages: dict[tuple[str, str], dict] = {}
    for package in packages:
        key = (package['ecosystem'], package['name'].lower())
        deduped_packages[key] = package

    return list(deduped_packages.values()), sorted(set(unpinned))


def parse_manifest(filename: str, content: str) -> tuple[list[dict], list[str]]:
    fname = filename.lower()
    if fname == 'requirements.txt' or fname.endswith('.txt'):
        return _parse_requirements_txt(content)
    if fname == 'package.json':
        return _parse_package_json(content)
    if fname == 'package-lock.json':
        return _parse_package_lock(content)
    if fname in ('go.mod', 'go.sum'):
        return _parse_go_mod(content)
    if fname == 'pom.xml':
        return _parse_pom_xml(content)
    if fname == 'gemfile.lock':
        return _parse_gemfile_lock(content)
    if fname in ('pipfile', 'pipfile.lock'):
        return _parse_pipfile(content)
    if fname == 'pyproject.toml':
        return _parse_pyproject_toml(content)
    raise ValueError(f"Unsupported manifest file: {filename}")


def _parse_requirements_txt(content: str) -> tuple[list[dict], list[str]]:
    pinned = []
    unpinned = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        line = line.split('#')[0].strip()
        match = re.match(r'^([A-Za-z0-9_\-\.]+)==([^\s,;]+)', line)
        if match:
            name, version = match.group(1), match.group(2)
            pinned.append({"name": name, "version": version, "ecosystem": "PyPI"})
        else:
            # Capture package name (anything before first operator or space)
            name_match = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
            if name_match:
                unpinned.append(name_match.group(1))
    return _dedupe_packages(pinned, unpinned)


def _parse_package_json(content: str) -> tuple[list[dict], list[str]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid package.json: malformed JSON") from exc

    if not isinstance(data, dict):
        raise ValueError("Invalid package.json: expected a JSON object")

    pinned = []
    unpinned = []
    for section in ('dependencies', 'devDependencies', 'peerDependencies'):
        for name, version_str in data.get(section, {}).items():
            # Check if version is a concrete number (no ^, ~, >, <, *, latest, etc.)
            clean = version_str.strip()
            if re.match(r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$', clean):
                pinned.append({"name": name, "version": clean, "ecosystem": "npm"})
            else:
                unpinned.append(name)
    return _dedupe_packages(pinned, unpinned)

def _parse_package_lock(content: str) -> tuple[list[dict], list[str]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid package-lock.json: malformed JSON") from exc

    if not isinstance(data, dict):
        raise ValueError("Invalid package-lock.json: expected a JSON object")

    pinned = []
    for pkg_path, info in data.get('packages', {}).items():
        if not pkg_path or pkg_path == '':
            continue
        name = pkg_path.replace('node_modules/', '', 1)
        version = info.get('version', '')
        if name and version:
            pinned.append({"name": name, "version": version, "ecosystem": "npm"})
    return _dedupe_packages(pinned, [])

def _parse_go_mod(content: str) -> tuple[list[dict], list[str]]:
    pinned = []
    unpinned = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('require ('):
            in_require = True
            continue
        if in_require and line == ')':
            in_require = False
            continue
        if in_require or line.startswith('require '):
            clean = line.replace('require ', '').strip()
            parts = clean.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].lstrip('v')
                # Go modules are always pinned to a specific version or pseudo-version
                if re.match(r'^v?\d+\.\d+\.\d+', parts[1]) or '-' in parts[1]:
                    pinned.append({"name": name, "version": version, "ecosystem": "Go"})
                else:
                    unpinned.append(name)
    return _dedupe_packages(pinned, unpinned)


def _parse_pom_xml(content: str) -> tuple[list[dict], list[str]]:
    pinned = []
    unpinned = []
    try:
        root = ET.fromstring(content)
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        for dep in root.findall('.//m:dependency', ns):
            group    = dep.findtext('m:groupId',    namespaces=ns) or ''
            artifact = dep.findtext('m:artifactId', namespaces=ns) or ''
            version  = dep.findtext('m:version',    namespaces=ns) or ''
            if group and artifact:
                full_name = f"{group}:{artifact}"
                if version and not version.startswith('$') and not version.startswith('${'):
                    pinned.append({"name": full_name, "version": version, "ecosystem": "Maven"})
                else:
                    unpinned.append(full_name)
    except ET.ParseError as exc:
        raise ValueError("Invalid pom.xml: malformed XML") from exc
    return _dedupe_packages(pinned, unpinned)

def _parse_gemfile_lock(content: str) -> tuple[list[dict], list[str]]:
    pinned = []
    unpinned = []
    in_specs = False
    for line in content.splitlines():
        if '  specs:' in line:
            in_specs = True
            continue
        if in_specs:
            if line and not line.startswith(' '):
                in_specs = False
                continue
            match = re.match(r'    ([a-zA-Z0-9_\-]+) \(([^\)]+)\)', line)
            if match:
                name = match.group(1)
                version = match.group(2)
                pinned.append({"name": name, "version": version, "ecosystem": "RubyGems"})
    return _dedupe_packages(pinned, [])


def _parse_pipfile(content: str) -> tuple[list[dict], list[str]]:
    pinned = []
    unpinned = []
    try:
        data = json.loads(content)
        for section in ('default', 'develop'):
            for name, info in data.get(section, {}).items():
                version = info.get('version', '').lstrip('==')
                if version:
                    pinned.append({"name": name, "version": version, "ecosystem": "PyPI"})
                else:
                    unpinned.append(name)
    except json.JSONDecodeError:
        # Plain Pipfile TOML
        for line in content.splitlines():
            match = re.match(r'^([a-zA-Z0-9_\-]+)\s*=.*"==([^"]+)"', line)
            if match:
                pinned.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "ecosystem": "PyPI"
                })
            else:
                # Unpinned entry
                name_match = re.match(r'^([a-zA-Z0-9_\-]+)\s*=', line)
                if name_match:
                    unpinned.append(name_match.group(1))
    return _dedupe_packages(pinned, unpinned)

def _parse_pyproject_toml(content: str) -> tuple[list[dict], list[str]]:
    pinned = []
    unpinned = []
    for line in content.splitlines():
        match = re.match(r'^\s*["\']?([A-Za-z0-9_\-]+)["\']?\s*==\s*["\']?([^\s"\'>,;]+)', line)
        if match:
            pinned.append({
                "name": match.group(1),
                "version": match.group(2),
                "ecosystem": "PyPI"
            })
        else:
            # Detect dependencies with other version specifiers
            name_match = re.match(r'^\s*["\']?([A-Za-z0-9_\-]+)["\']?\s*[~^<>]', line)
            if name_match:
                unpinned.append(name_match.group(1))
    return _dedupe_packages(pinned, unpinned)
