#!/usr/bin/env python3
"""Machine-readable authorization scope gate for network actions.

Exit codes:
  0 allowed
  2 denied / out of scope
  3 invalid configuration or target
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass


ACTIONS = ("passive", "active", "exploit", "destructive")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def split_target(value: str) -> tuple[str, int | None]:
    text = value.strip()
    if not text:
        raise ValueError("empty target")
    if "://" not in text and text.count(":") >= 2 and not text.startswith("["):
        try:
            host = str(ipaddress.ip_address(text)).lower()
        except ValueError:
            pass
        else:
            return host, None
    parsed = urlsplit(text if "://" in text else "//" + text)
    host = parsed.hostname
    if not host:
        raise ValueError("target has no host")
    try:
        host = host.encode("idna").decode("ascii").rstrip(".").lower()
    except UnicodeError as exc:
        raise ValueError(f"invalid host: {exc}") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port: {exc}") from exc
    if port is None and parsed.scheme == "https":
        port = 443
    elif port is None and parsed.scheme == "http":
        port = 80
    return host, port


def host_matches(host: str, rule: str) -> bool:
    candidate = rule.strip().lower().rstrip(".")
    if not candidate:
        return False
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    if candidate.startswith("*."):
        suffix = candidate[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return fnmatch.fnmatchcase(host, candidate)


def port_matches(port: int | None, rules: list[object] | None) -> bool:
    if not rules or "*" in rules:
        return True
    if port is None:
        return False
    for item in rules:
        if isinstance(item, int) and item == port:
            return True
        if isinstance(item, str):
            value = item.strip()
            if value.isdigit() and int(value) == port:
                return True
            if "-" in value:
                left, right = value.split("-", 1)
                if left.isdigit() and right.isdigit() and int(left) <= port <= int(right):
                    return True
    return False


def find_default_config() -> Path:
    env = os.environ.get("DSH_AUTHORIZED_TARGETS")
    if env:
        return Path(env).expanduser().resolve()
    current = Path.cwd().resolve()
    for directory in (current, *current.parents):
        candidate = directory / "AUTHORIZED-TARGETS.json"
        if candidate.is_file():
            return candidate
    return current / "AUTHORIZED-TARGETS.json"


def load_config(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(
            f"scope config not found: {path}; copy AUTHORIZED-TARGETS.template.json "
            "to AUTHORIZED-TARGETS.json and edit it"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read scope config {path}: {exc}") from exc
    if data.get("version") != 1 or not isinstance(data.get("targets"), list):
        raise ValueError("scope config must use version 1 and contain a targets array")
    return data


def require_allowed(
    target: str,
    action: str,
    config_path: str | Path | None = None,
    *,
    confirm_destructive: bool = False,
) -> dict:
    """Load the configured scope and raise when the requested action is denied."""
    path = Path(config_path).expanduser().resolve() if config_path else find_default_config()
    result = evaluate(
        load_config(path),
        target,
        action,
        confirm_destructive=confirm_destructive,
    )
    result["config"] = str(path)
    if not result.get("allowed"):
        raise PermissionError(result.get("reason") or "scope denied")
    return result


def evaluate(
    config: dict,
    target: str,
    action: str,
    *,
    now: datetime | None = None,
    confirm_destructive: bool = False,
) -> dict:
    host, port = split_target(target)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    matches: list[dict] = []
    expired: list[str] = []

    for entry in config.get("targets", []):
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id") or "unnamed")
        hosts = entry.get("hosts") or []
        if not any(host_matches(host, str(rule)) for rule in hosts):
            continue
        if not port_matches(port, entry.get("ports")):
            continue
        try:
            valid_from = parse_time(entry.get("validFrom"))
            valid_until = parse_time(entry.get("validUntil"))
        except (TypeError, ValueError) as exc:
            return {"allowed": False, "reason": f"invalid time window in {entry_id}: {exc}"}
        if (valid_from and current < valid_from) or (valid_until and current > valid_until):
            expired.append(entry_id)
            continue
        if action not in (entry.get("actions") or []):
            continue
        matches.append(entry)

    if not matches:
        reason = "no matching authorization entry"
        if expired:
            reason += "; expired/not-yet-valid entries: " + ", ".join(expired)
        return {"allowed": False, "target": target, "host": host, "port": port, "action": action, "reason": reason}

    entry = matches[0]
    if action == "destructive" and not confirm_destructive:
        return {
            "allowed": False,
            "target": target,
            "host": host,
            "port": port,
            "action": action,
            "scopeId": entry.get("id"),
            "reason": "destructive action requires --confirm-destructive for this invocation",
        }
    return {
        "allowed": True,
        "target": target,
        "host": host,
        "port": port,
        "action": action,
        "scopeId": entry.get("id"),
        "authorizationReference": entry.get("authorizationReference"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a target/action against AUTHORIZED-TARGETS.json")
    parser.add_argument("target", help="URL, hostname, IP, or host:port")
    parser.add_argument("--action", choices=ACTIONS, default="active")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--confirm-destructive", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    config_path = (args.config or find_default_config()).expanduser().resolve()
    try:
        result = evaluate(
            load_config(config_path),
            args.target,
            args.action,
            confirm_destructive=args.confirm_destructive,
        )
    except ValueError as exc:
        result = {"allowed": False, "reason": str(exc), "config": str(config_path)}
        code = 3
    else:
        result["config"] = str(config_path)
        code = 0 if result.get("allowed") else 2

    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        status = "ALLOW" if result.get("allowed") else "DENY"
        print(f"{status}: {result.get('reason') or result.get('scopeId')}")
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
