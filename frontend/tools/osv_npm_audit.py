"""Cross-check the frontend lockfile against OSV, without going through npm.

`npm audit` posts the whole lockfile to the registry's advisory endpoint, which
in this environment is slow enough to time out. OSV's batch API answers the same
question for an explicit (name, version) list and is reachable here, so this
gives an independent second opinion on what `npm audit` reports in CI.

`--prod-only` restricts the check to packages that are not dev-only, which is
the set that actually ships in the frontend image -- the split that decides
whether a finding blocks a release or is only build-time noise.

Usage: python tools/osv_npm_audit.py [--prod-only] [path/to/package-lock.json]
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 500


def load_packages(lock_path: Path, *, prod_only: bool = False) -> list[tuple[str, str, bool]]:
    """``(name, version, dev_only)`` for every package in the lockfile."""
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    packages: dict[str, tuple[str, bool]] = {}
    for path, meta in (lock.get("packages") or {}).items():
        if not path or "node_modules/" not in path:
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        version = meta.get("version")
        if not name or not version:
            continue
        packages[f"{name}@{version}"] = (version, bool(meta.get("dev")))
    return [
        (key.rsplit("@", 1)[0], version, dev_only)
        for key, (version, dev_only) in sorted(packages.items())
        if not (prod_only and dev_only)
    ]


def query_osv(packages: list[tuple[str, str, bool]]) -> list[list[dict]]:
    results: list[list[dict]] = []
    for start in range(0, len(packages), BATCH_SIZE):
        chunk = packages[start : start + BATCH_SIZE]
        payload = {
            "queries": [
                {"package": {"name": name, "ecosystem": "npm"}, "version": version}
                for name, version, _dev in chunk
            ]
        }
        request = urllib.request.Request(
            OSV_BATCH,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            body = json.loads(response.read().decode("utf-8"))
        results.extend(result.get("vulns") or [] for result in body.get("results", []))
    return results


def main() -> int:
    args = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
    prod_only = "--prod-only" in sys.argv
    lock_path = Path(args[0] if args else "package-lock.json")

    packages = load_packages(lock_path, prod_only=prod_only)
    scope = "production" if prod_only else "all"
    print(f"packages in {lock_path.name} ({scope}): {len(packages)}")

    vulns = query_osv(packages)
    findings = [
        (name, version, dev_only, [v["id"] for v in hits])
        for (name, version, dev_only), hits in zip(packages, vulns)
        if hits
    ]
    if not findings:
        print("OSV: no advisories for any locked package")
        return 0

    prod_findings = [f for f in findings if not f[2]]
    print(
        f"OSV: {len(findings)} package(s) with advisories "
        f"({len(prod_findings)} in the production tree, "
        f"{len(findings) - len(prod_findings)} dev-only)"
    )
    for name, version, dev_only, ids in findings:
        tag = "dev-only" if dev_only else "PROD    "
        print(f"  [{tag}] {name}@{version}: {', '.join(ids)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

