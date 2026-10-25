"""Inventory new curl probe dependencies against OSV's Debian advisory mirror.

Only public package/version metadata is sent to the vulnerability API. No image,
code, payroll, credential, runtime record or application data is uploaded. Unlisted combinations remain
unassessed, and this scan does not certify an entire image as vulnerability-free.
"""

import argparse
import hashlib
import json
import re
import urllib.request
from pathlib import Path

from agentguard.platform import command
from agentguard.schema import timestamp

PACKAGES = {
    "curl",
    "libbrotli1",
    "libcurl4",
    "libgssapi-krb5-2",
    "libk5crypto3",
    "libkeyutils1",
    "libkrb5-3",
    "libkrb5support0",
    "libldap-2.5-0",
    "libnghttp2-14",
    "libpsl5",
    "librtmp1",
    "libsasl2-2",
    "libsasl2-modules-db",
    "libssh2-1",
}


def run(image, output):
    if re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None:
        raise ValueError("Reviewed immutable local probe image ID required")
    os_release = command(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=128m",
            "--pids-limit=32",
            "--entrypoint=cat",
            image,
            "/etc/os-release",
        ]
    )
    identity = {
        key: value.strip('"')
        for line in os_release.splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
    }
    if identity.get("ID") != "debian" or identity.get("VERSION_ID") != "12":
        raise ValueError("This reviewed advisory mapping supports only actual Debian 12 images")
    inventory = command(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--label=agentguard.mode=dependency-review",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=128m",
            "--pids-limit=32",
            "--entrypoint=dpkg-query",
            image,
            "-W",
            "-f=${binary:Package}\t${source:Package}\t${source:Version}\n",
        ]
    )
    packages = []
    for line in inventory.splitlines():
        binary, source, version = line.split("\t")
        if binary.split(":")[0] in PACKAGES:
            packages.append({"binary": binary, "source": source, "source_version": version})
    url = "https://api.osv.dev/v1/querybatch"
    unique = sorted({(item["source"], item["source_version"]) for item in packages})
    queries = [
        {"package": {"ecosystem": "Debian:12", "name": source}, "version": version}
        for source, version in unique
    ]
    pending = queries
    findings, hashes = [], []
    for _ in range(5):
        if not pending:
            break
        request = urllib.request.Request(
            url,
            data=json.dumps({"queries": pending}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed official HTTPS metadata API
            content = response.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024:
            raise ValueError("Advisory metadata exceeded bounded size")
        hashes.append(hashlib.sha256(content).hexdigest())
        results = json.loads(content).get("results")
        if not isinstance(results, list) or len(results) != len(pending):
            raise ValueError("Vulnerability API returned an incomplete batch")
        next_queries = []
        for query, result in zip(pending, results, strict=True):
            for advisory in result.get("vulns", []):
                if not isinstance(advisory.get("id"), str):
                    raise ValueError("Invalid advisory identity")
                finding = {
                    "source": query["package"]["name"],
                    "installed_source_version": query["version"],
                    "advisory": advisory["id"],
                }
                if finding not in findings:
                    findings.append(finding)
            if result.get("next_page_token"):
                next_queries.append(query | {"page_token": result["next_page_token"]})
        pending = next_queries
    unknown = {query["package"]["name"] for query in pending}
    report = {
        "observed_at": timestamp(),
        "mode": "probe-image-new-apt-dependency-review",
        "image_id": image,
        "os_identity": {"id": identity["ID"], "version_id": identity["VERSION_ID"]},
        "metadata_source": url,
        "metadata_response_sha256": hashes,
        "packages": packages,
        "new_binary_packages_inventoried": len(packages),
        "source_version_queries": len(queries),
        "findings": findings,
        "unassessed_sources": sorted(unknown),
        "scan_completed": len(packages) == len(PACKAGES) and not pending,
        "production_image_certified": False,
        "scope": "15 newly installed probe-image packages only; default Finance image unchanged. Unlisted combinations and non-apt components unassessed. No exploitability or entire-image safety claim",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument(
        "--output", type=Path, default=Path("docs/linux/probe_dependency_review.json")
    )
    args = parser.parse_args()
    report = run(args.image_id, args.output)
    print(
        json.dumps(
            {
                "scan_completed": report["scan_completed"],
                "packages": len(report["packages"]),
                "advisory_findings": len(report["findings"]),
                "unassessed_sources": report["unassessed_sources"],
            }
        )
    )


if __name__ == "__main__":
    main()
