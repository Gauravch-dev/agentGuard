from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .authority import sample_contract
from .platform import DockerLab, PlatformError, host_audit
from .server import make_server
from .workbench import Workbench


def main(argv=None):
    parser = argparse.ArgumentParser(description="AgentGuard 2.0 development workbench")
    parser.add_argument("--state-dir", default=".agentguard", help="trusted local state; never mount into capsule")
    sub = parser.add_subparsers(dest="action", required=True)
    audit = sub.add_parser("audit", help="inventory actual host capabilities; no installation")
    audit.add_argument("--output")
    sub.add_parser("demo", help="run synthetic broker policy harness, without an agent/container")
    serve = sub.add_parser("serve", help="start loopback investigation dashboard")
    serve.add_argument("--port", type=int, default=8765)
    sub.add_parser("verify", help="verify evidence integrity chain")
    lab = sub.add_parser("isolation-lab", help="real fixed Docker probes on a verified local Linux daemon")
    lab.add_argument("--image", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "audit":
            result = host_audit()
            if args.output:
                path = Path(args.output)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result, indent=2))
        elif args.action == "isolation-lab":
            result = DockerLab().isolation_lab(sample_contract("LAB-001"), args.image)
            output = Path(args.state_dir) / "lab-results"
            output.mkdir(parents=True, exist_ok=True)
            path = output / (result["capsule_id"] + ".json")
            path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result, indent=2))
        else:
            workbench = Workbench(args.state_dir)
            if args.action == "demo":
                contract = workbench.seed()
                result = workbench.harness(contract["task_id"])
                print(json.dumps(result, indent=2))
            elif args.action == "verify":
                print(json.dumps(workbench.store.verify(), indent=2))
            elif args.action == "serve":
                workbench.seed()
                server, token = make_server(workbench, args.port)
                print(f"AgentGuard: http://127.0.0.1:{server.server_port}", flush=True)
                print(f"Local access key: {token}", flush=True)
                print("Policy harness only. Protected agent execution is not ready.", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
                finally:
                    server.server_close()
    except (ValueError, KeyError, PlatformError, OSError) as exc:
        print(f"AgentGuard refused: {exc}", file=sys.stderr)
        return 1
    return 0
