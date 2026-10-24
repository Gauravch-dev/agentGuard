from __future__ import annotations

import copy
from datetime import timedelta
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentguard.authority import Authority, sample_contract
from agentguard.brokers import Binding, BrokerDenied, BrokerSession, department_summary, request
from agentguard.platform import Check, DockerLab, PlatformError, verify_inspect
from agentguard.reconcile import reconcile
from agentguard.schema import ValidationError, canonical, event, strict_json, utcnow, validate_contract, validate_event
from agentguard.sensors import MappingError, TetragonNormalizer, Workload
from agentguard.server import make_server
from agentguard.store import IntegrityError, Store
from agentguard.transport import process_identity
from agentguard.workbench import Workbench

TEST_TMP = Path(__file__).resolve().parent.parent / ".agentguard" / "test-tmp"
TEST_TMP.mkdir(parents=True, exist_ok=True)


class TrustedState(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_TMP)
        self.addCleanup(self.temp.cleanup)
        self.workbench = Workbench(self.temp.name)
        self.store = self.workbench.store
        self.authority = self.workbench.authority
        self.contract = self.authority.approve(sample_contract())
        self.binding = Binding("FIN-001", 1, "test-capsule", "test-host", "policy-harness")
        self.broker = BrokerSession(self.store, self.authority, self.binding)

    def observation(self, **kwargs):
        defaults = dict(task_id="FIN-001", contract_version=1, capsule_id="test-capsule",
                        source="trusted_broker", event_type="broker_release", operation="data.get_department_totals",
                        verdict="allowed", effect="completed", coverage="complete")
        defaults.update(kwargs)
        return event(**defaults)


class ContractTests(TrustedState):
    def test_contract_round_trip_and_revision(self):
        self.assertEqual(self.authority.load("FIN-001"), self.contract)
        second = sample_contract(version=2)
        self.authority.approve(second)
        self.assertEqual(self.authority.load("FIN-001")["contract_version"], 2)
        self.assertEqual(self.authority.load("FIN-001", 1), self.contract)

    def test_contract_rejects_untrusted_approver(self):
        value = sample_contract("FIN-002")
        value["approved_by"] = "the-agent"
        with self.assertRaises(ValidationError):
            self.authority.approve(value)

    def test_contract_cannot_be_overwritten(self):
        with self.assertRaises(ValidationError):
            self.authority.approve(self.contract)
        with self.store.connect() as db, self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE contracts SET signature='fake'")

    def test_contract_signature_checked_not_just_task_id(self):
        with self.store.connect() as db:
            db.execute("DROP TRIGGER immutable_contract_update")
            db.execute("UPDATE contracts SET body=replace(body,'finance-reporting','admin')")
        with self.assertRaises(IntegrityError):
            self.authority.load("FIN-001")

    def test_expiry_blocks_approval_and_broker(self):
        expired = sample_contract("EXPIRED")
        expired["expires_at"] = (utcnow() - timedelta(seconds=1)).isoformat()
        with self.assertRaises(ValidationError):
            self.authority.approve(expired)
        with patch("agentguard.schema.utcnow", return_value=utcnow() + timedelta(hours=2)):
            with self.assertRaises(BrokerDenied):
                self.broker.request(request("data.get_department_totals", {}))

    def test_strict_contract_fields_and_limits(self):
        for mutate in (
            lambda c: c.update(direct_internet_allowed=True),
            lambda c: c.update(privileged=True),
            lambda c: c["limits"].update(max_processes=True),
            lambda c: c.update(allowed_operations=["data.raw_sql"]),
            lambda c: c.update(expires_at="2026-01-01T00:00:00"),
            lambda c: c.update(task_id="../escape"),
        ):
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(self.contract)
                mutate(value)
                with self.assertRaises(ValidationError):
                    validate_contract(value)

    def test_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for raw in ('{"task_id":"A","task_id":"B"}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValidationError):
                strict_json(raw)


class BrokerTests(TrustedState):
    def test_data_broker_aggregates_only(self):
        result = self.broker.request(request("data.get_department_totals", {}))["result"]
        self.assertEqual(result, department_summary())
        self.assertNotIn("salary", canonical(result))
        self.assertNotIn("name", canonical(result))

    def test_raw_rows_and_extra_keys_denied_at_approved_destination(self):
        payload = department_summary()
        payload["employees"] = [{"name": "secret", "salary": 123}]
        with self.assertRaises(BrokerDenied):
            self.broker.request(request("output.save_department_summary", payload))
        self.assertIsNone(self.store.report("test-capsule"))
        recorded = self.store.events()[-1]
        self.assertEqual((recorded["policy_verdict"], recorded["effect_status"]), ("denied", "blocked"))
        self.assertNotIn("secret", canonical(recorded))

    def test_forged_task_id_cannot_select_another_context(self):
        value = request("data.get_department_totals", {})
        value["task_id"] = "OTHER-TASK"
        with self.assertRaises(BrokerDenied):
            self.broker.request(value)
        self.assertEqual(self.store.events()[-1]["task_id"], "FIN-001")

    def test_sql_path_destination_injection_denied(self):
        for payload in ({"sql": "SELECT * FROM payroll"}, {"path": "/etc/shadow"}, {"destination": "https://example.invalid"}):
            with self.assertRaises(BrokerDenied):
                self.broker.request(request("data.get_department_totals", payload))

    def test_inaccurate_or_encoded_aggregate_denied(self):
        for bad_total in (True, float("nan"), -1, 80001):
            payload = department_summary()
            payload["departments"][0]["total"] = bad_total
            with self.assertRaises(BrokerDenied):
                self.broker.request(request("output.save_department_summary", payload))

    def test_scope_revocation_and_request_budget(self):
        self.broker.revoke()
        with self.assertRaisesRegex(BrokerDenied, "channel_revoked"):
            self.broker.request(request("data.get_department_totals", {}))
        other = BrokerSession(self.store, self.authority, self.binding)
        other._calls = 32
        with self.assertRaisesRegex(BrokerDenied, "budget"):
            other.request(request("data.get_department_totals", {}))

    def test_execution_deadline_is_enforced(self):
        self.broker._started -= 181
        with self.assertRaisesRegex(BrokerDenied, "deadline"):
            self.broker.request(request("data.get_department_totals", {}))

    def test_model_not_silently_simulated(self):
        payload = {"template_id": "department_summary_v1", "aggregates": department_summary()}
        with self.assertRaisesRegex(BrokerDenied, "not_configured"):
            self.broker.request(request("model.generate_report_draft", payload))

    def test_model_receives_only_approved_aggregates_and_is_bounded(self):
        received = []
        def provider(value):
            received.append(value)
            return "A draft, not released output"
        broker = BrokerSession(self.store, self.authority, self.binding, model_provider=provider)
        payload = {"template_id": "department_summary_v1", "aggregates": department_summary()}
        self.assertFalse(broker.request(request("model.generate_report_draft", payload))["result"]["released"])
        broker.request(request("model.generate_report_draft", payload))
        with self.assertRaisesRegex(BrokerDenied, "budget"):
            broker.request(request("model.generate_report_draft", payload))
        self.assertEqual(received, [department_summary(), department_summary()])

    def test_protected_output_holds_on_missing_sensor(self):
        binding = Binding("FIN-001", 1, "protected", "test-host", "protected")
        broker = BrokerSession(self.store, self.authority, binding)
        with self.assertRaisesRegex(BrokerDenied, "coverage"):
            broker.request(request("output.save_department_summary", department_summary()))
        self.assertIsNone(self.store.report("protected"))

    def test_business_success_and_blocked_attempt_coexist(self):
        result = self.workbench.harness("FIN-001")
        self.assertEqual(result["run"]["outcome"], "completed")
        self.assertEqual(set(result["assessment"]["classifications"]), {"Blocked", "Aligned", "Unverified"})
        self.assertTrue(all(e["source"] != "host_sensor" for e in result["events"]))

    def test_fresh_runs_do_not_reuse_reports_or_identity(self):
        one, two = self.workbench.harness("FIN-001"), self.workbench.harness("FIN-001")
        self.assertNotEqual(one["run"]["capsule_id"], two["run"]["capsule_id"])
        self.assertTrue(set(e["event_id"] for e in one["events"]).isdisjoint(e["event_id"] for e in two["events"]))


class EvidenceTests(TrustedState):
    def test_chain_dedup_and_conflicting_replay(self):
        value = self.observation()
        self.assertTrue(self.store.append(value))
        value["received_at"] = utcnow().isoformat()
        self.assertFalse(self.store.append(value))
        self.assertEqual(self.store.verify()["verified_events"], 1)
        value["effect_status"] = "blocked"
        with self.assertRaises(IntegrityError):
            self.store.append(value)

    def test_same_source_id_in_different_sources_is_distinct(self):
        value = self.observation()
        self.store.append(value)
        value["source"] = "host_sensor"
        self.store.append(value)
        self.assertEqual(self.store.verify()["verified_events"], 2)

    def test_sql_mutation_and_tampering_detected(self):
        self.store.append(self.observation())
        with self.store.connect() as db, self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM events")
        with self.store.connect() as db:
            db.execute("DROP TRIGGER immutable_event_update")
            db.execute("UPDATE events SET body=replace(body,'completed','blocked')")
        with self.assertRaises(IntegrityError):
            self.store.verify()

    def test_index_tampering_detected(self):
        self.store.append(self.observation())
        with self.store.connect() as db:
            db.execute("DROP TRIGGER immutable_event_update")
            db.execute("UPDATE events SET task_id='OTHER'")
        with self.assertRaises(IntegrityError):
            self.store.verify()

    def test_malformed_event_not_ingested(self):
        value = self.observation()
        value["source"] = "agent_claim"
        with self.assertRaises(ValidationError):
            self.store.append(value)

    def test_concurrent_append_keeps_global_chain_valid(self):
        errors = []
        def append():
            try:
                self.store.append(self.observation())
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=append) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.store.verify()["verified_events"], 12)


class ReconciliationTests(TrustedState):
    def test_blocked_remains_blocked_when_coverage_missing(self):
        value = self.observation(verdict="denied", effect="blocked", coverage="unavailable")
        result = reconcile(self.contract, [value], outcome="completed")
        self.assertIn("Blocked", result["classifications"])
        self.assertIn("Unverified", result["classifications"])
        self.assertEqual(result["business_outcome"], "completed")

    def test_empty_log_never_establishes_safety(self):
        self.assertEqual(reconcile(self.contract, [])["classifications"], ["Unverified"])

    def test_forged_host_denial_is_not_trusted_enforcement(self):
        value = self.observation(source="host_sensor", verdict="denied", effect="blocked")
        self.assertNotIn("Blocked", reconcile(self.contract, [value])["classifications"])

    def test_unexplained_flow_does_not_assert_data_leak(self):
        value = self.observation(source="network_sensor", event_type="egress_flow", operation="connect",
                                 verdict="not_applicable", effect="observed", coverage="partial",
                                 process_identity={"pid": 22, "start_time": utcnow().isoformat(), "cgroup_id": "cg-test"})
        result = reconcile(self.contract, [value])
        self.assertIn("Unexplained", result["classifications"])
        self.assertNotIn("Aligned", result["classifications"])

    def test_contract_version_mismatch_unverified(self):
        value = self.observation(contract_version=2)
        self.assertEqual(reconcile(self.contract, [value])["classifications"], ["Unverified"])

    def test_failed_integrity_ignores_apparent_alignment(self):
        result = reconcile(self.contract, [self.observation()], integrity_ok=False)
        self.assertEqual(result["classifications"], ["Unverified"])


class SensorTests(unittest.TestCase):
    def setUp(self):
        self.now = utcnow()
        self.workload = Workload("a" * 64, "trusted-cgroup", "FIN-001", 1, "capsule-one", "linux-one", (self.now - timedelta(seconds=10)).isoformat())
        self.normalizer = TetragonNormalizer("trusted-sensor", [self.workload])
        self.raw = {"time": self.now.isoformat(), "process_exec": {"process": {"docker": "a" * 12, "pid": 234, "binary": "/usr/bin/python", "arguments": "DO-NOT-LOG", "start_time": (self.now - timedelta(seconds=2)).isoformat()}}}

    def test_real_schema_shape_normalizes_without_arguments(self):
        value = self.normalizer.normalize(self.raw, "protected-file:offset-20")
        self.assertEqual(value["source"], "host_sensor")
        self.assertEqual(value["coverage_status"], "partial")
        self.assertEqual(value["process_identity"]["cgroup_id"], "trusted-cgroup")
        self.assertNotIn("DO-NOT-LOG", canonical(value))
        self.assertEqual(value["event_id"], self.normalizer.normalize(self.raw, "protected-file:offset-20")["event_id"])

    def test_unmapped_container_cannot_choose_task(self):
        self.raw["process_exec"]["process"]["docker"] = "b" * 12
        self.raw["task_id"] = "FIN-001"
        with self.assertRaises(MappingError):
            self.normalizer.normalize(self.raw, "raw-1")

    def test_pid_reuse_and_stale_lifecycle_are_rejected(self):
        self.raw["process_exec"]["process"]["start_time"] = (self.now - timedelta(hours=1)).isoformat()
        with self.assertRaises(MappingError):
            self.normalizer.normalize(self.raw, "raw-2")

    def test_ambiguous_container_prefix_is_rejected(self):
        ambiguous = Workload("a" * 12 + "b" * 52, "other", "OTHER", 1, "other", "linux-one", self.workload.started_at)
        normalizer = TetragonNormalizer("sensor", [self.workload, ambiguous])
        with self.assertRaises(MappingError):
            normalizer.normalize(self.raw, "raw-3")

    def test_unsupported_hook_not_fabricated(self):
        with self.assertRaises(MappingError):
            self.normalizer.normalize({"process_kprobe": {}}, "raw-4")

    def test_proc_stat_command_parentheses_do_not_break_start_identity(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as directory:
            process = Path(directory) / "123"
            process.mkdir()
            fields = ["S"] + ["0"] * 18 + ["987654"] + ["0"] * 4
            (process / "stat").write_text("123 (name with ) parentheses) " + " ".join(fields))
            (process / "cgroup").write_text("0::/agentguard/capsule\n")
            self.assertEqual(process_identity(123, Path(directory))["start_ticks"], "987654")


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.contract = sample_contract()
        self.image = "sha256:" + "1" * 64
        self.info = {"Image": self.image, "Mounts": [], "Config": {"User": "65532:65532", "Entrypoint": ["python", "-I", "/opt/agentguard/isolation_probe.py"], "Cmd": [], "WorkingDir": "/work"}, "HostConfig": {
            "NetworkMode": "none", "Privileged": False, "ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": [], "SecurityOpt": ["no-new-privileges:true"],
            "Memory": 768 * 1024**2, "MemorySwap": 768 * 1024**2, "PidsLimit": 64, "NanoCpus": 1_000_000_000,
            "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private", "Binds": [],
            "Tmpfs": {p: "rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=700" for p in ("/tmp", "/work")},
            "LogConfig": {"Type": "local", "Config": {"max-size": "1m"}},
        }}

    def test_profile_is_fixed_and_pinned(self):
        args = DockerLab.create_args(self.contract, self.image, "lab-" + "a" * 32)
        self.assertIn("--network=none", args)
        self.assertIn("--pull=never", args)
        self.assertNotIn("--privileged", args)
        self.assertFalse(any(arg.startswith("--volume") for arg in args))
        with self.assertRaises(PlatformError):
            DockerLab.create_args(self.contract, "python:latest", "lab-" + "a" * 32)

    def test_effective_profile_detects_runtime_drift(self):
        self.assertEqual(verify_inspect(self.info, self.contract, self.image), [])
        for field, value in (("Privileged", True), ("NetworkMode", "bridge"), ("PidsLimit", 0), ("ReadonlyRootfs", False), ("Binds", ["/:/host"]), ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", ["seccomp=unconfined"])):
            info = copy.deepcopy(self.info)
            info["HostConfig"][field] = value
            with self.subTest(field=field):
                self.assertTrue(verify_inspect(info, self.contract, self.image))

    def test_preflight_failure_never_creates_container(self):
        calls = []
        lab = DockerLab(runner=lambda args: calls.append(args))
        with patch.object(lab, "preflight", return_value=[Check("sensor", "failed", "offline")]):
            with self.assertRaises(PlatformError):
                lab.isolation_lab(self.contract, "image")
        self.assertEqual(calls, [])

    def test_windows_has_no_unrestricted_fallback(self):
        with patch("agentguard.platform.host_platform.system", return_value="Windows"):
            self.assertEqual(DockerLab().preflight()[0].status, "failed")

    def test_termination_request_does_not_prove_descendants_stopped(self):
        lab = DockerLab()
        with self.assertRaisesRegex(PlatformError, "Unverified"):
            lab.terminate("a" * 64, None)

    def test_cgroup_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as directory:
            root = Path(directory)
            (root / "proc" / "123").mkdir(parents=True)
            (root / "cgroups").mkdir()
            (root / "proc" / "123" / "cgroup").write_text("0::/../../outside\n")
            lab = DockerLab(proc_root=root / "proc", cgroup_root=root / "cgroups")
            with self.assertRaises(PlatformError):
                lab._cgroup(123)


class APITests(TrustedState):
    def setUp(self):
        super().setUp()
        self.server, self.token = make_server(self.workbench, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def call(self, path, method="GET", body=None, *, authenticated=True, extra_headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        headers.update(extra_headers or {})
        connection.request(method, path, canonical(body) if body is not None else None, headers)
        response = connection.getresponse()
        raw = response.read()
        status, content_type = response.status, response.getheader("Content-Type")
        connection.close()
        return status, strict_json(raw) if content_type == "application/json" else raw

    def test_local_key_required_for_api(self):
        self.assertEqual(self.call("/api/v1/snapshot", authenticated=False)[0], 401)
        self.assertEqual(self.call("/api/v1/snapshot")[0], 200)

    def test_dns_rebinding_and_foreign_origin_rejected(self):
        self.assertEqual(self.call("/api/v1/snapshot", extra_headers={"Host": "attacker.invalid"})[0], 403)
        self.assertEqual(self.call("/api/v1/tasks/FIN-001/harness", "POST", {}, extra_headers={"Origin": "https://attacker.invalid"})[0], 403)

    def test_launch_refuses_without_falling_back_to_harness(self):
        status, value = self.call("/api/v1/tasks/FIN-001/launch", "POST", {})
        self.assertEqual(status, 409)
        self.assertFalse(value["capsule_started"])
        self.assertEqual(self.store.runs(), [])

    def test_no_http_endpoint_can_forge_sensor_evidence(self):
        self.assertEqual(self.call("/api/v1/events", "POST", {"source": "host_sensor"})[0], 404)
        self.assertEqual(self.store.events(), [])

    def test_harness_and_result_end_to_end(self):
        status, result = self.call("/api/v1/tasks/FIN-001/harness", "POST", {})
        self.assertEqual(status, 200)
        self.assertIn("Unverified", result["assessment"]["classifications"])
        self.assertEqual(self.call("/api/v1/tasks/FIN-001/result")[1]["run"]["capsule_id"], result["run"]["capsule_id"])

    def test_harness_rejects_agent_code_and_runtime_options(self):
        self.assertEqual(self.call("/api/v1/tasks/FIN-001/harness", "POST", {"command": "anything"})[0], 400)

    def test_only_fixed_dashboard_assets_are_served(self):
        self.assertEqual(self.call("/", authenticated=False)[0], 200)
        self.assertEqual(self.call("/../.agentguard/authority.key")[0], 404)


if __name__ == "__main__":
    unittest.main()
