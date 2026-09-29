import json
import tempfile
import unittest
from pathlib import Path

from harness.runtime.terraform_trace import (
    SanitizationError,
    TraceError,
    audit_no_secrets,
    compile_operations,
    derive_events,
    extract_derivative,
    parse_log_lines,
    trace_header,
    write_trace,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "terraform_trace"
BINDINGS = {"vpc-0abc1234567890def": "aws_vpc.main"}


def fixture_records():
    return parse_log_lines((FIXTURES / "expected-apply.log.jsonl").read_text())


def fixture_plan():
    return json.loads((FIXTURES / "expected-plan.json").read_text())


def compiled():
    return compile_operations(fixture_records(), fixture_plan(), BINDINGS,
                              command_succeeded=True)


class ParseTests(unittest.TestCase):
    def test_malformed_line_fails_closed(self):
        with self.assertRaises(TraceError):
            parse_log_lines('{"ok": 1}\nnot json\n')

    def test_fixture_parses_fully(self):
        self.assertEqual(len(fixture_records()), 16)


class DerivativeTests(unittest.TestCase):
    def test_only_http_records_enter_the_derivative_with_digests(self):
        events = derive_events(fixture_records())
        self.assertEqual(len(events), 16)
        for event in events:
            self.assertIn("raw_evidence_digest", event)

    def test_non_allowlisted_service_bodies_are_dropped(self):
        events = derive_events(fixture_records())
        sts = [e for e in events if e.get("rpc.service") == "STS"]
        self.assertTrue(sts)
        for event in sts:
            self.assertNotIn("http.request.body", event)
            self.assertNotIn("http.response.body", event)

    def test_extract_derivative_unlinks_raw_log_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.jsonl"
            good.write_text((FIXTURES / "expected-apply.log.jsonl").read_text())
            events = extract_derivative(good)
            self.assertTrue(events)
            self.assertFalse(good.exists())

            bad = Path(tmp) / "bad.jsonl"
            bad.write_text("not json\n")
            with self.assertRaises(TraceError):
                extract_derivative(bad)
            self.assertFalse(bad.exists())


class AuditTests(unittest.TestCase):
    def test_redacted_sensitive_keys_pass(self):
        audit_no_secrets({"SessionToken": {"$redacted_sha256": "ab"}})

    def test_unredacted_sensitive_key_fails(self):
        with self.assertRaises(SanitizationError):
            audit_no_secrets({"SessionToken": "FwoGZXIvYXdzE..."})

    def test_access_key_id_pattern_fails(self):
        with self.assertRaises(SanitizationError):
            audit_no_secrets({"note": "key AKIATEST000000000002 leaked"})


class CompileTests(unittest.TestCase):
    def test_pilot_apply_compiles_to_five_operations(self):
        ops = compiled()
        self.assertEqual(
            [(o.id, o.operation, o.kind) for o in ops],
            [("op-001", "CreateSecurityGroup", "mutation"),
             ("op-002", "RevokeSecurityGroupEgress", "mutation"),
             ("op-003", "RevokeSecurityGroupEgress", "benign_failed_mutation"),
             ("op-004", "AuthorizeSecurityGroupIngress", "mutation"),
             ("op-005", "AuthorizeSecurityGroupEgress", "mutation")])

    def test_reads_and_credential_calls_are_not_operations(self):
        methods = {o.operation for o in compiled()}
        self.assertNotIn("DescribeSecurityGroups", methods)
        self.assertNotIn("GetCallerIdentity", methods)

    def test_initial_binding_substitution_despite_trailing_newline(self):
        # Real provider bodies end with "\n"; the fixture reproduces that.
        create = compiled()[0]
        self.assertEqual(create.input["VpcId"], "${aws_vpc.main.id}")

    def test_reserved_ownership_tags_are_stripped_from_inputs(self):
        create = compiled()[0]
        self.assertNotIn("TagSpecifications", create.input)
        text = json.dumps([o.to_dict() for o in compiled()])
        self.assertNotIn("cloudgym:", text)

    def test_produced_id_substitution_and_dependencies(self):
        ops = compiled()
        create = ops[0]
        self.assertEqual(create.produces, {"GroupId": "${op-001.GroupId}"})
        for op in ops[1:]:
            self.assertEqual(op.input["GroupId"], "${op-001.GroupId}")
            self.assertEqual(op.depends_on, ("op-001",))

    def test_benign_failure_is_not_replayable_but_transition_survives(self):
        benign = compiled()[2]
        self.assertFalse(benign.replayable)
        self.assertEqual(benign.observed_status, 400)
        replayable = [o for o in compiled() if o.replayable]
        self.assertEqual(len(replayable), 4)

    def test_failed_command_refuses_compilation(self):
        with self.assertRaises(TraceError):
            compile_operations(fixture_records(), fixture_plan(), BINDINGS,
                               command_succeeded=False)

    def test_ambiguous_address_join_fails_closed(self):
        plan = fixture_plan()
        plan["resource_changes"].append({
            "address": "aws_security_group.other",
            "type": "aws_security_group",
            "change": {"actions": ["create"]}})
        with self.assertRaises(TraceError) as ctx:
            compile_operations(fixture_records(), plan, BINDINGS,
                               command_succeeded=True)
        self.assertIn("ambiguous", str(ctx.exception))

    def test_missing_response_for_mutation_fails_closed(self):
        records = [r for r in fixture_records()
                   if not (r.get("rpc.method") == "AuthorizeSecurityGroupEgress"
                           and "http.status_code" in r)]
        with self.assertRaises(TraceError):
            compile_operations(records, fixture_plan(), BINDINGS,
                               command_succeeded=True)

    def test_uncovered_planned_change_fails_closed(self):
        reads_only = [r for r in fixture_records()
                      if r.get("rpc.method", "").startswith(("Describe", "Get"))]
        with self.assertRaises(TraceError) as ctx:
            compile_operations(reads_only, fixture_plan(), BINDINGS,
                               command_succeeded=True)
        self.assertIn("no parsed mutating operation", str(ctx.exception))


class WriteTests(unittest.TestCase):
    def test_trace_file_round_trips(self):
        header = trace_header(run_id="r-1", seed_id="s-1", region="us-east-1",
                              terraform_version="1.15.4",
                              provider_version="5.100.0")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace" / "T_main.jsonl"
            write_trace(path, header, compiled())
            lines = [json.loads(l) for l in path.read_text().splitlines()]
        self.assertEqual(lines[0]["kind"], "canonical-operation-trace")
        self.assertEqual(lines[0]["capture"]["provider_log_level"],
                         "TF_LOG_PROVIDER=DEBUG")
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[1]["id"], "op-001")


if __name__ == "__main__":
    unittest.main()
