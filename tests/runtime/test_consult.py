"""The `consult` awareness level: policy withheld from the prompt, asked for at runtime.

The invariants worth pinning are the negative ones. A principal must not answer before its
program has landed, must not answer a question that does not name what it touched, the
requester's own words must never route, and the resolution text must not reach the agent
through any other level's tool. The positive ones are about delivery: a reply that arrives
after the ask is handed over on the next call, and what is never read is counted.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from harness.awareness import AWARENESS_LEVELS, AWARENESS_TOOL_NAMES, AWARENESS_TOOLS
from harness.runtime.consult import (ConsultChannel, cites, excluded_terms, fingerprint_facts,
                                     harvest_identifiers, match_principals)
from harness.runtime.coordinator import RuntimeCoordinator


def _principal(pid, *, role, resolution, subject):
    return {"principal": pid, "role": role, "responsibility": "r", "intent": "i",
            "resolution": resolution, "subject": list(subject)}


LOCKS = _principal("shared-lock-table", role="sibling developer",
                   resolution="Locking is one table for the whole account.",
                   subject=("lock table", "shared-terraform-locks"))
CATALOGUE = _principal("store-cataloguing", role="data governance analyst",
                       resolution="Every data store says who owns it.",
                       subject=("owner", "classification"))


class MatchTests(unittest.TestCase):
    ALL = {"shared-lock-table", "store-cataloguing"}

    def test_answers_only_about_what_the_question_names(self):
        out = match_principals("the lock table", [LOCKS, CATALOGUE], landed=self.ALL)
        self.assertEqual([r["from"] for r in out], ["sibling developer"])
        self.assertIn("one table for the whole account", out[0]["text"])

    def test_a_subject_occurring_in_the_question_matches(self):
        for phrasing in ("shared-terraform-locks", "the existing lock table in the account",
                         "LOCK TABLE", "  the   lock\ttable "):
            self.assertEqual(len(match_principals(phrasing, [LOCKS], landed=self.ALL)), 1, phrasing)

    def test_via_kind_says_what_answered(self):
        out = match_principals("the lock table", [LOCKS], landed=self.ALL)
        self.assertEqual(out[0]["via_kind"], "subject")
        out = match_principals("who owns tf-locks-9f3a1c?", [LOCKS], landed=self.ALL,
                               touched={"shared-lock-table": ["tf-locks-9f3a1c"]})
        self.assertEqual((out[0]["via"], out[0]["via_kind"]), ("tf-locks-9f3a1c", "identifier"))

    def test_matching_is_one_directional(self):
        # The reverse test (question occurs in subject) makes every short string a
        # substring of nearly every subject: with it, about="a" returned all four of case
        # 108's resolutions at once. A short form the case wants to accept is declared.
        self.assertEqual(match_principals("lock", [LOCKS], landed=self.ALL), [])
        self.assertEqual(len(match_principals("lock table", [LOCKS], landed=self.ALL)), 1)

    def test_a_fragment_answers_nothing(self):
        for fragment in ("a", "e", "??", " x ", "", None):
            self.assertEqual(match_principals(fragment, [LOCKS, CATALOGUE], landed=self.ALL), [], repr(fragment))

    def test_silent_before_the_program_has_landed(self):
        self.assertEqual(match_principals("the lock table", [LOCKS], landed=set()), [])
        self.assertEqual(len(match_principals("the lock table", [LOCKS], landed=set(), require_landed=False)), 1)

    def test_touched_identifiers_route_once_landed(self):
        # Nothing declares the table's physical name; the principal's write carried it.
        touched = {"shared-lock-table": {"tf-locks-9f3a1c"}}
        self.assertEqual(len(match_principals("who owns tf-locks-9f3a1c?", [LOCKS], landed=self.ALL, touched=touched)), 2 - 1)
        # Not landed: the identifier does not exist yet, and even the open gate cannot use it.
        self.assertEqual(match_principals("who owns tf-locks-9f3a1c?", [LOCKS], landed=set(),
                                          touched=touched, require_landed=False), [])

    def test_the_requesters_own_words_never_route(self):
        # The utterance gave the bucket prefix; a principal whose write carried it would
        # otherwise answer every question, because every question repeats it.
        bucket = _principal("migration", role="ops", resolution="The old store stays.",
                            subject=("cutover",))
        touched = {"migration": {"iac-misc-terraform-state-1234"}}
        excluded = excluded_terms("Set up the bucket named `iac-misc-terraform-state-1234`.")
        self.assertEqual(match_principals("versioning on iac-misc-terraform-state-1234?", [bucket],
                                          landed={"migration"}, touched=touched, excluded=excluded), [])
        self.assertEqual(len(match_principals("what about the cutover?", [bucket], landed={"migration"},
                                              touched=touched, excluded=excluded)), 1)

    def test_a_question_naming_two_subjects_reaches_both(self):
        both = match_principals("the owner records on the lock table", [LOCKS, CATALOGUE], landed=self.ALL)
        self.assertEqual({r["from"] for r in both}, {"sibling developer", "data governance analyst"})

    def test_harvest_splits_arns_and_keeps_slash_names(self):
        found = harvest_identifiers({"arn": "arn:aws:logs:us-east-1:000000000114:log-group:/aws/route53/central-dns-audit",
                                     "store": "/aws/route53/example53.com"})
        self.assertIn("/aws/route53/central-dns-audit", found)
        self.assertIn("central-dns-audit", found)
        self.assertIn("/aws/route53/example53.com", found)
        self.assertNotIn("us-east-1", found)
        self.assertNotIn("000000000114", found)
        self.assertNotIn("log-group", found)

    def test_harvest_keeps_identifiers_and_drops_words(self):
        found = harvest_identifiers({"HostedZoneId": "Z07975712XHJ5JEJWOE3I", "status": "succeeded",
                                     "arn": "arn:aws:logs:us-east-1:1:log-group:/aws/route53/x",
                                     "tags": [{"Key": "Owner", "Value": "cc-8802"}], "n": 3,
                                     "note": "moved zone Z0912487289IY0UX0UO01 today"})
        self.assertIn("Z07975712XHJ5JEJWOE3I", found)
        self.assertIn("Z0912487289IY0UX0UO01", found)
        self.assertIn("cc-8802", found)
        self.assertNotIn("succeeded", found)
        self.assertNotIn("Owner", found)


class FingerprintMatchTests(unittest.TestCase):
    """Fingerprint mode (the ``consult`` level since 2026-09-18): a principal answers only a
    question that cites a fact its program returned, not one that names its topic."""

    RETENTION = _principal("dns-log-retention-term", role="data governance analyst",
                           resolution="Read the term off the existing store.",
                           subject=("retention", "how long"))
    FACTS = {"dns-log-retention-term": ["731"]}

    def test_the_topic_word_no_longer_routes(self):
        # The question every recorded cell opened with: it routed via `retention` and the
        # late-delivered reply handed over the policy before anything had been observed.
        out = match_principals("Is there a retention convention for log groups under this prefix?",
                               [self.RETENTION], landed={"dns-log-retention-term"}, fingerprints=self.FACTS)
        self.assertEqual(out, [])

    def test_citing_the_fact_routes(self):
        out = match_principals("the shared store is now kept for 731 days; should mine match?",
                               [self.RETENTION], landed={"dns-log-retention-term"}, fingerprints=self.FACTS)
        self.assertEqual([r["via"] for r in out], ["731"])

    def test_a_fact_is_a_whole_token(self):
        for msg, hit in (("731-day retention", True), ("(731)", True), ("kept 17318 days", False),
                         ("sgr-731abc", False), ("retention: 731", True)):
            self.assertEqual(cites(msg, "731"), hit, msg)
        self.assertTrue(cites("Owner=UNASSIGNED on my group", "unassigned"))
        self.assertTrue(cites('an egress rule described "package  mirror" appeared', "package mirror"))

    def test_not_landed_means_no_fact_to_cite(self):
        out = match_principals("kept for 731 days now", [self.RETENTION], landed=set(),
                               fingerprints=self.FACTS, require_landed=False)
        self.assertEqual(out, [])

    def test_excluded_and_unobserved_facts_do_not_route(self):
        msg = "kept for 731 days now"
        self.assertEqual(match_principals(msg, [self.RETENTION], landed={"dns-log-retention-term"},
                                          fingerprints=self.FACTS, excluded={"731"}), [])
        self.assertEqual(match_principals(msg, [self.RETENTION], landed={"dns-log-retention-term"},
                                          fingerprints=self.FACTS, observed=lambda pid, f: False), [])
        self.assertEqual(len(match_principals(msg, [self.RETENTION], landed={"dns-log-retention-term"},
                                              fingerprints=self.FACTS, observed=lambda pid, f: f == "731")), 1)

    def test_fingerprint_facts_come_only_from_the_declared_key(self):
        self.assertEqual(fingerprint_facts({"republished": 731, "fingerprint": ["731", None, " "]}), {"731": "731"})
        self.assertEqual(fingerprint_facts({"republished": 731}), {})
        self.assertEqual(fingerprint_facts({"fingerprint": "Z0B"}), {"Z0B": "Z0B"})
        self.assertEqual(fingerprint_facts(None), {})

    def test_a_fact_may_be_said_differently_from_how_it_is_seen(self):
        facts = fingerprint_facts({"fingerprint": [{"say": ["PITR", "point-in-time recovery"],
                                                    "seen": '"PointInTimeRecoveryStatus":"ENABLED"'}]})
        self.assertEqual(facts, {"PITR": '"PointInTimeRecoveryStatus":"ENABLED"',
                                 "point-in-time recovery": '"PointInTimeRecoveryStatus":"ENABLED"'})
        seen_asked = []
        out = match_principals("PITR got switched on for my table; expected?", [self.RETENTION],
                               landed={"dns-log-retention-term"}, fingerprints={"dns-log-retention-term": facts},
                               observed=lambda pid, seen: seen_asked.append(seen) or True)
        self.assertEqual([r["via"] for r in out], ["PITR"])
        self.assertEqual(seen_asked, ['"PointInTimeRecoveryStatus":"ENABLED"'])


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _channel(principals, landed, *, require_landed=True, touched=None, excluded=()):
    clock = _Clock()
    ch = ConsultChannel(principals=lambda: principals, landed=lambda: set(landed),
                        touched=lambda pid: set((touched or {}).get(pid, ())), clock=clock,
                        require_landed=require_landed, excluded=excluded)
    return ch, clock


class ChannelTests(unittest.TestCase):
    def test_every_ask_opens_a_thread_even_in_silence(self):
        ch, _ = _channel([LOCKS], landed=set())
        out = ch.ask("the lock table", "should I reuse it?")
        self.assertEqual(out["thread"], "t1")
        self.assertEqual(out["replies"], [])
        self.assertEqual(out["earlier_threads"], [])

    def test_a_late_reply_is_delivered_with_the_next_call(self):
        landed = set()
        ch, clock = _channel([LOCKS, CATALOGUE], landed)
        first = ch.ask("the lock table", "reuse it?")
        self.assertEqual(first["replies"], [])
        landed.add("shared-lock-table")
        clock.t = 90.0
        second = ch.ask("classification", "owner tags on the bucket?")
        self.assertEqual(second["replies"], [])            # catalogue has not landed
        self.assertEqual(second["earlier_threads"], [{
            "thread": "t1", "about": "the lock table",
            "replies": [{"from": "sibling developer", "text": LOCKS["resolution"]}]}])
        # Delivered once: the next call does not repeat it.
        third = ch.ask("t2", thread="t2") if False else ch.ask(thread="t2")
        self.assertEqual(third["earlier_threads"], [])
        summary = ch.summary()
        self.assertEqual(summary["replies_delivered"], 1)
        self.assertEqual(summary["replies_delivered_late"], 1)

    def test_rereading_a_thread_returns_everything_on_it(self):
        landed = {"shared-lock-table"}
        ch, _ = _channel([LOCKS], landed)
        ch.ask("the lock table", "reuse?")
        again = ch.ask(thread="t1")
        self.assertEqual(again["thread"], "t1")
        self.assertEqual([r["from"] for r in again["replies"]], ["sibling developer"])
        self.assertIn("error", ch.ask(thread="t9"))

    def test_unread_counts_what_was_never_collected(self):
        landed = set()
        ch, _ = _channel([LOCKS], landed)
        ch.ask("the lock table", "reuse?")
        self.assertEqual(ch.summary()["unread_replies_at_finish"], 0)
        landed.add("shared-lock-table")
        # The agent finishes without another call: the answer was there, unread.
        summary = ch.summary()
        self.assertEqual(summary["unread_replies_at_finish"], 1)
        self.assertEqual(summary["unread_at_finish"][0]["principals"], ["shared-lock-table"])
        self.assertEqual(summary["replies_delivered"], 0)   # unread() records no delivery

    def test_open_gate_answers_before_landing(self):
        ch, _ = _channel([LOCKS], landed=set(), require_landed=False)
        self.assertEqual(len(ch.ask("the lock table")["replies"]), 1)

    def test_a_blank_ask_opens_no_thread_but_still_delivers(self):
        landed = set()
        ch, _ = _channel([LOCKS], landed)
        ch.ask("the lock table")
        landed.add("shared-lock-table")
        out = ch.ask("")
        self.assertIsNone(out["thread"])
        self.assertEqual(len(out["earlier_threads"]), 1)
        self.assertEqual(len(ch.threads), 1)

    def test_resolution_never_leaks_through_the_public_roster(self):
        public = [{k: v for k, v in p.items() if k not in ("resolution", "subject")} for p in (LOCKS, CATALOGUE)]
        blob = repr(public)
        self.assertNotIn("resolution", blob)
        self.assertNotIn("one table for the whole account", blob)


class _FakeController:
    def __init__(self, principals, responses=()):
        self._principals = principals
        self._responses = list(responses)   # (monotonic_ns, call_id)

    def roster(self, *, private=False):
        return list(self._principals) if private else []

    def touched_by(self, pid):
        return set()

    def elapsed_s(self):
        return 1.0

    def main_responses_since(self, monotonic_ns):
        return [c for at, c in self._responses if at >= monotonic_ns]


class CoordinatorTests(unittest.TestCase):
    """The subject-mode paths, exercised through ``consult_open`` (require_landed=False)
    where they still run, plus the gate invariants."""

    def _coordinator(self, statuses):
        c = RuntimeCoordinator.__new__(RuntimeCoordinator)
        c.controller = _FakeController([LOCKS])
        c.scheduler = SimpleNamespace(summary=lambda: {k: {"status": v} for k, v in statuses.items()})
        c.config = SimpleNamespace(consult_excluded_terms=())
        c.consult_channel = None
        c._s0_terms = frozenset()
        c._observed_cache = {}
        return c

    def test_gated_by_status(self):
        # At the gated level only a landed program has a fingerprint to cite. The
        # observation check is stubbed out here; FingerprintGateTests covers it.
        result = {"table": "tf-locks-9f3a1c", "fingerprint": ["tf-locks-9f3a1c"]}
        for status in ("not-fired", "no-op", "failed"):
            c = self._coordinator({"shared-lock-table": status})
            c._observed_by_agent = lambda pid, fact: True
            self.assertEqual(c.consult("who owns tf-locks-9f3a1c?")["replies"], [], status)
        c = self._coordinator({"shared-lock-table": "succeeded"})
        c.scheduler = SimpleNamespace(summary=lambda: {"shared-lock-table": {
            "status": "succeeded", "result": result, "outcomes": [{"status": "succeeded", "result": result}]}})
        c._observed_by_agent = lambda pid, fact: True
        self.assertEqual(len(c.consult("who owns tf-locks-9f3a1c?")["replies"]), 1)
        # Subject mode (consult_open) answers whether or not the program landed.
        c = self._coordinator({"shared-lock-table": "not-fired"})
        self.assertEqual(len(c.consult("the lock table", require_landed=False)["replies"]), 1)

    def test_the_gate_is_fixed_for_the_run(self):
        c = self._coordinator({"shared-lock-table": "succeeded"})
        c.consult("the lock table", require_landed=True)
        with self.assertRaises(RuntimeError):
            c.consult("the lock table", require_landed=False)

    def test_evidence_dict_routes_a_question_naming_the_object(self):
        # Subject mode (consult_open): the program's own return value says which objects it
        # touched, because distractor calls are journaled without decoded parameters.
        c = self._coordinator({"shared-lock-table": "succeeded"})
        c.scheduler = SimpleNamespace(summary=lambda: {"shared-lock-table": {
            "status": "succeeded", "result": {"table": "tf-locks-9f3a1c", "created": True},
            "outcomes": [{"status": "succeeded", "result": {"table": "tf-locks-9f3a1c"}}]}})
        self.assertEqual(len(c.consult("who owns tf-locks-9f3a1c?", require_landed=False)["replies"]), 1)

    def test_seed_identifiers_never_route(self):
        # The evidence dict names the seed VPC the program worked inside; every question on
        # the case names that VPC too, so it must not be a routing key.
        c = self._coordinator({"shared-lock-table": "succeeded"})
        c.scheduler = SimpleNamespace(summary=lambda: {"shared-lock-table": {
            "status": "succeeded", "result": {"vpc": "vpc-0abc123def456", "rule": "sgr-0fedcba987654"},
            "outcomes": []}})
        c._s0_terms = frozenset({"vpc-0abc123def456"})
        self.assertEqual(c.consult("anything about vpc-0abc123def456?", require_landed=False)["replies"], [])
        self.assertEqual(len(c.consult("who added sgr-0fedcba987654?", require_landed=False)["replies"]), 1)


class FingerprintGateTests(unittest.TestCase):
    """The ``consult`` level end to end: fingerprint from run()'s result, the agent's stored
    response bodies as proof of observation, landing time as the cut-off."""

    RETENTION = _principal("dns-log-retention-term", role="data governance analyst",
                           resolution="Read the term off the existing store.",
                           subject=("retention",))

    def setUp(self):
        import tempfile
        from pathlib import Path
        self._tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self._tmp.name)
        (self.run_dir / "private" / "api").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _response(self, call_id, body: bytes):
        (self.run_dir / "private" / "api" / f"{call_id}.res").write_bytes(
            b"200 \ncontent-type: application/x-amz-json-1.1\n\n" + body)

    def _coordinator(self, *, landed_ns, responses, result=None):
        c = RuntimeCoordinator.__new__(RuntimeCoordinator)
        c.controller = _FakeController([self.RETENTION], responses)
        result = result or {"republished": 731, "was": 365, "fingerprint": ["731"]}
        c.scheduler = SimpleNamespace(summary=lambda: {"dns-log-retention-term": {
            "status": "succeeded", "result": result,
            "outcomes": [{"status": "succeeded", "result": result, "landed_ns": landed_ns}]}})
        c.config = SimpleNamespace(consult_excluded_terms=())
        c.consult_channel = None
        c._s0_terms = frozenset()
        c._observed_cache = {}
        c.run_dir = self.run_dir
        return c

    def test_cited_and_read_after_landing_routes(self):
        self._response("c2", b'{"logGroups":[{"logGroupName":"/aws/route53/central-dns-audit","retentionInDays":731}]}')
        c = self._coordinator(landed_ns=1000, responses=[(2000, "c2")])
        out = c.consult("the shared store", "it is kept for 731 days now, it was 365 — should mine match?")
        self.assertEqual([r["from"] for r in out["replies"]], ["data governance analyst"])
        self.assertEqual(c.consult_channel.summary()["gate"], "fingerprint")

    def test_the_topic_question_stays_silent_even_after_landing(self):
        self._response("c2", b'{"logGroups":[{"retentionInDays":731}]}')
        c = self._coordinator(landed_ns=1000, responses=[(2000, "c2")])
        self.assertEqual(c.consult("log groups", "any retention convention under this prefix?")["replies"], [])

    def test_cited_but_never_read_does_not_route(self):
        c = self._coordinator(landed_ns=1000, responses=[])
        self.assertEqual(c.consult("store", "kept for 731 days now?")["replies"], [])

    def test_a_read_before_landing_does_not_count(self):
        self._response("c1", b'{"logGroups":[{"retentionInDays":731}]}')
        c = self._coordinator(landed_ns=5000, responses=[(2000, "c1")])
        self.assertEqual(c.consult("store", "kept for 731 days now?")["replies"], [])

    def test_a_numeric_fact_must_be_a_value_not_a_digit_run(self):
        self._response("c2", b'{"timestamp":"2026-09-18T22:59:10.731Z","requestId":"7317-731a"}')
        c = self._coordinator(landed_ns=1000, responses=[(2000, "c2")])
        self.assertEqual(c.consult("store", "kept for 731 days now?")["replies"], [])
        self._response("c3", b"<retentionInDays>731</retentionInDays>")
        c = self._coordinator(landed_ns=1000, responses=[(2000, "c3")])
        self.assertEqual(len(c.consult("store", "kept for 731 days now?")["replies"]), 1)

    def test_a_string_fact_matches_case_insensitively_as_a_token(self):
        self._response("c2", b'{"tags":{"Owner":"unassigned","CostCenter":"unassigned"}}')
        result = {"stamped": [{"store": "/aws/route53/example53.com"}], "fingerprint": ["unassigned"]}
        c = self._coordinator(landed_ns=1000, responses=[(2000, "c2")], result=result)
        c.controller = _FakeController([_principal("dns-log-retention-term", role="platform engineer",
                                                    resolution="Take the values the zone and the store agree on.",
                                                    subject=("owner",))], [(2000, "c2")])
        self.assertEqual(len(c.consult("my group", "it now carries Owner=Unassigned; what should it be?")["replies"]), 1)
        self.assertEqual(c.consult("my group", "who owns log groups here?")["replies"], [])



class AwarenessVocabularyTests(unittest.TestCase):
    def test_every_level_declares_its_tools(self):
        self.assertEqual(set(AWARENESS_TOOLS), set(AWARENESS_LEVELS))
        self.assertEqual(AWARENESS_TOOLS["none"], ())

    def test_every_tool_name_is_counted_as_an_awareness_call(self):
        for names in AWARENESS_TOOLS.values():
            for name in names:
                self.assertIn(name, AWARENESS_TOOL_NAMES)


class PromptTests(unittest.TestCase):
    """`consult` is the only level that changes the prompt's content, not just its tools."""

    def _spec(self):
        return SimpleNamespace(utterance="Create a lock table.",
                               resolution_prompt="One store of each shared kind per account.")

    def _prompt(self, awareness):
        from harness.runtime.case import build_prompt
        return build_prompt(self._spec(), region="us-east-1", mcp_server_name="cloudgym",
                            awareness=awareness, modality="hybrid")

    def test_policy_withheld_only_at_consult_levels(self):
        for level in AWARENESS_LEVELS:
            text = self._prompt(level)
            if level in ("consult", "consult_open"):
                self.assertNotIn("One store of each shared kind", text, level)
            else:
                self.assertIn("One store of each shared kind", text, level)

    def test_consult_and_consult_open_render_identically(self):
        self.assertEqual(self._prompt("consult"), self._prompt("consult_open"))


if __name__ == "__main__":
    unittest.main()
