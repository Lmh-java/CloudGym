"""Routes: subscription first, the API fallback while the window is spent (no network)."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from harness.bench.routes import (
    API, CODEX, SUBSCRIPTION, Fallback, Route, RouteBook, load_fallback, parse_reset, route_status,
)

NOW = datetime(2026, 9, 24, 15, 0, tzinfo=timezone.utc).timestamp()     # 15:00 UTC


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%b %d %H:%M")


class ParseResetTests(unittest.TestCase):
    def test_messages_seen_on_the_vm(self) -> None:
        self.assertEqual(utc(parse_reset("You've hit your session limit · resets 5:40pm (UTC)", NOW)), "Sep 24 17:40")
        self.assertEqual(utc(parse_reset("You've hit your session limit · resets 12:10pm (UTC)", NOW)), "Sep 25 12:10")
        self.assertEqual(utc(parse_reset("You've hit your session limit · resets 10pm (UTC)", NOW)), "Sep 24 22:00")
        self.assertEqual(utc(parse_reset("You've hit your weekly limit · resets Sep 28, 5pm (UTC)", NOW)), "Sep 28 17:00")
        codex = ("You’ve hit your usage limit. Upgrade to Pro (https://chatgpt.com/explore/pro), visit "
                 "https://chatgpt.com/codex/settings/usage to purchase more credits or try again at 10:13 PM.")
        self.assertEqual(utc(parse_reset(codex, NOW)), "Sep 24 22:13")
        self.assertEqual(utc(parse_reset("try again at Sep 25th, 2026 3:04 AM.", NOW)), "Sep 25 03:04")
        self.assertEqual(parse_reset("rate limited, try again in 20 minutes", NOW), NOW + 1200)
        self.assertEqual(parse_reset(f"Claude AI usage limit reached|{int(NOW) + 7200}", NOW), NOW + 7200)

    def test_no_time_means_none(self) -> None:
        self.assertIsNone(parse_reset("Claude AI usage limit reached|1700000000", NOW))       # an epoch in the past
        self.assertIsNone(parse_reset("You've hit your weekly limit · resets Sep 21", NOW))     # a date is not a time
        self.assertIsNone(parse_reset("overloaded_error", NOW))


class FallbackTests(unittest.TestCase):
    def test_load_scrubs_every_routing_secret(self) -> None:
        env = {"CLOUDGYM_CLAUDE_FALLBACK": "openrouter", "OPENROUTER_API_KEY": "sk-or-1",
               "CLOUDGYM_ANTHROPIC_API_KEY": "sk-ant-1", "ANTHROPIC_API_KEY": "stray", "PATH": "/bin"}
        fb = load_fallback(env)
        self.assertEqual((fb.kind, fb.key), ("openrouter", "sk-or-1"))
        self.assertEqual(env, {"CLOUDGYM_CLAUDE_FALLBACK": "openrouter", "PATH": "/bin"})
        self.assertNotIn("sk-or-1", repr(fb))
        self.assertEqual(fb.env(), {"ANTHROPIC_BASE_URL": "https://openrouter.ai/api", "ANTHROPIC_AUTH_TOKEN": "sk-or-1",
                                    "ANTHROPIC_API_KEY": ""})
        # the Anthropic ids go through unchanged: OpenRouter accepts them and claude prices them
        self.assertEqual(fb.model("claude-opus-5"), "claude-opus-5")
        self.assertEqual(fb.model("claude-haiku-4-5-20251001"), "claude-haiku-4-5-20251001")
        prefixed = Fallback("openrouter", "k", model_prefix="anthropic/")
        self.assertEqual(prefixed.model("claude-opus-5"), "anthropic/claude-opus-5")

    def test_anthropic_api_and_off(self) -> None:
        fb = load_fallback({"CLOUDGYM_CLAUDE_FALLBACK": "anthropic-api", "CLOUDGYM_ANTHROPIC_API_KEY": "sk-ant-1"})
        self.assertEqual(fb.env(), {"ANTHROPIC_API_KEY": "sk-ant-1"})
        self.assertEqual(fb.model("claude-opus-5"), "claude-opus-5")
        self.assertIsNone(load_fallback({"OPENROUTER_API_KEY": "k"}))
        self.assertIsNone(load_fallback({"CLOUDGYM_CLAUDE_FALLBACK": "off"}))
        with self.assertRaises(ValueError):
            load_fallback({"CLOUDGYM_CLAUDE_FALLBACK": "openrouter"})             # no key
        with self.assertRaises(ValueError):
            load_fallback({"CLOUDGYM_CLAUDE_FALLBACK": "bedrock", "OPENROUTER_API_KEY": "k"})


class RouteBookTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.dir = Path(self._temp.name)
        self.fb = Fallback("anthropic-api", "sk-ant-1")

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_subscription_then_api_then_back(self) -> None:
        book = RouteBook(self.dir, self.fb)
        self.assertEqual(book.choose("claude", now=NOW).name, SUBSCRIPTION)
        until = book.note_limited(Route(SUBSCRIPTION, {}), "You've hit your session limit · resets 5:40pm (UTC)", now=NOW)
        self.assertEqual(utc(until), "Sep 24 17:41")                          # + the reset margin
        route = book.choose("claude", now=NOW + 60)
        self.assertEqual((route.name, route.label, dict(route.env)), (API, "api:anthropic-api", {"ANTHROPIC_API_KEY": "sk-ant-1"}))
        self.assertEqual(book.choose("codex", now=NOW + 60).name, CODEX)     # codex has its own window
        # a second process sees the same state
        other = RouteBook(self.dir, self.fb)
        self.assertEqual(other.choose("claude", now=NOW + 60).name, API)
        self.assertEqual(book.choose("claude", now=until + 1).name, SUBSCRIPTION)
        events = [json.loads(l) for l in (self.dir / "route-events.jsonl").read_text().splitlines()]
        self.assertEqual([(e["route"], e["event"]) for e in events], [(SUBSCRIPTION, "limited"), (SUBSCRIPTION, "restored")])

    def test_model_limit_without_a_time_holds_a_day(self) -> None:
        book = RouteBook(self.dir, None)
        fable = book.choose("claude", "claude-fable-5", now=NOW)
        until = book.note_limited(fable, "You've reached your Fable limit. Switch to another model to continue.", now=NOW)
        self.assertEqual(until, NOW + 86400)
        self.assertIsNone(book.choose("claude", "claude-fable-5", now=NOW + 7200))
        self.assertEqual(book.choose("claude", "claude-opus-5", now=NOW + 7200).name, SUBSCRIPTION)

    def test_no_fallback_waits(self) -> None:
        book = RouteBook(self.dir, None)
        book.note_limited(Route(SUBSCRIPTION, {}), "Claude AI usage limit reached", now=NOW)   # no time: 1 h
        self.assertIsNone(book.choose("claude", now=NOW + 3000))
        self.assertEqual(book.choose("claude", now=NOW + 3700).name, SUBSCRIPTION)

    def test_out_of_credits_switches_the_fallback_off_until_re_enabled(self) -> None:
        book = RouteBook(self.dir, self.fb)
        book.note_limited(book.choose("claude", "claude-opus-5", now=NOW),
                          "You've hit your session limit · resets 5:40pm (UTC)", now=NOW)
        api = book.choose("claude", "claude-opus-5", now=NOW + 60)
        self.assertIsNone(book.note_limited(api, "402 Insufficient credits. Add more using https://openrouter.ai/credits",
                                            now=NOW + 60))
        self.assertIsNone(book.choose("claude", "claude-opus-5", now=NOW + 120))     # subscription spent, API off
        status = route_status(self.dir, now=NOW + 120)
        self.assertEqual(status["claude"]["mode"], "waiting")
        self.assertIn("Insufficient credits", status["claude"]["fallback_off"]["reason"])
        self.assertEqual(status["codex"]["mode"], CODEX)
        # never retried on its own: a week later the subscription is back, the API still off
        haiku = book.choose("claude", "claude-haiku-4-5", now=NOW + 7 * 86400)
        book.note_limited(haiku, "You've hit your session limit · resets 11pm (UTC)", now=NOW + 7 * 86400)
        self.assertIsNone(book.choose("claude", "claude-haiku-4-5", now=NOW + 7 * 86400 + 60))
        self.assertTrue(RouteBook(self.dir, None, record=False).enable_fallback())
        tos = "Failed to authenticate. API Error: 403 The request is prohibited due to a violation of provider Terms Of Service."
        self.assertIsNone(book.note_limited(book.choose("claude", "claude-opus-5", now=NOW + 200), tos, now=NOW + 200))
        self.assertIn("Terms Of Service", route_status(self.dir, now=NOW + 200)["claude"]["fallback_off"]["reason"])
        RouteBook(self.dir, None, record=False).enable_fallback()
        self.assertEqual(book.choose("claude", "claude-opus-5", now=NOW + 180).name, API)
        self.assertEqual(route_status(self.dir, now=NOW)["claude"]["fallback"], "anthropic-api")   # record=False kept it

    def test_limits_are_per_model(self) -> None:
        book = RouteBook(self.dir, self.fb)
        fable = book.choose("claude", "claude-fable-5", now=NOW)
        self.assertEqual(fable.key, "subscription:claude-fable-5")
        book.note_limited(fable, "You've hit your weekly limit · resets Sep 28, 5pm (UTC)", now=NOW)
        self.assertEqual(book.choose("claude", "claude-fable-5", now=NOW + 60).name, API)
        self.assertEqual(book.choose("claude", "claude-haiku-4-5", now=NOW + 60).name, SUBSCRIPTION)
        status = route_status(self.dir, now=NOW + 60)
        self.assertEqual(list(status["claude"]["models"]), ["claude-fable-5"])
        self.assertEqual(status["claude"]["models"]["claude-fable-5"]["mode"], API)
        self.assertEqual(book.choose("claude", "claude-haiku-4-5", now=NOW, force=API).name, API)

    def test_a_later_reset_extends_an_earlier_one_never_shortens(self) -> None:
        book = RouteBook(self.dir, self.fb)
        late = book.note_limited(Route(CODEX, {}), "try again at 10:13 PM.", now=NOW)
        self.assertEqual(book.note_limited(Route(CODEX, {}), "try again at 4:00 PM.", now=NOW), late)
        self.assertIsNone(book.choose("codex", now=NOW + 3600))
        self.assertEqual(route_status(self.dir, now=NOW)["codex"]["mode"], "waiting")


if __name__ == "__main__":
    unittest.main()
