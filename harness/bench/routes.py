"""Which account pays for an agent cell: the CLI login first, a pay-per-token API while it is spent.

    claude:  subscription (the `claude` login on this box)  --limit-->  api (fallback) until the reset
    codex:   the `codex` login                               --limit-->  paused until the reset

Subscription limits are tracked per model (``subscription:<model>``): the weekly Fable or Opus
limit spends one model's window only, and a shared 5-hour window is simply rediscovered by each
model's next cell (one interrupted cell per model).

A cell that hits "You've hit your session limit · resets 5:40pm (UTC)" (or Codex's "try again
at 10:13 PM") marks its route limited until that time. Claude cells then run on the fallback,
configured by the operator in ``~/.cloudgym-env`` and never written to disk by the harness:

    CLOUDGYM_CLAUDE_FALLBACK=anthropic-api   CLOUDGYM_ANTHROPIC_API_KEY=sk-ant-...
    CLOUDGYM_CLAUDE_FALLBACK=openrouter      OPENROUTER_API_KEY=sk-or-...

An empty balance or a refused key (402/401, "insufficient credits") switches the fallback **off**
until the operator re-enables it (``bench routes --enable-fallback``); it is never retried on
its own. A plain 429 holds it for 10 minutes.

Without a fallback (or while the fallback itself is limited or off) such cells wait: the runner skips
them before leasing an account, so other routes keep every account busy. At the reset the
subscription is tried again; a cell that still finds it spent re-marks it.

State is one small JSON file next to the pool state (``.cloudgym/route-state.json``, under
``fcntl.flock``) because both paper batches run as separate watch processes and must agree;
``route-events.jsonl`` beside it is the switch history the dashboard shows. Every cell's route
is also recorded on its ledger attempt (``route``) and in its run metadata.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, MutableMapping

STATE_FILE = "route-state.json"
EVENTS_FILE = "route-events.jsonl"
LOCK_FILE = "route-state.lock"

SUBSCRIPTION = "subscription"      # claude on the box's login
API = "api"                        # claude on the fallback
CODEX = "codex"                    # codex on the box's login

# How long a route stays limited when its message names no reset time we can read.
DEFAULT_HOLD_S = {SUBSCRIPTION: 3600.0, API: 600.0, CODEX: 3600.0}
# A weekly or per-model limit ("You've reached your Fable limit") without a stated reset: hold a day.
LONG_HOLD_S = 86400.0
LONG_LIMIT_RE = re.compile(r"weekly|reached your \w+ limit|switch to another model", re.I)
RESET_MARGIN_S = 60.0              # the window reopens a little after the stated minute

# Variables that decide where `claude` sends requests. Taken out of the harness's own environment
# at startup so no cell inherits them: only a cell on the API route gets them, explicitly.
ANTHROPIC_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")
SECRET_VARS = ("CLOUDGYM_ANTHROPIC_API_KEY", "OPENROUTER_API_KEY")

# The fallback is unusable (not merely busy): no credits, a refused key, a refused account
# (OpenRouter answered every model with "403 ... prohibited due to a violation of provider Terms
# Of Service" on 2026-09-24). Such an answer is never scored against the model.
BILLING_RE = re.compile(r"credit balance|insufficient (?:credits|funds)|payment required|\b402\b|billing|"
                        r"invalid (?:x-)?api[ _-]?key|authentication[_ ]error|\b401\b|unauthori[sz]ed|"
                        r"\b403\b|prohibited|terms of service|failed to authenticate|permission[_ ]error", re.I)

_CLOCK = r"(?P<h>\d{1,2})(?::(?P<m>\d{2}))?\s*(?P<ap>am|pm)?"
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov",
                                        "dec"), start=1)}
_RESET_RES = (
    # claude: "resets 5:40pm (UTC)", "resets 12pm", "resets Sep 28, 5pm (UTC)", "resets Sep 28 at 5pm"
    re.compile(r"resets?\s+(?:at\s+)?(?:(?P<mon>[A-Za-z]{3})[a-z]*\s+(?P<day>\d{1,2})(?:st|nd|rd|th)?,?\s+(?:at\s+)?)?"
               + _CLOCK, re.I),
    # codex: "try again at 10:13 PM.", "try again at Sep 25th, 2026 3:04 AM."
    re.compile(r"try again at\s+(?:(?P<mon>[A-Za-z]{3})[a-z]*\s+(?P<day>\d{1,2})(?:st|nd|rd|th)?,?\s+(?:\d{4}\s+)?)?"
               + _CLOCK, re.I),
)
_IN_RE = re.compile(r"(?:try again|resets?) in\s+(?P<n>\d+)\s*(?P<unit>seconds?|minutes?|mins?|hours?|h|m|s)\b", re.I)


def parse_reset(text: str, now: float) -> float | None:
    """When a limit message says the window reopens (UTC epoch seconds), or None if it names no time.

    Times are read as UTC (the VM's clock and what the messages print); a clock time already past
    today means tomorrow."""
    match = re.search(r"limit reached\|(\d{10})\b", text)      # older claude: "usage limit reached|<reset epoch>"
    if match and float(match.group(1)) > now:
        return float(match.group(1))
    match = _IN_RE.search(text)
    if match:
        n, unit = int(match["n"]), match["unit"].lower()
        return now + n * (3600 if unit.startswith("h") else 60 if unit.startswith("m") else 1)
    for pattern in _RESET_RES:
        match = pattern.search(text)
        if not match or (match["m"] is None and match["ap"] is None):
            continue                                     # a bare number is not a time
        hour, minute = int(match["h"]), int(match["m"] or 0)
        if match["ap"]:
            hour = hour % 12 + (12 if match["ap"].lower() == "pm" else 0)
        if hour > 23 or minute > 59:
            continue
        base = datetime.fromtimestamp(now, timezone.utc)
        if match["mon"] and match["mon"][:3].lower() in _MONTHS:
            month, day = _MONTHS[match["mon"][:3].lower()], int(match["day"])
            try:
                when = base.replace(month=month, day=day, hour=hour, minute=minute, second=0, microsecond=0)
            except ValueError:
                continue
            if when.timestamp() < now - 86400:           # "Jan 2" read in late December
                when = when.replace(year=when.year + 1)
        else:
            when = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if when.timestamp() <= now:
                when += timedelta(days=1)
        return when.timestamp()
    return None


@dataclass(frozen=True)
class Fallback:
    """Where claude cells go while the subscription is spent. ``key`` never leaves this process
    except in the environment of a cell that runs on it."""
    kind: str                                   # "anthropic-api" | "openrouter"
    key: str = field(repr=False)
    base_url: str = "https://openrouter.ai/api"
    # OpenRouter's Anthropic endpoint takes the Anthropic model ids as they are (checked on the VM
    # 2026-09-24 for haiku-4-5-20251001, opus-5, fable-5), and claude only prices ids it knows:
    # "anthropic/claude-haiku-4.5" ran but was costed at a default rate (~5x). No prefix, then.
    model_prefix: str = ""

    def env(self) -> dict[str, str]:
        if self.kind == "anthropic-api":
            return {"ANTHROPIC_API_KEY": self.key}
        # OpenRouter's Anthropic-compatible endpoint: bearer token, and an explicitly empty API key
        # so claude does not fall back to the box's login.
        return {"ANTHROPIC_BASE_URL": self.base_url, "ANTHROPIC_AUTH_TOKEN": self.key, "ANTHROPIC_API_KEY": ""}

    def model(self, model: str | None) -> str | None:
        if self.kind == "openrouter" and self.model_prefix and model and "/" not in model:
            return self.model_prefix + model
        return model


def load_fallback(environ: MutableMapping[str, str] | None = None) -> Fallback | None:
    """The configured claude fallback, and scrub every routing secret out of ``environ``
    (default ``os.environ``) so child processes never inherit one."""
    environ = os.environ if environ is None else environ
    kind = (environ.get("CLOUDGYM_CLAUDE_FALLBACK") or "").strip().lower()
    keys = {name: environ.pop(name, "") for name in SECRET_VARS}
    base_url = environ.get("OPENROUTER_BASE_URL") or "https://openrouter.ai/api"
    prefix = environ.get("CLOUDGYM_OPENROUTER_MODEL_PREFIX", "")
    for name in ANTHROPIC_VARS:
        environ.pop(name, None)
    if kind in ("", "off", "none"):
        return None
    if kind == "anthropic-api":
        key = keys["CLOUDGYM_ANTHROPIC_API_KEY"]
    elif kind == "openrouter":
        key = keys["OPENROUTER_API_KEY"]
    else:
        raise ValueError(f"CLOUDGYM_CLAUDE_FALLBACK={kind!r}: expected anthropic-api, openrouter or off")
    if not key:
        raise ValueError(f"CLOUDGYM_CLAUDE_FALLBACK={kind} but its key is not set")
    return Fallback(kind, key, base_url=base_url, model_prefix=prefix)


@dataclass(frozen=True)
class Route:
    name: str                                   # SUBSCRIPTION | API | CODEX
    env: Mapping[str, str]
    fallback: Fallback | None = None
    key: str = ""                               # the limit it shares: subscription:<model>, api, codex

    def __post_init__(self) -> None:
        if not self.key:
            object.__setattr__(self, "key", self.name)

    def model(self, model: str | None) -> str | None:
        return self.fallback.model(model) if self.fallback else model

    @property
    def label(self) -> str:
        return f"{API}:{self.fallback.kind}" if self.name == API and self.fallback else self.name


class RouteBook:
    """Route state shared by every batch process on this machine."""

    def __init__(self, state_dir: Path, fallback: Fallback | None = None, *, log=lambda _m: None,
                 record: bool = True):
        self.state_path = state_dir / STATE_FILE
        self.events_path = state_dir / EVENTS_FILE
        self.lock_path = state_dir / LOCK_FILE
        self.fallback = fallback
        self.log = log
        if record:                         # the dashboard reads the configured fallback from here
            with self._locked() as state:
                state["fallback"] = fallback.kind if fallback else None

    @contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                try:
                    state = json.loads(self.state_path.read_text())
                    if not isinstance(state, dict):
                        state = {}
                except (OSError, json.JSONDecodeError):
                    state = {}
                state.setdefault("limits", {})
                yield state
                tmp = self.state_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
                os.replace(tmp, self.state_path)
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _event(self, **fields: Any) -> None:
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": round(time.time(), 3), **fields}, sort_keys=True) + "\n")

    def _limited(self, state: dict[str, Any], name: str, now: float) -> bool:
        entry = state["limits"].get(name)
        if not entry:
            return False
        if float(entry.get("until") or 0) > now:
            return True
        state["limits"].pop(name, None)
        self._event(route=name, event="restored")
        self.log(f"route {name}: window reopened")
        return False

    def choose(self, agent: str, model: str | None = None, *, now: float | None = None,
               force: str | None = None) -> Route | None:
        """The route a cell of ``agent``/``model`` runs on now, or None: its routes are all spent
        (wait). ``force=API`` skips the subscription (smoke tests of the fallback)."""
        now = time.time() if now is None else now
        with self._locked() as state:
            if agent == "codex":
                return None if self._limited(state, CODEX, now) else Route(CODEX, {})
            sub = subscription_key(model)
            if force != API and not self._limited(state, sub, now):
                return Route(SUBSCRIPTION, {}, key=sub)
            if self.fallback is not None and not state.get("fallback_off") and not self._limited(state, API, now):
                return Route(API, self.fallback.env(), self.fallback)
            return None

    def enable_fallback(self) -> bool:
        """Turn the fallback back on after it was switched off (credits added, key fixed)."""
        with self._locked() as state:
            was = state.pop("fallback_off", None)
            state["limits"].pop(API, None)
        if was:
            self._event(route=API, event="enabled")
        return bool(was)

    def note_limited(self, route: Route, text: str, *, now: float | None = None) -> float | None:
        """Mark ``route`` spent until the reset its message names; returns that time. A fallback
        that is out of money or refuses its key is switched off instead (returns None)."""
        now = time.time() if now is None else now
        if route.name == API and BILLING_RE.search(text):
            with self._locked() as state:
                first = not state.get("fallback_off")
                state["fallback_off"] = {"at": round(now, 3), "reason": text[:300]}
            if first:
                self._event(route=API, event="disabled", reason=text[:300])
                self.log(f"API fallback switched OFF ({text[:120]}); claude cells wait for the subscription. "
                         "Add credits / fix the key, then `bench routes --enable-fallback`")
            return None
        until = parse_reset(text, now)
        if until is not None:
            until += RESET_MARGIN_S
        elif route.name == SUBSCRIPTION and LONG_LIMIT_RE.search(text):
            until = now + LONG_HOLD_S
        else:
            until = now + DEFAULT_HOLD_S[route.name]
        with self._locked() as state:
            entry = state["limits"].get(route.key)
            fresh = not entry or float(entry.get("until") or 0) <= now
            if entry and float(entry.get("until") or 0) >= until:
                return float(entry["until"])
            state["limits"][route.key] = {"until": round(until, 3), "since": round(now, 3) if fresh else entry["since"],
                                          "reason": text[:300]}
        self._event(route=route.key, event="limited", until=round(until, 3), reason=text[:300])
        target = (f"its claude cells move to the {self.fallback.kind} fallback" if route.name == SUBSCRIPTION and self.fallback
                  else "its cells wait")
        self.log(f"route {route.key} limited until "
                 f"{datetime.fromtimestamp(until, timezone.utc).strftime('%H:%M UTC %b %d')}; {target}")
        return until

    def status(self, *, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        return route_status(self.state_path.parent, now=now)


def subscription_key(model: str | None) -> str:
    return f"{SUBSCRIPTION}:{model}" if model else SUBSCRIPTION


def route_status(state_dir: Path, *, now: float, history: int = 10) -> dict[str, Any]:
    """Read-only view for the dashboard and `ops status`: the mode each agent is in right now."""
    try:
        state = json.loads((state_dir / STATE_FILE).read_text())
    except (OSError, json.JSONDecodeError):
        state = {}
    limits = {k: v for k, v in (state.get("limits") or {}).items() if float(v.get("until") or 0) > now}
    fallback = state.get("fallback")

    def entry(name: str) -> dict[str, Any] | None:
        e = limits.get(name)
        return {"until": e["until"], "since": e.get("since"), "reason": e.get("reason")} if e else None

    off = state.get("fallback_off")
    api_open = bool(fallback) and not off and API not in limits
    models = {}
    for key in sorted(limits):
        if key == SUBSCRIPTION or key.startswith(SUBSCRIPTION + ":"):
            model = key.partition(":")[2] or "all"
            models[model] = {"mode": API if api_open else "waiting", **entry(key)}
    claude_mode = SUBSCRIPTION if not models else (API if api_open else "waiting")
    events: list[dict[str, Any]] = []
    try:
        lines = (state_dir / EVENTS_FILE).read_text().splitlines()[-history:]
        events = [json.loads(line) for line in lines if line.strip()]
    except (OSError, json.JSONDecodeError):
        pass
    return {"claude": {"mode": claude_mode, "fallback": fallback, "models": models, "api": entry(API),
                       "fallback_off": off},
            "codex": {"mode": "waiting" if CODEX in limits else CODEX, "limit": entry(CODEX)},
            "events": list(reversed(events))}
