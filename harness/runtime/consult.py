"""The consult channel: who answers a question, and when the answer is delivered.

Two things live here because the validator needs the first without the second.

``match_principals`` is the pure routing rule, in one of two modes.

*Fingerprint* mode (the ``consult`` level): a principal answers a message when the message
cites one of the *fingerprint facts* its program returned — a value that is in the account
only because the program ran (the config id it created, the retention term it wrote, the
zone it added) — and, at runtime, the agent's own journaled reads returned that fact after
the program landed. A question that carries no such fact reaches nobody, however well it
describes the topic. This replaced routing on declared concept words on 2026-09-18: the
recorded asks showed every agent opening with "any retention or tagging conventions?"
before anything had happened, the concept words `retention` and `owner` routed it, and late
delivery then handed over the withheld policy — the leak the gate exists to close.

*Subject* mode (``consult_open``, kept as the historical control and no longer run): a
principal answers when the message names something it *touched* — an identifier harvested
from its writes — or one of the *concept subjects* it declares.

In both modes, identifiers the utterance already gave, and anything present at S0, are
never routing keys: the agent repeats the requester's words in every question, so a
principal that could be reached by them would answer everything.

``ConsultChannel`` is the thread ledger. Every ask opens a thread whether or not anyone
answers, and replies accrue on threads as principals land. They are delivered on the
next call to the channel — a fresh ask returns what arrived on earlier threads alongside
its own replies, and re-reading a thread returns everything on it. Silence at a given
moment therefore means "nobody has answered yet", and a thread still empty at finish
means nobody owns what it named. Nothing is pushed: the harness authors no tool result
but its own, and injecting prose into an AWS response would corrupt the evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

IDENTIFIER = re.compile(r"[A-Za-z0-9/][A-Za-z0-9._/:-]{5,}")   # a log group name starts with "/"
# What makes a string look like a name or an id rather than a word: a digit, a path
# separator, a dot, a dash or a colon. "unassigned" and "succeeded" are words; "cc-8802",
# "Z07975712XHJ5JEJWOE3I" and "/aws/route53/central-dns-audit" are identifiers.
IDENTIFIER_MARK = re.compile(r"[0-9/._:-]")
MIN_MESSAGE = 3
MIN_SUBJECT = 3


def identifier_shaped(token: str) -> bool:
    return bool(IDENTIFIER.fullmatch(token) and IDENTIFIER_MARK.search(token))


REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")


def _parts(token: str) -> set[str]:
    """A token and the named parts inside it: an ARN's resource path, a colon-separated
    id's tail. A question says "/aws/route53/central-dns-audit", never the full ARN. Parts
    keep only what still looks like a name (a slash or a dash, eight characters or more),
    never a region, an account number or a bare service word."""
    out = {token}
    if ":" in token:
        for part in token.split(":"):
            named = "/" in part or ("-" in part and any(c.isdigit() for c in part))
            if len(part) >= 8 and named and not part.isdigit() and not REGION.match(part):
                out.add(part)
                if "/" in part:
                    tail = part.rsplit("/", 1)[-1]
                    if len(tail) >= 8 and identifier_shaped(tail):
                        out.add(tail)
    return out


def harvest_identifiers(value: Any) -> set[str]:
    """Every identifier-shaped string leaf in a JSON-like value, whole, split on space,
    and with the parts of an ARN-like token."""
    found: set[str] = set()
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif isinstance(item, str):
            for token in {item.strip(), *item.split()}:
                token = token.strip("\"',;()[]{}")
                if identifier_shaped(token):
                    found |= {t for t in _parts(token) if identifier_shaped(t)}
    return found


def excluded_terms(*texts: str) -> frozenset[str]:
    """Identifiers the requester's own words already carry, lowercased.

    A touched identifier that also appears in the utterance (the zone name, the bucket
    prefix) is not evidence that the agent noticed anything, so it never routes.
    """
    terms: set[str] = set()
    for text in texts:
        terms |= {t.lower() for t in harvest_identifiers(text or "")}
        for m in re.finditer(r"`([^`]+)`", text or ""):
            terms.add(m.group(1).strip().lower())
    return frozenset(terms)


def normalize(message: str) -> str:
    return " ".join((message or "").lower().split())


def cites(message: str, fact: str) -> bool:
    """Whether ``message`` carries ``fact`` as a whole token, case-insensitively.

    A fact is a value, so it must stand on its own: "731 days" and "731-day" cite the
    retention term 731, "17318" and "sgr-731a" do not. Facts are matched as substrings only
    when bounded by non-alphanumerics on both sides."""
    needle = normalize(fact)
    if len(needle) < MIN_SUBJECT:
        return False
    return re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", normalize(message)) is not None


def fingerprint_facts(result: Any) -> dict[str, str]:
    """The fingerprint facts a program's evidence dict declares, as ``{said: seen}``.

    ``result["fingerprint"]`` is a list. A plain string is a fact the agent says the way a
    response shows it (an id, a number). ``{"say": [...], "seen": "..."}`` is a fact whose
    spoken forms differ from the token a response carries: point-in-time recovery is
    "PITR" in a question and ``"PointInTimeRecoveryStatus":"ENABLED"`` in the response.
    Citation is checked against ``say``; the agent's reads are checked for ``seen``.
    Anything else in the dict is evidence for the oracle, not a routing key."""
    if not isinstance(result, Mapping):
        return {}
    facts = result.get("fingerprint")
    if isinstance(facts, (str, Mapping)):
        facts = [facts]
    if not isinstance(facts, (list, tuple, set)):
        return {}
    out: dict[str, str] = {}
    for fact in facts:
        if isinstance(fact, Mapping):
            seen = str(fact.get("seen") or "").strip()
            said = fact.get("say") or []
            said = [said] if isinstance(said, str) else list(said)
            if seen:
                for alias in said or [seen]:
                    alias = str(alias).strip()
                    if alias:
                        out[alias] = seen
        elif fact is not None and str(fact).strip():
            out[str(fact).strip()] = str(fact).strip()
    return out


def match_principals(message: str, principals: Iterable[Mapping[str, Any]], *,
                     landed: Iterable[str] = (), touched: Mapping[str, Iterable[str]] | None = None,
                     require_landed: bool = True, excluded: Iterable[str] = (),
                     fingerprints: Mapping[str, Iterable[str]] | None = None,
                     observed: Callable[[str, str], bool] | None = None) -> list[dict[str, Any]]:
    """The principals a message reaches, in roster order.

    ``landed`` are the principal ids whose program has succeeded; with ``require_landed``
    (the gated level) nobody else answers. ``excluded`` are lowercased terms that never
    route.

    With ``fingerprints`` (principal id -> the facts its program returned) the rule is
    fingerprint mode: a landed principal answers when the message cites one of its facts
    and ``observed(principal, fact)`` — the runtime's check that the agent's own reads
    returned the fact after the program landed — agrees (``None`` means "assume observed",
    which is what the case fixtures use). Subjects and touched identifiers are ignored.

    Without ``fingerprints`` the rule is subject mode: ``touched`` maps a principal id to
    the identifiers its writes carried, and a subject or identifier answers when it occurs
    in the message. Matching is one-directional and whole-message: the reverse (message
    occurs in subject) would make every short string a substring of nearly every subject,
    so it is deliberately absent.
    """
    needle = normalize(message)
    if len(needle) < MIN_MESSAGE:
        return []
    landed_set = set(landed)
    touched = touched or {}
    excluded_set = {str(t).lower() for t in excluded}
    reached: list[dict[str, Any]] = []
    for principal in principals:
        pid = str(principal.get("principal") or "")
        resolution = (principal.get("resolution") or "").strip()
        if not resolution:
            continue
        if require_landed and pid not in landed_set:
            continue
        hit = None
        kind = "fingerprint"
        if fingerprints is not None:
            if pid not in landed_set:
                continue    # a fact exists only once the program ran; nothing to cite before
            facts = fingerprints.get(pid, ())
            pairs = facts.items() if isinstance(facts, Mapping) else ((str(f), str(f)) for f in facts)
            for said, seen in pairs:
                said = str(said).strip()
                if said.lower() in excluded_set or not cites(needle, said):
                    continue
                if observed is not None and not observed(pid, str(seen).strip()):
                    continue
                hit = said
                break
        else:
            subjects = [str(s).lower() for s in (principal.get("subject") or []) if str(s).strip()]
            identifiers = [str(t).lower() for t in touched.get(pid, ())] if pid in landed_set else []
            for kind, keys in (("subject", subjects), ("identifier", identifiers)):
                hit = next((k for k in keys if len(k) >= MIN_SUBJECT and k not in excluded_set and k in needle), None)
                if hit is not None:
                    break
        if hit is None:
            continue
        # ``via_kind`` says what kind of key answered: a fingerprint fact the agent read, an
        # identifier a principal's writes carried, or a declared concept word. Only the first
        # exists at the gated level; the other two are what the old routing leaked through.
        reached.append({"principal": pid, "from": principal.get("role"), "text": resolution,
                        "via": hit, "via_kind": kind})
    return reached


@dataclass
class Thread:
    thread_id: str
    about: str
    question: str
    opened_s: float
    opened_call: int = 0
    delivered: dict[str, float] = field(default_factory=dict)   # principal -> t_s delivered
    replies: list[dict[str, Any]] = field(default_factory=list)

    @property
    def message(self) -> str:
        return f"{self.about or ''} {self.question or ''}"


class ConsultChannel:
    """Threads, matching and delivery for one run.

    ``principals`` returns the private roster (with resolution and subject);
    ``landed`` the ids whose program has succeeded; ``touched(pid)`` the identifiers that
    principal's writes carried; ``clock()`` seconds since the run started. With
    ``fingerprints(pid)`` (the facts that principal's program returned) the channel routes
    in fingerprint mode, and ``observed(pid, fact)`` says whether the agent's own reads
    returned the fact after the program landed.
    """

    def __init__(self, *, principals: Callable[[], list[dict[str, Any]]],
                 landed: Callable[[], set[str]], touched: Callable[[str], set[str]],
                 clock: Callable[[], float], require_landed: bool, excluded: Iterable[str] = (),
                 fingerprints: Callable[[str], Mapping[str, str] | set[str]] | None = None,
                 observed: Callable[[str, str], bool] | None = None):
        self._principals = principals
        self._landed = landed
        self._touched = touched
        self._fingerprints = fingerprints
        self._observed = observed
        self._clock = clock
        self.require_landed = require_landed
        self.excluded = frozenset(str(t).lower() for t in excluded)
        self.threads: list[Thread] = []
        self.calls: list[dict[str, Any]] = []

    # -- matching ---------------------------------------------------------------------

    @property
    def gate(self) -> str:
        return "fingerprint" if self._fingerprints is not None else "subject"

    def _reached(self, thread: Thread) -> list[dict[str, Any]]:
        landed = self._landed()
        if self._fingerprints is not None:
            facts = {pid: self._fingerprints(pid) for pid in landed}
            return match_principals(thread.message, self._principals(), landed=landed,
                                    require_landed=self.require_landed, excluded=self.excluded,
                                    fingerprints=facts, observed=self._observed)
        touched = {pid: self._touched(pid) for pid in landed}
        return match_principals(thread.message, self._principals(), landed=landed, touched=touched,
                                require_landed=self.require_landed, excluded=self.excluded)

    def _deliver(self, thread: Thread, now: float, call: int) -> list[dict[str, Any]]:
        """Replies that have arrived on ``thread`` since it was last read."""
        fresh = []
        for hit in self._reached(thread):
            if hit["principal"] in thread.delivered:
                continue
            reply = {"from": hit["from"], "text": hit["text"]}
            thread.replies.append({**reply, "principal": hit["principal"], "via": hit["via"],
                                   "via_kind": hit.get("via_kind"), "delivered_s": round(now, 3), "call": call})
            thread.delivered[hit["principal"]] = round(now, 3)
            fresh.append(reply)
        return fresh

    # -- the tool ---------------------------------------------------------------------

    def ask(self, about: str = "", question: str = "", thread: str | None = None) -> dict[str, Any]:
        now = self._clock()
        call = len(self.calls) + 1
        current: Thread | None = None
        if thread:
            current = next((t for t in self.threads if t.thread_id == thread), None)
            if current is None:
                return {"error": f"no thread {thread!r}", "threads": [t.thread_id for t in self.threads]}
        elif len(normalize(f"{about} {question}")) >= MIN_MESSAGE:
            current = Thread(f"t{len(self.threads) + 1}", about or "", question or "", round(now, 3), call)
            self.threads.append(current)

        earlier: list[dict[str, Any]] = []
        for other in self.threads:
            if other is current:
                continue
            fresh = self._deliver(other, now, call)
            if fresh:
                earlier.append({"thread": other.thread_id, "about": other.about, "replies": fresh})

        result: dict[str, Any] = {"earlier_threads": earlier}
        if current is None:
            result.update({"thread": None, "replies": [], "asked": about})
        elif thread:
            self._deliver(current, now, call)
            result.update({"thread": current.thread_id, "asked": current.about,
                           "replies": [{"from": r["from"], "text": r["text"]} for r in current.replies]})
        else:
            result.update({"thread": current.thread_id, "asked": about,
                           "replies": self._deliver(current, now, call)})
        self.calls.append({"call": call, "t_s": round(now, 3), "thread": current.thread_id if current else None,
                           "reread": bool(thread), "delivered": len(result["replies"]),
                           "earlier": sum(len(e["replies"]) for e in earlier)})
        return result

    # -- accounting -------------------------------------------------------------------

    def unread(self) -> list[dict[str, Any]]:
        """Replies that would be delivered now but have not been read: what the agent left
        in the channel. Evaluated without recording a delivery."""
        pending = []
        for thread in self.threads:
            waiting = [h for h in self._reached(thread) if h["principal"] not in thread.delivered]
            if waiting:
                pending.append({"thread": thread.thread_id, "about": thread.about,
                                "principals": [h["principal"] for h in waiting]})
        return pending

    def summary(self) -> dict[str, Any]:
        unread = self.unread()
        # Late: delivered on a later call than the one that opened the thread — the reply
        # was not available when the question was asked.
        late = sum(1 for t in self.threads for r in t.replies if r["call"] > t.opened_call)
        return {
            "require_landed": self.require_landed,
            "gate": self.gate,
            "threads": [{"thread": t.thread_id, "about": t.about, "question": t.question,
                         "opened_s": t.opened_s, "opened_call": t.opened_call, "replies": t.replies}
                        for t in self.threads],
            "calls": self.calls,
            "asks": len(self.threads),
            "threads_answered": sum(1 for t in self.threads if t.replies),
            "replies_delivered": sum(len(t.replies) for t in self.threads),
            # Answer rate: threads that got at least one reply. Replies per ask: how many
            # policies one question harvested — the number the subject routing inflated
            # (one config question, three replies) and the gate brings back to about one.
            "answer_rate": (round(sum(1 for t in self.threads if t.replies) / len(self.threads), 3)
                            if self.threads else None),
            "replies_per_ask": (round(sum(len(t.replies) for t in self.threads) / len(self.threads), 3)
                                if self.threads else None),
            "replies_delivered_late": late,
            "threads_silent": sum(1 for t in self.threads if not t.replies),
            "unread_at_finish": unread,
            "unread_replies_at_finish": sum(len(u["principals"]) for u in unread),
        }
