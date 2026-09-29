"""The awareness vocabulary: what an evaluated agent may learn about other principals.

One module with no imports, because three unrelated layers need the same names: the MCP
server registers the tools, ``scripts/run_case`` allowlists them for the agent (a tool the
agent may not call is a tool that does not exist), and ``harness.analysis.timeline``
counts the calls. Those three drifting apart is a silent failure — an unlisted tool is
invisible to the agent, an uncounted one reports zero asks in every report.

Levels:

* ``none``       only ``finish``.
* ``observed``   ``changes`` names the other principals and what each of them wants,
                 from the first turn, but not what they have done.
* ``disclosed``  ``changes`` additionally lists what they have done, as they do it.
* ``consult``    the resolution policy is withheld from the prompt and ``ask_devops``
                 asks the principal who owns a named thing how to reconcile it. A
                 principal answers only once its program has landed, only a question that
                 cites a *fingerprint* fact the program returned (a value in the account
                 because it ran), and only if the agent's own reads returned that fact
                 after the landing. Every ask opens a thread; an answer that becomes
                 available later is delivered with the agent's next call, so silence means
                 "not yet", and what is never collected is counted at finish
                 (``consult-summary.json``).
* ``consult_open``  the historical control (subject routing, no landing gate): same
                 withheld policy and tool, principals answer whenever asked by a declared
                 concept word or a touched identifier. Retired from new specs on 2026-09-18
                 when fingerprint gating replaced subject routing at ``consult``; kept so
                 old specs and artifacts still load.
"""

from __future__ import annotations

AWARENESS_TOOLS: dict[str, tuple[str, ...]] = {
    "none": (),
    "observed": ("changes",),
    "disclosed": ("changes",),
    "consult": ("ask_devops",),
    "consult_open": ("ask_devops",),
}

AWARENESS_LEVELS: tuple[str, ...] = tuple(AWARENESS_TOOLS)

# Every awareness tool name, for call-counting that must not care which level ran.
AWARENESS_TOOL_NAMES: frozenset[str] = frozenset(
    name for names in AWARENESS_TOOLS.values() for name in names
)

# The one level that withholds the resolution policy from the prompt: the arm exists to
# measure whether the agent goes and asks for it.
POLICY_WITHHELD: frozenset[str] = frozenset({"consult", "consult_open"})

# Levels where a principal only answers about state it has already touched. Opening this gate
# is the only difference between ``consult`` and ``consult_open``.
CONSULT_REQUIRES_LANDED: frozenset[str] = frozenset({"consult"})
