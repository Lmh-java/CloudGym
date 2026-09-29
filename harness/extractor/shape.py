"""Shape a raw snapshot into the checker input document.

Provider-neutral: raw files are provider-native envelopes (whatever the
platform's inventory API returned, verbatim), and the provider package
supplies ``parse_envelope`` to turn each into ``(type_name, identifier,
properties)``. Shaping itself is mechanical and judgment-free — no stripping,
no renaming; the Rego oracles select and join over the raw property shapes.
Canonicalization, if ever needed (diff-based equivalence, publishable
artifacts), is a separate view derived from the same raw capture.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

ParseEnvelope = Callable[[dict], tuple[str, str, dict]]


def shape_snapshot(snapshot_dir: Path, parse_envelope: ParseEnvelope) -> dict:
    """Build and write ``snapshot.json`` (the Rego ``input``) from ``raw/``.

    Every captured type appears in ``resources`` even when empty, so an
    oracle's "not found" genuinely means "looked and it isn't there".
    """
    manifest = json.loads((snapshot_dir / "manifest.json").read_text())
    resources: dict[str, dict[str, dict]] = {t: {} for t in manifest["types"]}
    for envelope_path in sorted((snapshot_dir / "raw").rglob("*.json")):
        envelope = json.loads(envelope_path.read_text())
        type_name, identifier, properties = parse_envelope(envelope)
        resources[type_name][identifier] = properties
    shaped = {
        "schema_version": manifest["schema_version"],
        "region": manifest["region"],
        "resources": resources,
    }
    (snapshot_dir / "snapshot.json").write_text(
        json.dumps(shaped, indent=2, sort_keys=True) + "\n"
    )
    return shaped
