"""Live cloud-state extractor.

Extraction is extraction: provider packages capture verbatim resource
documents, and the generic shape layer indexes them into the checker input
document. All checking lives in the cases' Rego oracles; the shaped document
is the contract between the two.

Capture is platform-dependent by nature (AWS: Cloud Control; other providers
have their own inventory APIs), so each provider package implements the same
small surface — ``case_type_manifest``, ``capture_snapshot``,
``parse_envelope`` — and everything above dispatches through
:func:`get_extractor`.
"""

from types import ModuleType

from . import aws
from .errors import CaptureError, UnmappedResourceType, UnsupportedPlatform
from .shape import shape_snapshot

_EXTRACTORS: dict[str, ModuleType] = {"aws": aws}

__all__ = [
    "CaptureError",
    "UnmappedResourceType",
    "UnsupportedPlatform",
    "get_extractor",
    "shape_snapshot",
]


def get_extractor(platform: str) -> ModuleType:
    """The provider package implementing the extractor surface for ``platform``."""
    try:
        return _EXTRACTORS[platform]
    except KeyError:
        raise UnsupportedPlatform(
            f"no extractor for platform '{platform}' "
            f"(have: {', '.join(sorted(_EXTRACTORS))})"
        ) from None
