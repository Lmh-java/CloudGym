"""AWS extractor: Cloud Control capture and capability adapters."""

from .capture import capture_snapshot, parse_envelope
from .capabilities import CAPABILITY_REGISTRY, case_type_manifest

__all__ = [
    "CAPABILITY_REGISTRY",
    "capture_snapshot",
    "case_type_manifest",
    "parse_envelope",
]
