"""Exceptions shared across provider extractors."""

from __future__ import annotations


class CaptureError(Exception):
    """A cloud read failed; the message preserves the provider error verbatim."""


class UnmappedResourceType(Exception):
    """A case declares a terraform type its provider extractor cannot map."""


class UnsupportedPlatform(Exception):
    """No extractor implements the requested platform."""


class BindingError(Exception):
    """Terraform-state -> physical-identifier binding is missing or ambiguous."""


class StabilityTimeout(Exception):
    """Repeated snapshot reads did not converge before the deadline."""
