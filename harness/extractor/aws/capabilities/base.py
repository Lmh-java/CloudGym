"""Base interface shared by AWS resource capability adapters."""

from __future__ import annotations


class CapabilityAdapter:
    """Terraform-state binding, projection, and readiness for one type."""

    terraform_type: str
    cloudcontrol_type: str
    # Projection allowlist: only these captured properties are semantic.
    semantic_properties: tuple[str, ...]
    # Runtime-generated fields, recorded for documentation/audit; the
    # allowlist projection already excludes them from normalized snapshots.
    volatile_fields: tuple[str, ...] = ()
    # Captured properties that must be present for the resource to count as
    # a complete, settled read.
    readiness_properties: tuple[str, ...] = ()
    # False for Terraform types that are projections of another type's Cloud
    # Control resource (aws_s3_bucket_public_access_block -> AWS::S3::Bucket):
    # they widen the capture scope but never bind a resource of their own.
    standalone: bool = True
    # Cloud Control types whose ``list`` handler needs a parent's properties
    # as ResourceModel (AWS::Lambda::Permission needs FunctionName) name the
    # parent type here and derive the model in ``list_resource_model``.
    list_parent: str | None = None
    # True when this type's Cloud Control identifier is *another* bound resource's
    # identifier (AWS::S3::BucketPolicy is identified by its bucket's name). Bindings
    # then stay unique per (type, identifier), and cross-resource reference rewriting
    # keeps pointing at the owner of the identifier rather than at this resource.
    identifier_is_borrowed: bool = False
    # Seconds the type's LIST can lag a create (SQS ListQueues: up to about a minute). Bound
    # resources are read by identifier and never depend on it; it bounds how long a newly
    # created, unbound resource can be missing from a region-wide capture. The live smoke
    # waits this long for presence before calling it a false negative.
    list_lag_s: float = 0.0

    def list_resource_model(self, parent_properties: dict) -> dict:
        """ResourceModel for ``list_resources`` given one captured parent."""
        raise NotImplementedError(f"{self.cloudcontrol_type} is listed region-wide")

    def identifier_from_state(self, attributes: dict) -> str:
        """Return the Cloud Control identifier from a state instance."""
        identifier = attributes.get("id")
        if not identifier or not isinstance(identifier, str):
            raise ValueError(
                f"{self.terraform_type}: state instance has no usable 'id'")
        return identifier

    def project(self, properties: dict) -> dict:
        return {key: properties[key] for key in self.semantic_properties
                if key in properties}

    def ready(self, properties: dict) -> bool:
        return all(properties.get(key) not in (None, "")
                   for key in self.readiness_properties)

    def capture_identifier_matches(self, state_identifier: str, captured_identifier: str) -> bool:
        """Whether a captured identifier denotes the same resource as a state-derived one.

        Default: strict equality. Override when Cloud Control's *list* handler emits a
        different identifier form than the one derivable from Terraform state
        (AWS::Lambda::Permission lists ``<function ARN>|<sid>`` while state yields
        ``<function name>|<sid>``; GetResource accepts both).
        """
        return state_identifier == captured_identifier

    def native_list(self, session, region: str) -> "list[str] | None":
        """Optional discovery override: return every identifier of this type in ``region``.

        Default None: discovery uses Cloud Control ``list_resources``. Override when the
        Cloud Control LIST handler is unsupported (AWS::CodeBuild::Project) or unusable
        (AWS::IAM::ManagedPolicy lists every AWS-managed policy; the native
        ``list_policies(Scope="Local")`` is one call). Envelopes still come verbatim from
        ``get_resource`` — only discovery is native.
        """
        return None

    def native_describe(self, session, region: str) -> "list[tuple[str, dict]] | None":
        """Optional capture override: every (identifier, properties) of this type in ``region``.

        Default None: capture uses Cloud Control list+get. Override for types with NO
        Cloud Control read support at all (AWS::CodeBuild::Project supports neither LIST
        nor READ): properties are the verbatim response of the service's own describe
        call — still captured raw, all judgment stays downstream in the projection,
        but it must be JSON-serializable (boto3 datetimes converted to ISO strings).
        Adapters overriding this must also override ``native_read``.
        """
        return None

    def native_read(self, session, region: str, identifier: str) -> "dict | None":
        """Targeted single-resource read for ``native_describe`` types.

        Returns the verbatim properties dict, or None when the resource does not exist
        (the absence signal Cloud Control would express as ResourceNotFoundException).
        """
        raise NotImplementedError(f"{self.cloudcontrol_type} reads via Cloud Control")

    def tolerated_get_error(self, identifier: str, error: Exception) -> bool:
        """Whether a per-item GetResource failure on a listed identifier may be skipped.

        Default: never — a get that fails after a successful list aborts the snapshot
        (a silently missing resource is the vacuous-pass hazard). Override only for
        identifiers a list handler emits that are *structurally* unreadable:
        AWS::EC2::SubnetRouteTableAssociation's region listing includes every VPC's
        main route-table association, which has no subnet and whose GetResource fails.
        """
        return False

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        """Whether a GetResource failure proves the resource is gone (absence checks only).

        Default: only ResourceNotFoundException counts, handled centrally — any other
        error fails closed because it cannot prove absence. Override for types whose
        handler reports a missing resource through a different error: AWS::EC2::Route's
        GetResource fails with GeneralServiceException "routeTable ID ... does not exist"
        once the parent table is deleted, which entails the route is gone too.
        """
        return False

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        """Optional live-smoke hook: perform ONE out-of-band native write that changes a
        semantic property, and return ``{property: expected_value, ...}`` for the recapture
        to assert — the false-negative guard proving property changes are visible to capture.

        Return None (the default) when the adapter has no mutation implemented yet; the
        smoke reports the type as "mutation: unproven" rather than failing.
        """
        return None
