"""Capability adapters for Route 53: hosted zone, record set, query logging, health check.

Cloud Control facts (verified live 2026-09-08):
* ``AWS::Route53::HostedZone`` lists globally; identifier is the bare zone id
  (``Z0151…``), which is also Terraform's id.
* ``AWS::Route53::RecordSet`` lists per zone (``HostedZoneId`` resource model) and
  its identifier is ``<name>|<zone id>|<type>|<set identifier>`` with the name
  carrying no trailing dot and an empty last field for simple records. The
  zone's own NS/SOA apex records are listed too. Terraform's id is
  ``<zone>_<name>_<type>[_<set>]``; the adapter rebuilds the Cloud Control form
  from ``fqdn`` / ``zone_id`` / ``type`` / ``set_identifier``.
* ``aws_route53_query_log`` is a standalone type listed natively (see ``QueryLogAdapter``);
  the zone document still carries ``QueryLoggingConfig`` as a projection.
* ``AWS::Route53::HealthCheck`` lists globally; identifier is ``HealthCheckId``.

Route 53 is a global service, outside the SCP's us-east-1 restriction. A hosted
zone costs $0.50/month but is not billed if deleted within 12 hours.
"""

from .base import CapabilityAdapter


def _tags(session, resource_type: str, resource_id: str, existing: list | None) -> list[dict]:
    """Add the smoke tag; return the full tag list the recapture should show."""
    tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
    session.client("route53").change_tags_for_resource(
        ResourceType=resource_type, ResourceId=resource_id, AddTags=tags)
    return [t for t in (existing or []) if t.get("Key") != "cloudgym-smoke"] + tags


class HostedZoneAdapter(CapabilityAdapter):
    terraform_type = "aws_route53_zone"
    cloudcontrol_type = "AWS::Route53::HostedZone"
    semantic_properties = (
        "HostedZoneConfig",
        "HostedZoneTags",
        "Name",
        "QueryLoggingConfig",
        "VPCs",
    )
    volatile_fields = ("Id", "NameServers", "HostedZoneFeatures")
    readiness_properties = ("Id", "Name")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        return {"HostedZoneTags": _tags(session, "hostedzone", identifier, properties.get("HostedZoneTags"))}


class QueryLogAdapter(CapabilityAdapter):
    """Query logging configs as resources of their own, listed natively.

    Cloud Control has no resource type for them (CloudFormation models query logging as
    a property of the zone, which the HostedZone adapter still projects as
    ``QueryLoggingConfig``). But a config outlives its zone: an agent that replaces the
    seed's config leaves its own behind when the zone is destroyed, and by 2026-09-18
    the sandbox accounts held sixteen such orphans that every later run listed at S0.
    Only a standalone type makes them visible to the extras cleanup and the leak check.
    Terraform's id for ``aws_route53_query_log`` is the config id, which is also the
    identifier here.
    """
    terraform_type = "aws_route53_query_log"
    cloudcontrol_type = "AWS::Route53::QueryLoggingConfig"
    semantic_properties = ("HostedZoneId", "CloudWatchLogsLogGroupArn")
    volatile_fields = ("Id",)
    readiness_properties = ("Id", "HostedZoneId", "CloudWatchLogsLogGroupArn")

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        route53 = session.client("route53")
        out: list[tuple[str, dict]] = []
        for page in route53.get_paginator("list_query_logging_configs").paginate():
            for config in page.get("QueryLoggingConfigs", []):
                out.append((config["Id"], dict(config)))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        try:
            got = session.client("route53").get_query_logging_config(Id=identifier)
        except Exception as exc:  # noqa: BLE001 - absence is the signal
            if "NoSuchQueryLoggingConfig" in str(exc):
                return None
            raise
        return dict(got.get("QueryLoggingConfig") or {}) or None

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        return None   # a config has no mutable property; create/delete is its only write


class RecordSetAdapter(CapabilityAdapter):
    terraform_type = "aws_route53_record"
    cloudcontrol_type = "AWS::Route53::RecordSet"
    list_parent = "AWS::Route53::HostedZone"
    semantic_properties = (
        "AliasTarget",
        "CidrRoutingConfig",
        "Failover",
        "GeoLocation",
        "HealthCheckId",  # rewritten to a logical address during normalization
        "HostedZoneId",   # rewritten to a logical address during normalization
        "MultiValueAnswer",
        "Name",
        "Region",
        "ResourceRecords",
        "SetIdentifier",
        "TTL",
        "Type",
        "Weight",
    )
    volatile_fields = ()
    readiness_properties = ("Name", "Type", "HostedZoneId")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"HostedZoneId": parent_properties["Id"]}

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        # Once the zone is deleted, GetResource fails with InvalidRequestException
        # "No hosted zone found with ID: …" rather than NotFound (capability smoke,
        # 2026-09-08); a record cannot outlive its zone.
        return "No hosted zone found" in str(error)

    def identifier_from_state(self, attributes: dict) -> str:
        name = attributes.get("fqdn") or attributes.get("name")
        zone = attributes.get("zone_id")
        record_type = attributes.get("type")
        if not name or not zone or not record_type:
            raise ValueError(f"{self.terraform_type}: state needs fqdn, zone_id and type")
        return f"{name.rstrip('.')}|{zone}|{record_type}|{attributes.get('set_identifier') or ''}"

    def capture_identifier_matches(self, state_identifier: str, captured_identifier: str) -> bool:
        def parts(identifier: str) -> tuple:
            name, _, rest = identifier.partition("|")
            return (name.rstrip(".").lower(), rest)
        return parts(state_identifier) == parts(captured_identifier)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        if "ResourceRecords" not in properties or properties.get("AliasTarget"):
            return None
        ttl = properties.get("TTL")
        new_ttl = 600 if int(ttl or 0) != 600 else 900
        record = {
            "Name": properties["Name"], "Type": properties["Type"], "TTL": new_ttl,
            "ResourceRecords": [{"Value": v} for v in properties["ResourceRecords"]],
        }
        if properties.get("SetIdentifier"):
            record["SetIdentifier"] = properties["SetIdentifier"]
            for key in ("Weight", "Failover", "Region", "MultiValueAnswer"):
                if key in properties:
                    record[key] = properties[key]
        session.client("route53").change_resource_record_sets(
            HostedZoneId=properties["HostedZoneId"],
            ChangeBatch={"Changes": [{"Action": "UPSERT", "ResourceRecordSet": record}]})
        # The handler types TTL as the schema does (string); mirror whatever we read.
        return {"TTL": str(new_ttl) if isinstance(ttl, str) else new_ttl}


class HealthCheckAdapter(CapabilityAdapter):
    terraform_type = "aws_route53_health_check"
    cloudcontrol_type = "AWS::Route53::HealthCheck"
    semantic_properties = ("HealthCheckConfig", "HealthCheckTags")
    volatile_fields = ("HealthCheckId",)
    readiness_properties = ("HealthCheckId", "HealthCheckConfig")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        return {"HealthCheckTags": _tags(session, "healthcheck", identifier, properties.get("HealthCheckTags"))}
