"""The sweep covers the services cases now use: an interrupted cell must not poison the
next deploy of the same case (a stale fixed-name log group did, modality-matrix-v1)."""
from scripts.sandbox_cleanup import Sweeper


class _Paginator:
    def __init__(self, pages): self._pages = pages
    def paginate(self, **kwargs): return list(self._pages)


class _Logs:
    def __init__(self, calls): self.calls = calls
    def get_paginator(self, name):
        assert name == "describe_log_groups"
        return _Paginator([{"logGroups": [{"logGroupName": "/aws/route53/central-dns-audit"}, {"logGroupName": "/aws/lambda/fn"}]}])
    def describe_resource_policies(self): return {"resourcePolicies": [{"policyName": "route53-query-logging"}]}
    def delete_log_group(self, logGroupName): self.calls.append(("delete_log_group", logGroupName))
    def delete_resource_policy(self, policyName): self.calls.append(("delete_resource_policy", policyName))


class _Route53:
    def __init__(self, calls): self.calls = calls
    def get_paginator(self, name):
        if name == "list_hosted_zones":
            return _Paginator([{"HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example53.com."}]}])
        if name == "list_resource_record_sets":
            return _Paginator([{"ResourceRecordSets": [
                {"Name": "example53.com.", "Type": "NS"}, {"Name": "example53.com.", "Type": "SOA"},
                {"Name": "www.example53.com.", "Type": "A", "TTL": 300, "ResourceRecords": [{"Value": "192.0.2.1"}]}]}])
        if name == "list_health_checks":
            return _Paginator([{"HealthChecks": [{"Id": "hc-1"}]}])
        raise AssertionError(name)
    def change_resource_record_sets(self, HostedZoneId, ChangeBatch):
        self.calls.append(("change_rrs", HostedZoneId, [c["ResourceRecordSet"]["Name"] for c in ChangeBatch["Changes"]]))
    def delete_hosted_zone(self, Id): self.calls.append(("delete_hosted_zone", Id))
    def delete_health_check(self, HealthCheckId): self.calls.append(("delete_health_check", HealthCheckId))


class _Session:
    def __init__(self, clients): self._clients = clients
    def client(self, name, **kwargs): return self._clients[name]


def test_logs_and_route53_sweeps():
    calls = []
    sweeper = Sweeper(_Session({"logs": _Logs(calls), "route53": _Route53(calls)}), "us-east-1", dry_run=False)
    sweeper.logs(); sweeper.route53()
    assert ("delete_log_group", "/aws/route53/central-dns-audit") in calls
    assert ("delete_log_group", "/aws/lambda/fn") in calls
    assert ("delete_resource_policy", "route53-query-logging") in calls
    # Only the non-apex record is deleted explicitly; the apex NS/SOA go with the zone.
    assert ("change_rrs", "Z1", ["www.example53.com."]) in calls
    assert ("delete_hosted_zone", "Z1") in calls and ("delete_health_check", "hc-1") in calls
    assert not sweeper.failed


def test_dry_run_only_lists():
    calls = []
    sweeper = Sweeper(_Session({"logs": _Logs(calls), "route53": _Route53(calls)}), "us-east-1", dry_run=True)
    sweeper.logs(); sweeper.route53()
    assert calls == [] and len(sweeper.deleted) == 5


class _Ec2:
    """Enough EC2 for `_teardown_vpc`: every describe_* is empty except the security groups."""

    def __init__(self, calls, groups):
        self.calls, self.groups = calls, groups

    def describe_security_groups(self, **kwargs):
        return {"SecurityGroups": self.groups}

    def __getattr__(self, name):
        if name.startswith("describe_"):
            return lambda **kwargs: {}
        return lambda **kwargs: self.calls.append((name, kwargs))


def test_default_group_rules_naming_other_groups_are_revoked_first():
    # sbx-02, 2026-09-24: the default group allowed the NLB's group in, so the NLB group never
    # deleted (DependencyViolation) and the janitor failed on it every 30 minutes.
    nlb_rule = {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "UserIdGroupPairs": [{"GroupId": "sg-nlb"}]}
    self_rule = {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-default"}]}
    groups = [{"GroupId": "sg-default", "GroupName": "default", "IpPermissions": [self_rule, nlb_rule],
               "IpPermissionsEgress": []},
              {"GroupId": "sg-nlb", "GroupName": "edge-app-nlb", "IpPermissions": [], "IpPermissionsEgress": []}]
    calls = []
    sweeper = Sweeper(_Session({}), "us-east-1", dry_run=False)
    sweeper._teardown_elbv2 = lambda vpc: None                 # no load balancers or instances here
    sweeper._terminate_instances = lambda ec2, vpc: None
    sweeper._teardown_vpc(_Ec2(calls, groups), "vpc-1")
    revokes = [c for c in calls if c[0] == "revoke_security_group_ingress"]
    assert revokes == [("revoke_security_group_ingress", {"GroupId": "sg-default", "IpPermissions": [nlb_rule]})]
    order = [c[0] for c in calls]
    assert order.index("revoke_security_group_ingress") < order.index("delete_security_group")
    assert ("delete_security_group", {"GroupId": "sg-nlb"}) in calls
