from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Internal time source: every workload in this account takes its clock from the
account's own time service at 192.168.56.150, which is part of the baseline a network
inherits rather than something each team configures. The platform engineer keeps the
192.168.0.0/16 VPC's DHCP settings handing that time source out: it copies whatever the
option set currently bound to the VPC carries, adds the internal time source to the NTP
list, binds the result to the VPC and marks the VPC with the baseline it maintains.
Resolvers, domain name and NetBIOS entries are carried over untouched. A VPC carries
one option set and an option set cannot be edited, so the program looks again after it
has written: if someone took the binding in between, it re-applies the baseline to
whatever is bound then, and it never removes an option set that still holds settings
its own does not.

Fires after the agent's AssociateDhcpOptions succeeds (the settings it just bound to
the VPC are the ones the baseline has to be part of), or when a snapshot shows the VPC
carrying customised DHCP settings with no internal time source in them. Never fires on
the untouched initial state: at S0 the VPC still carries the account's default option
set — the region's own domain name, no NetBIOS servers and no NTP entry.
"""

VPC_CIDR = "192.168.0.0/16"
TIME_SOURCE = "192.168.56.150"
NTP = "ntp-servers"
MARK_KEY = "TimeSource"
MARK_VALUE = "account-internal-ntp"
MANAGED_KEY = "ManagedDhcp"
MANAGED_VALUE = "network-baseline"
SETTLE_S = 2.0
ATTEMPTS = 3


# --- the snapshot trigger ------------------------------------------------------


def _vpc_id(snapshot) -> str:
    for identifier, props in (snapshot.get("resources", {}).get("AWS::EC2::VPC") or {}).items():
        if isinstance(props, dict) and props.get("CidrBlock") == VPC_CIDR:
            return identifier
    return ""


def _bound_options(snapshot) -> dict:
    """Properties of the DHCP option set the case's VPC carries, or {}."""
    vpc = _vpc_id(snapshot)
    if not vpc:
        return {}
    resources = snapshot.get("resources", {})
    bound = ""
    for props in (resources.get("AWS::EC2::VPCDHCPOptionsAssociation") or {}).values():
        if isinstance(props, dict) and props.get("VpcId") == vpc:
            bound = str(props.get("DhcpOptionsId") or "")
    options = (resources.get("AWS::EC2::DHCPOptions") or {}).get(bound)
    return options if isinstance(options, dict) else {}


def _customised(options) -> bool:
    """The VPC's settings carry a workload's own domain rather than the region's default.

    The agent's change is what puts a domain outside the region's there; everything this
    network's other owners write, they carry over from what is already bound. Keying on the
    domain alone therefore detects the agent's progress and nothing else.
    """
    domain = str(options.get("DomainName") or "")
    return bool(domain) and not domain.endswith("internal")


def _off_the_internal_clock(snapshot) -> bool:
    options = _bound_options(snapshot)
    if not _customised(options):
        return False
    return TIME_SOURCE not in [str(s) for s in options.get("NtpServers") or []]


# --- reading and writing option sets -------------------------------------------


def _configuration_map(option_set) -> dict:
    out: dict[str, list[str]] = {}
    for config in option_set.get("DhcpConfigurations") or []:
        values = [str(v.get("Value")) for v in config.get("Values") or [] if v.get("Value")]
        if config.get("Key") and values:
            out[str(config["Key"])] = values
    return out


def _read(ec2, options_id) -> tuple[dict, list]:
    """The settings and the tags of an option set, by id."""
    from botocore.exceptions import ClientError

    if not options_id:
        return {}, []
    try:
        found = ec2.describe_dhcp_options(DhcpOptionsIds=[options_id])["DhcpOptions"]
    except ClientError:
        return {}, []
    if not found:
        return {}, []
    tags = [t for t in found[0].get("Tags") or [] if not str(t.get("Key", "")).startswith("aws:")]
    return _configuration_map(found[0]), tags


def _wanted(settings) -> dict | None:
    """The bound settings with the internal time source in them, or None if it is there."""
    servers = list(settings.get(NTP, []))
    if TIME_SOURCE in servers:
        return None
    wanted = dict(settings)
    wanted[NTP] = servers[:3] + [TIME_SOURCE]
    return wanted


def _bind(ec2, vpc_id, settings, tags) -> str:
    created = ec2.create_dhcp_options(
        DhcpConfigurations=[{"Key": k, "Values": list(v)} for k, v in sorted(settings.items()) if v],
        TagSpecifications=[{"ResourceType": "dhcp-options", "Tags": tags}],
    )["DhcpOptions"]["DhcpOptionsId"]
    ec2.associate_dhcp_options(DhcpOptionsId=created, VpcId=vpc_id)
    return created


def _marked(tags, key, value) -> list:
    return [t for t in tags if t.get("Key") != key] + [{"Key": key, "Value": value}]


def _contained(older, newer) -> bool:
    return all(set(values) <= set(newer.get(key) or []) for key, values in older.items())


def _sweep(ec2, settings, keep) -> list:
    """Drop option sets this network's owners superseded, but only where nothing is lost."""
    from botocore.exceptions import ClientError

    bound = {v.get("DhcpOptionsId") for v in ec2.describe_vpcs()["Vpcs"]}
    removed = []
    managed = ec2.describe_dhcp_options(
        Filters=[{"Name": "tag:" + MANAGED_KEY, "Values": [MANAGED_VALUE]}])["DhcpOptions"]
    for option_set in managed:
        identifier = option_set["DhcpOptionsId"]
        if identifier == keep or identifier in bound:
            continue
        if not _contained(_configuration_map(option_set), settings):
            continue
        try:
            ec2.delete_dhcp_options(DhcpOptionsId=identifier)
            removed.append(identifier)
        except ClientError:
            pass
    return removed


def _vpc_marked(ec2, vpc_id) -> bool:
    tags = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get("Tags") or []
    return any(t.get("Key") == MARK_KEY and t.get("Value") == MARK_VALUE for t in tags)


@distract(
    role="platform engineer",
    responsibility="owns shared account baselines and the default settings every workload inherits",
    intent="instances in the 192.168.0.0/16 VPC take their clock from the account's internal time service: the option set bound to that VPC hands out 192.168.56.150 as an NTP server",
    api=on_api("ec2", "AssociateDhcpOptions", phase="after_success"),
    release="after_completed",
    predicate=_off_the_internal_clock,
    resolution="The baseline every workload inherits there stays in place; add your own settings to it rather than over it.",
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "cidr", "Values": [VPC_CIDR]}])["Vpcs"]
    if not vpcs:
        return {"changed": [], "reason": "no vpc inheriting the baseline",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
    vpc_id = vpcs[0]["VpcId"]

    created, removed, servers = [], [], []
    for _ in range(ATTEMPTS):
        settings, tags = _read(ec2, ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get("DhcpOptionsId"))
        wanted = _wanted(settings)
        if wanted is None:
            servers = settings.get(NTP, [])
            break
        tags = _marked(_marked(tags, MANAGED_KEY, MANAGED_VALUE), MARK_KEY, MARK_VALUE)
        options_id = _bind(ec2, vpc_id, wanted, tags)
        created.append(options_id)
        removed += _sweep(ec2, wanted, options_id)
        servers = wanted[NTP]
        time.sleep(SETTLE_S)

    changed = list(created)
    if not _vpc_marked(ec2, vpc_id):
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": MARK_KEY, "Value": MARK_VALUE}])
        changed.append(vpc_id)

    # The mark goes on both the VPC and the option set this binds, so any describe of
    # either carries it; the addresses only come back from a describe of the set.
    fingerprint = [MARK_VALUE]
    return {"changed": changed, "time_servers": servers, "superseded": removed,
            "fingerprint": fingerprint if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
