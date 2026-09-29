from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""NetBIOS name service path: short names in this account's networks are resolved
point-to-point through name servers the network engineer runs, never by broadcast on
the segment. On the 192.168.0.0/16 VPC that means the option set bound to it lists the
account's WINS server 192.168.56.111 and sets node type 2, so every instance asks a
name server instead of shouting. The program copies whatever the bound set carries,
adds the WINS server to the NetBIOS list and the node type, binds the result to the VPC
and marks the VPC with the resolution path it maintains. Resolvers, domain name and NTP
entries are carried over untouched. A VPC carries one option set and an option set
cannot be edited, so the program looks again after it has written: if someone took the
binding in between, it re-applies the path to whatever is bound then, and it never
removes an option set that still holds settings its own does not.

Fires after the agent's CreateDhcpOptions succeeds (the settings it just minted are
about to take the VPC's single binding), or when a snapshot shows the VPC carrying
customised DHCP settings whose NetBIOS resolution is not point-to-point through the
account's name server. Never fires on the untouched initial state: at S0 the VPC still
carries the account's default option set, which names no NetBIOS server, sets no node
type and keeps the region's own domain name.
"""

VPC_CIDR = "192.168.0.0/16"
WINS_SERVER = "192.168.56.111"
NODE_TYPE = "2"
NETBIOS = "netbios-name-servers"
NETBIOS_TYPE = "netbios-node-type"
MARK_KEY = "NetbiosResolution"
MARK_VALUE = "wins-point-to-point"
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


def _resolution_is_broadcast(snapshot) -> bool:
    options = _bound_options(snapshot)
    if not _customised(options):
        return False
    servers = [str(s) for s in options.get("NetbiosNameServers") or []]
    return WINS_SERVER not in servers or str(options.get("NetbiosNodeType") or "") != NODE_TYPE


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
    """The bound settings resolving NetBIOS point-to-point, or None if they already do."""
    servers = list(settings.get(NETBIOS, []))
    if WINS_SERVER in servers and settings.get(NETBIOS_TYPE) == [NODE_TYPE]:
        return None
    wanted = dict(settings)
    wanted[NETBIOS] = servers if WINS_SERVER in servers else servers[:3] + [WINS_SERVER]
    wanted[NETBIOS_TYPE] = [NODE_TYPE]
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
    role="network engineer",
    responsibility="owns naming and record ownership under the account's domains",
    intent="NetBIOS names in the 192.168.0.0/16 VPC resolve point-to-point through name servers: the option set bound to it lists the account's WINS server 192.168.56.111 and sets node type 2, so nothing on that network falls back to broadcast",
    api=on_api("ec2", "CreateDhcpOptions", phase="after_success"),
    release="after_completed",
    predicate=_resolution_is_broadcast,
    resolution="The name service path I set on that network stays as it is; add to it, never over it.",
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "cidr", "Values": [VPC_CIDR]}])["Vpcs"]
    if not vpcs:
        return {"changed": [], "reason": "no vpc under the account's domains",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
    vpc_id = vpcs[0]["VpcId"]

    created, removed, servers = [], [], []
    for _ in range(ATTEMPTS):
        settings, tags = _read(ec2, ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get("DhcpOptionsId"))
        wanted = _wanted(settings)
        if wanted is None:
            servers = settings.get(NETBIOS, [])
            break
        tags = _marked(_marked(tags, MANAGED_KEY, MANAGED_VALUE), MARK_KEY, MARK_VALUE)
        options_id = _bind(ec2, vpc_id, wanted, tags)
        created.append(options_id)
        removed += _sweep(ec2, wanted, options_id)
        servers = wanted[NETBIOS]
        time.sleep(SETTLE_S)

    changed = list(created)
    if not _vpc_marked(ec2, vpc_id):
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": MARK_KEY, "Value": MARK_VALUE}])
        changed.append(vpc_id)

    # The mark goes on both the VPC and the option set this binds, so any describe of
    # either carries it; the addresses only come back from a describe of the set.
    fingerprint = [MARK_VALUE]
    return {"changed": changed, "netbios_servers": servers, "superseded": removed,
            "fingerprint": fingerprint if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
