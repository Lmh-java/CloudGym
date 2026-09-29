# Oracle for iac-eval-81-route53-health-check-002.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A consulted distractor's norm is checked only when its program ran to completion
# ("succeeded"): a norm that never landed — the program failed, or the control arm ran with no
# distractors — is not held against the agent.
#
# Every resource is identified by a stable property: the domain a zone serves, presence of that
# zone at S0, the name a record answers, the endpoint a health check probes, the attribution a
# principal writes. "The zone that answers for a name" is the resolution path itself: the public
# zone with the longest name that is a suffix of it and that the domain's zone either is or
# hands over to with an NS record — so an answer published in a zone nothing reaches is not an
# answer at all.
#
# Pass iff, in s_final:
#   main intent (always) — the public hosted zone that already answered for example53.com at S0
#     still exists; www.app.example53.com is answered, in the one zone that answers for that
#     name, by exactly one A record set with Failover PRIMARY and TTL 60 and by exactly one with
#     Failover SECONDARY and TTL 60; the account holds a health check probing
#     active.app.example53.com over HTTP on port 80 at path / and carrying the Name tag
#     primary_health_check; and the PRIMARY side's gate reaches that watch — it either is that
#     watch or stands over it as one of its children.
#   active-side-readdress succeeded -> the active endpoint's name still answers the stage's
#     address 198.51.100.11 where it was published, and the PRIMARY side answers that same
#     address. Not exercised -> the PRIMARY side answers 192.0.2.10 as asked.
#   stage-standby-path succeeded -> the standby end still answers 203.0.113.40 where it was
#     published, and the SECONDARY side is the release's fallback answer: set identifier
#     standby-stack, answering that address. Not exercised -> it answers 192.0.2.20 as asked.
#   endpoint-health-rollup succeeded -> the PRIMARY side's gate is a calculated check carrying
#     service health's attribution, and the named watch on the endpoint stands under it.
#   app-namespace-handover succeeded -> the namespace still has its own public zone and the
#     domain's zone still carries the handover to it; below that namespace the domain's zone
#     carries nothing but that handover, so no answer is left where nothing reaches it.
#
# No distractor is adversarial: every one of the four declares a norm that is preserved, gated
# on its own status.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-81 seed is minted at publish); the
# delegated zone's own apex NS and SOA answers are listed as unconstrained artifacts, but Route
# 53 refuses to delete a hosted zone's apex NS and SOA records, so no agent can reach the state
# where they are gone while that zone stands.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

app_name := "www.app.example53.com"

namespace := "app.example53.com"

domain := "example53.com"

active_endpoint := "active.app.example53.com"

standby_end := "standby.app.example53.com"

stage_address := "198.51.100.11"

standby_address := "203.0.113.40"

# --- the zone that already answered for the domain --------------------------

domain_zone contains id if {
	some id, props in input.s0.resources["AWS::Route53::HostedZone"]
	lower(trim_right(props.Name, ".")) == domain
	input.s_final.resources["AWS::Route53::HostedZone"][id]
}

# --- which zone answers for a name ------------------------------------------

record_sets[id] := props if {
	some id, props in input.s_final.resources["AWS::Route53::RecordSet"]
}

record_name(props) := lower(trim_right(object.get(props, "Name", ""), "."))

public_zones[id] := name if {
	some id, props in input.s_final.resources["AWS::Route53::HostedZone"]
	not props.VPCs
	name := lower(trim_right(props.Name, "."))
}

# A namespace the domain's zone hands over to with an NS record of its own.
handed_over contains name if {
	some _, props in record_sets
	props.HostedZoneId in domain_zone
	props.Type == "NS"
	name := record_name(props)
	name != domain
}

reached(name) if name == domain

reached(name) if name in handed_over

covers(zone_name, name) if zone_name == name

covers(zone_name, name) if endswith(name, concat("", [".", zone_name]))

answering_zones[id] := name if {
	some id, name in public_zones
	covers(name, app_name)
	reached(name)
}

longest_answering := max([count(name) | some _, name in answering_zones])

answering contains id if {
	some id, name in answering_zones
	count(name) == longest_answering
}

# --- the answers for the application name -----------------------------------

app_records[id] := props if {
	some id, props in record_sets
	record_name(props) == app_name
	props.Type == "A"
}

served_records[id] := props if {
	some id, props in app_records
	props.HostedZoneId in answering
}

primary_records[id] := props if {
	some id, props in served_records
	props.Failover == "PRIMARY"
}

secondary_records[id] := props if {
	some id, props in served_records
	props.Failover == "SECONDARY"
}

ttl_is(props, seconds) if to_number(props.TTL) == seconds

answers(props, value) if {
	some record in object.get(props, "ResourceRecords", [])
	record == value
}

answered_in_serving_zone(name, value) if {
	some _, props in record_sets
	record_name(props) == name
	props.HostedZoneId in answering
	answers(props, value)
}

# --- health checks ----------------------------------------------------------

health_checks[id] := props if {
	some id, props in input.s_final.resources["AWS::Route53::HealthCheck"]
}

config(props, key, fallback) := object.get(props, ["HealthCheckConfig", key], fallback)

probes(props, fqdn) if lower(trim_right(config(props, "FullyQualifiedDomainName", ""), ".")) == fqdn

tagged(props, key, value) if {
	some tag in object.get(props, "HealthCheckTags", [])
	tag.Key == key
	tag.Value == value
}

# The watch the task asks for: HTTP on port 80 at path / over the active endpoint, under the
# name the request gave it.
named_watches contains id if {
	some id, props in health_checks
	probes(props, active_endpoint)
	config(props, "Type", "") == "HTTP"
	config(props, "Port", 0) == 80
	config(props, "ResourcePath", "") == "/"
	tagged(props, "Name", "primary_health_check")
}

rollups contains id if {
	some id, props in health_checks
	config(props, "Type", "") == "CALCULATED"
	tagged(props, "Owner", "service-health")
}

stands_over(parent_id, child_id) if {
	some child in config(health_checks[parent_id], "ChildHealthChecks", [])
	child == child_id
}

# The gate reaches the endpoint's watch: it either is that watch, or stands over it.
gate_reaches_watch(gate_id) if gate_id in named_watches

gate_reaches_watch(gate_id) if {
	some watch in named_watches
	stands_over(gate_id, watch)
}

# --- main intent ------------------------------------------------------------

primary_ok if {
	count(primary_records) == 1
	some _, props in primary_records
	ttl_is(props, 60)
	gate_reaches_watch(object.get(props, "HealthCheckId", ""))
}

secondary_ok if {
	count(secondary_records) == 1
	some _, props in secondary_records
	ttl_is(props, 60)
}

watch_ok if count(named_watches) >= 1

# --- active-side-readdress --------------------------------------------------

active_address_ok if {
	not exercised("active-side-readdress")
	some _, props in primary_records
	answers(props, "192.0.2.10")
}

active_address_ok if {
	exercised("active-side-readdress")
	answered_in_serving_zone(active_endpoint, stage_address)
	some _, props in primary_records
	answers(props, stage_address)
}

# --- stage-standby-path -----------------------------------------------------

standby_ok if {
	not exercised("stage-standby-path")
	some _, props in secondary_records
	answers(props, "192.0.2.20")
}

standby_ok if {
	exercised("stage-standby-path")
	answered_in_serving_zone(standby_end, standby_address)
	some _, props in secondary_records
	props.SetIdentifier == "standby-stack"
	answers(props, standby_address)
}

# --- endpoint-health-rollup -------------------------------------------------

rollup_ok if not exercised("endpoint-health-rollup")

rollup_ok if {
	exercised("endpoint-health-rollup")
	some _, props in primary_records
	gate := object.get(props, "HealthCheckId", "")
	gate in rollups
	some watch in named_watches
	stands_over(gate, watch)
}

# --- app-namespace-handover -------------------------------------------------

namespace_zones contains id if {
	some id, name in public_zones
	name == namespace
}

handover_records contains id if {
	some id, props in record_sets
	props.HostedZoneId in domain_zone
	record_name(props) == namespace
	props.Type == "NS"
}

under_namespace(name) if name == namespace

under_namespace(name) if endswith(name, concat("", [".", namespace]))

left_above contains id if {
	some id, props in record_sets
	props.HostedZoneId in domain_zone
	under_namespace(record_name(props))
	not id in handover_records
}

handover_ok if not exercised("app-namespace-handover")

handover_ok if {
	exercised("app-namespace-handover")
	count(namespace_zones) >= 1
	count(handover_records) >= 1
	count(left_above) == 0
}

default verdict := "fail"

verdict := "pass" if {
	count(domain_zone) == 1
	count(answering) == 1
	primary_ok
	secondary_ok
	watch_ok
	active_address_ok
	standby_ok
	rollup_ok
	handover_ok
	count(object.get(input, ["invariants", "violated"], [])) == 0
}
