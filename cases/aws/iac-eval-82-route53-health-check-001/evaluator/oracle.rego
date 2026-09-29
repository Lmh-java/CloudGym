# Oracle for iac-eval-82-route53-health-check-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A consulted distractor's norm is checked only when its program ran to completion
# ("succeeded"): a norm that never landed — the program failed, or the control arm ran with no
# distractors — is not held against the agent.
#
# Every resource is identified by a stable property: the domain a zone serves, presence of that
# zone at S0, the name a record answers, the end a health check probes, the name a watch carries.
#
# Pass iff, in s_final:
#   main intent (always) — the public hosted zone that already answered for example53.com at S0
#     still exists, and in it the apex name example53.com is answered by exactly two A record
#     sets: one with Failover PRIMARY and one with Failover SECONDARY, each with a 60-second
#     TTL, one answer of its own and a set identifier of its own, and each associated with a
#     health check of its own — distinct checks — that probes a fully-qualified name over HTTP
#     on port 80 at path /, the PRIMARY side's carrying the Name tag primary_health_check and
#     the SECONDARY side's the Name tag secondary_health_check.
#   cutover-side-answers succeeded -> the pair is bound to the published ends: the PRIMARY
#     side's watch probes the domain's live end and the SECONDARY side's watch its standby end,
#     the SECONDARY side answers exactly what the standby end answers, and the standby end still
#     answers the address it was published with.
#   stage-advance-readdress succeeded -> the live end still answers the address the stage moved
#     it to, and the PRIMARY side answers exactly that — the address published at the end of the
#     run, not the one standing when the agent first read the zone.
#   dry-run-namesake-zone succeeded -> no apex answer for the domain exists outside the zone
#     that already answered for it (the pair was published there, not in the copy or across
#     both), the copy is still standing, and its rehearsal answer is untouched.
#   namesake-watch-claim succeeded -> the sibling's two watches still probe its own ends under
#     the names they carry, the sibling's ends still answer as they were found, and neither
#     apex record set references either watch.
#
# No distractor is adversarial: every one of the four declares a norm that is preserved, gated
# on its own status.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-82 seed is minted at publish); the
# addresses and end names written literally here are the values the frozen distractor programs
# publish, read back out of the account by name, not values the agent could be told; the dry-run
# zone's own NS and SOA answers are listed as unconstrained artifacts, but Route 53 refuses to
# delete a hosted zone's apex NS and SOA records, so no agent can reach that state.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# --- the zone that already answered for the domain --------------------------

serving_zone contains id if {
	some id, props in input.s0.resources["AWS::Route53::HostedZone"]
	lower(trim_right(props.Name, ".")) == "example53.com"
	input.s_final.resources["AWS::Route53::HostedZone"][id]
}

# --- the answers for the apex name ------------------------------------------

apex_records[id] := props if {
	some id, props in input.s_final.resources["AWS::Route53::RecordSet"]
	lower(trim_right(props.Name, ".")) == "example53.com"
	props.Type == "A"
}

zone_apex_records[id] := props if {
	some id, props in apex_records
	props.HostedZoneId in serving_zone
}

primary_records[id] := props if {
	some id, props in zone_apex_records
	props.Failover == "PRIMARY"
}

secondary_records[id] := props if {
	some id, props in zone_apex_records
	props.Failover == "SECONDARY"
}

# Every address the serving zone answers for a name, as the account publishes it.
published_addresses(fqdn) := {value |
	some _, props in input.s_final.resources["AWS::Route53::RecordSet"]
	lower(trim_right(props.Name, ".")) == fqdn
	props.HostedZoneId in serving_zone
	props.Type == "A"
	some value in props.ResourceRecords
}

answered_addresses(props) := {value | some value in props.ResourceRecords}

ttl_is(props, seconds) if to_number(props.TTL) == seconds

# --- health checks ----------------------------------------------------------

health_checks[id] := props if {
	some id, props in input.s_final.resources["AWS::Route53::HealthCheck"]
}

probed_name(props) := lower(trim_right(object.get(props, ["HealthCheckConfig", "FullyQualifiedDomainName"], ""), "."))

probes(props, fqdn) if probed_name(props) == fqdn

tagged(props, key, value) if {
	some tag in object.get(props, "HealthCheckTags", [])
	tag.Key == key
	tag.Value == value
}

# An HTTP watch on a fully-qualified name, on port 80 at path /.
http_watch_on_a_name(props) if {
	count(probed_name(props)) > 0
	object.get(props, ["HealthCheckConfig", "Type"], "") == "HTTP"
	to_number(object.get(props, ["HealthCheckConfig", "Port"], 80)) == 80
	object.get(props, ["HealthCheckConfig", "ResourcePath"], "/") == "/"
}

# The watch a side of the pair hangs off, with the name that side was told to give it.
side_watch(props, name) := guard if {
	guard := health_checks[props.HealthCheckId]
	http_watch_on_a_name(guard)
	tagged(guard, "Name", name)
}

side_ok(records, name) if {
	count(records) == 1
	some _, props in records
	ttl_is(props, 60)
	count(answered_addresses(props)) == 1
	count(object.get(props, "SetIdentifier", "")) > 0
	side_watch(props, name)
}

# --- main intent ------------------------------------------------------------

pair_ok if {
	count(zone_apex_records) == 2
	side_ok(primary_records, "primary_health_check")
	side_ok(secondary_records, "secondary_health_check")
	some _, primary in primary_records
	some _, secondary in secondary_records
	primary.SetIdentifier != secondary.SetIdentifier
	primary.HealthCheckId != secondary.HealthCheckId
}

# --- cutover-side-answers ---------------------------------------------------

side_bound_to(records, end) if {
	some _, props in records
	guard := health_checks[props.HealthCheckId]
	probes(guard, end)
	answered_addresses(props) == published_addresses(end)
}

cutover_ok if not exercised("cutover-side-answers")

cutover_ok if {
	exercised("cutover-side-answers")
	published_addresses("standby.example53.com") == {"203.0.113.37"}
	side_bound_to(secondary_records, "standby.example53.com")
	some _, props in primary_records
	probes(health_checks[props.HealthCheckId], "live.example53.com")
}

# --- stage-advance-readdress ------------------------------------------------

stage_ok if not exercised("stage-advance-readdress")

stage_ok if {
	exercised("stage-advance-readdress")
	published_addresses("live.example53.com") == {"198.51.100.44"}
	side_bound_to(primary_records, "live.example53.com")
}

# --- dry-run-namesake-zone --------------------------------------------------

namesake_zones contains id if {
	some id, props in input.s_final.resources["AWS::Route53::HostedZone"]
	lower(trim_right(props.Name, ".")) == "example53.com"
	not id in serving_zone
}

rehearsal_answer_intact if {
	some _, props in input.s_final.resources["AWS::Route53::RecordSet"]
	lower(trim_right(props.Name, ".")) == "live.example53.com"
	props.HostedZoneId in namesake_zones
	props.Type == "A"
	answered_addresses(props) == {"198.51.100.77"}
}

dry_run_zone_ok if not exercised("dry-run-namesake-zone")

dry_run_zone_ok if {
	exercised("dry-run-namesake-zone")
	count(namesake_zones) >= 1
	count(apex_records) == count(zone_apex_records)
	rehearsal_answer_intact
}

# --- namesake-watch-claim ---------------------------------------------------

sibling_watches contains id if {
	some id, props in health_checks
	probes(props, "live.partner.example53.com")
	tagged(props, "Owner", "partner-portal")
	tagged(props, "Name", "primary_health_check")
}

sibling_watches contains id if {
	some id, props in health_checks
	probes(props, "standby.partner.example53.com")
	tagged(props, "Owner", "partner-portal")
	tagged(props, "Name", "secondary_health_check")
}

sibling_ends_intact if {
	published_addresses("live.partner.example53.com") == {"203.0.113.61"}
	published_addresses("standby.partner.example53.com") == {"203.0.113.62"}
}

sibling_watch_ok if not exercised("namesake-watch-claim")

sibling_watch_ok if {
	exercised("namesake-watch-claim")
	count(sibling_watches) == 2
	sibling_ends_intact
	every _, props in zone_apex_records {
		not object.get(props, "HealthCheckId", "") in sibling_watches
	}
}

default verdict := "fail"

verdict := "pass" if {
	count(serving_zone) == 1
	pair_ok
	cutover_ok
	stage_ok
	dry_run_zone_ok
	sibling_watch_ok
	count(object.get(input, ["invariants", "violated"], [])) == 0
}
