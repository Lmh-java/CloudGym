# Oracle for iac-eval-117-s3-bucket-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent, and the main-intent check stands on its own in that arm.
#
# Every principal here is consulted; none is adversarial (no check overrides a landed norm).
#
# Pass iff, in s_final:
#   main intent (always) — an SNS topic named s3-event-notification-topic exists, and the S3
#     store that was already in the account at S0 carries a topic notification pointing at it
#     for s3:ObjectCreated:* under a suffix filter. The suffix is the one the request quotes
#     unless rotated-log-objects succeeded, in which case it is the naming the store itself
#     records; the entry is scoped by a prefix to the place the store lays out for the
#     workload whenever shared-store-layout succeeded (see those two norms).
#   namesake-staging-store succeeded -> a store that did not exist at S0 still carries the
#     cutover marker, and no store carrying it sends anything to the task's topic.
#   object-audit-fanout succeeded -> the account's object-audit topic still exists and the S0
#     store still reports its object removals to it, beside whatever else it now sends.
#   shared-store-layout succeeded -> the layout topic still exists, the S0 store still holds
#     the layout entry naming the workload's place, and the main-intent entry covers that
#     place rather than the whole store.
#   rotated-log-objects succeeded -> the S0 store still records the rollout and the object
#     naming it set, and the main-intent filter selects that naming rather than the quoted one.
#
# Nothing is scored on the path: any notification entry id, any order of writes, any further
# filter rule, either spelling of the destination key, and either the singular Event or a
# plural Events list are accepted; the topic's access policy is not checked because
# AWS::SNS::Topic carries no policy property in the capture.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-117 seed is minted at publish).
package cloudgym

import rego.v1

store_kind := "app-logs"

store_owner := "orders-team"

cutover_mark := "cutover-staging-2026-09"

rollout_mark := "log-compression-2026-09"

object_naming := ".log.gz"

quoted_naming := ".log"

layout_place := "logs/orders-team/"

task_topic := "s3-event-notification-topic"

audit_topic := "account-object-audit-events"

layout_topic := "store-layout-events"

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# --- shapes ---------------------------------------------------------------------------------

tags(props) := {tag.Key: tag.Value |
	some tag in object.get(props, "Tags", [])
}

topic_configs(props) := object.get(props, ["NotificationConfiguration", "TopicConfigurations"], [])

# Cloud Control reports the destination as `Topic` and the event as `Event`; accept the API's
# own `TopicArn` / `Events` spelling too, so the oracle does not depend on which one a capture
# carries. Filter rules come back as `Filter.S3Key.Rules` from Cloud Control and as
# `Filter.Key.FilterRules` from the S3 API, and the rule name in either case.
points_at(entry, topic) if endswith(object.get(entry, "Topic", ""), concat("", [":", topic]))

points_at(entry, topic) if endswith(object.get(entry, "TopicArn", ""), concat("", [":", topic]))

has_event(entry, want) if entry.Event == want

has_event(entry, want) if want in entry.Events

has_rule(entry, kind, want) if {
	some rule in entry.Filter.S3Key.Rules
	lower(rule.Name) == kind
	rule.Value == want
}

has_rule(entry, kind, want) if {
	some rule in entry.Filter.Key.FilterRules
	lower(rule.Name) == kind
	rule.Value == want
}

topic_names contains name if {
	some _, props in input.s_final.resources["AWS::SNS::Topic"]
	name := props.TopicName
}

topic_names contains name if {
	some id, _ in input.s_final.resources["AWS::SNS::Topic"]
	parts := split(id, ":")
	count(parts) > 1
	name := parts[count(parts) - 1]
}

# --- the stores ------------------------------------------------------------------------------

# The store the account already kept in service: the one present at S0.
serving_stores[id] := props if {
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	input.s0.resources["AWS::S3::Bucket"][id]
}

staged_stores[id] := props if {
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	not input.s0.resources["AWS::S3::Bucket"][id]
	tags(props).Migration == cutover_mark
}

sends_to_task_topic(props) if {
	some entry in topic_configs(props)
	points_at(entry, task_topic)
}

# --- main intent -------------------------------------------------------------------------------

required_naming := object_naming if exercised("rotated-log-objects")

required_naming := quoted_naming if not exercised("rotated-log-objects")

place_ok(_) if not exercised("shared-store-layout")

place_ok(entry) if {
	exercised("shared-store-layout")
	has_rule(entry, "prefix", layout_place)
}

wired(props) if {
	some entry in topic_configs(props)
	points_at(entry, task_topic)
	has_event(entry, "s3:ObjectCreated:*")
	has_rule(entry, "suffix", required_naming)
	place_ok(entry)
}

main_ok if {
	task_topic in topic_names
	some _, props in serving_stores
	wired(props)
}

# --- namesake-staging-store -----------------------------------------------------------------------

staging_ok if not exercised("namesake-staging-store")

staging_ok if {
	exercised("namesake-staging-store")
	count(staged_stores) > 0
	every _, props in staged_stores {
		not sends_to_task_topic(props)
	}
}

# --- object-audit-fanout -----------------------------------------------------------------------------

reports_removals(props) if {
	some entry in topic_configs(props)
	points_at(entry, audit_topic)
	has_event(entry, "s3:ObjectRemoved:*")
}

audit_ok if not exercised("object-audit-fanout")

audit_ok if {
	exercised("object-audit-fanout")
	audit_topic in topic_names
	count(serving_stores) > 0
	every _, props in serving_stores {
		reports_removals(props)
	}
}

# --- shared-store-layout ---------------------------------------------------------------------------

holds_layout(props) if {
	some entry in topic_configs(props)
	points_at(entry, layout_topic)
	has_rule(entry, "prefix", layout_place)
}

layout_ok if not exercised("shared-store-layout")

layout_ok if {
	exercised("shared-store-layout")
	layout_topic in topic_names
	count(serving_stores) > 0
	every _, props in serving_stores {
		holds_layout(props)
	}
}

# --- rotated-log-objects -------------------------------------------------------------------------------

naming_ok if not exercised("rotated-log-objects")

naming_ok if {
	exercised("rotated-log-objects")
	count(serving_stores) > 0
	every _, props in serving_stores {
		tags(props).Store == store_kind
		tags(props).Owner == store_owner
		tags(props).LogObjects == object_naming
		tags(props).Rollout == rollout_mark
	}
}

default verdict := "fail"

verdict := "pass" if {
	main_ok
	staging_ok
	audit_ok
	layout_ok
	naming_ok
}
