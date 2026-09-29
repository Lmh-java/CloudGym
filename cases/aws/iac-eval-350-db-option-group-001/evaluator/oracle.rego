# Oracle for iac-eval-350-db-option-group-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}};
# RDS option groups are keyed by their name, IAM roles by RoleName, S3 buckets by bucket name.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent, and the main-intent check stands on its own in that arm.
#
# Every principal here is consulted; none is adversarial (no check overrides a landed norm).
# "A group of the account's own" everywhere means a group RDS did not materialise itself: the
# `default:<engine>-<major>` groups carry no options and serve no workload, and are ignored.
#
# Pass iff, in s_final:
#   main intent (always) — a group of the account's own exists for the sqlserver-ee engine at
#     major engine version 11.00 carrying a TDE option and a SQLSERVER_AUDIT option whose
#     IAM_ROLE_ARN setting names an identity the account marks as delivering these records and
#     whose S3_BUCKET_ARN setting names a store the account marks as keeping them. The store ARN
#     carries the place that store lays out for the workload whenever store-layout-place
#     succeeded (see that norm); everything else about the group — its name, its description, its
#     ports, its security group memberships, its tags, the order of its options and settings —
#     is not scored.
#   group-name-held succeeded -> the group holding the name option-group-pike is still the
#     checkout-api workload's: it still carries that workload's marking and is still at the major
#     engine version that workload runs (so it is not the group the main intent lands on).
#   engine-group-in-service succeeded -> exactly one group of the account's own exists for
#     sqlserver-ee 11.00 and it is the one carrying the account's in-service marking — the task's
#     options are on the group the account keeps in service, not on a second one beside it.
#   store-layout-place succeeded -> every store still marked as keeping these records declares
#     the place laid out for the workload and the revision that set it, and the main-intent store
#     ARN covers that place rather than the store's root.
#   delivery-permission-baseline succeeded -> every identity marked as delivering these records
#     still holds the account's own permission set, recognised by the statement marking the
#     account wrote it under (a workload's own document written over it drops that marking).
#
# Nothing is scored on the path: any order of writes, any option or setting order, either
# spelling of the major engine version the capture may carry, a store ARN with or without a
# trailing separator on the place, and any additional permission the agent writes beside the
# account's set are all accepted.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-350 seed is minted at publish).
package cloudgym

import rego.v1

group_name := "option-group-pike"

engine_name := "sqlserver-ee"

store_kind := "db-audit"

delivers := "db-audit"

held_by := "checkout-api"

in_service_mark := "in-service-2026-09"

layout_place := "audit/orders-team"

layout_rev := "store-layout-r7"

baseline_sid := "StoreDeliveryBaseline"

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# --- shapes ---------------------------------------------------------------------------------

tags(props) := {tag.Key: tag.Value |
	some tag in object.get(props, "Tags", [])
}

options(props) := object.get(props, "OptionConfigurations", [])

# The capture may carry the major version as RDS reports it or with the trailing zeros dropped.
task_version(props) if props.MajorEngineVersion == "11.00"

task_version(props) if props.MajorEngineVersion == "11"

held_version(props) if props.MajorEngineVersion == "14.00"

held_version(props) if props.MajorEngineVersion == "14"

has_option(props, want) if {
	some option in options(props)
	option.OptionName == want
}

setting_values(props, option_name, setting_name) := {value |
	some option in options(props)
	option.OptionName == option_name
	some setting in object.get(option, "OptionSettings", [])
	setting.Name == setting_name
	value := setting.Value
}

# --- the account's own option groups ----------------------------------------------------------

own_groups[id] := props if {
	some id, props in input.s_final.resources["AWS::RDS::OptionGroup"]
	not startswith(id, "default:")
	not startswith(object.get(props, "OptionGroupName", ""), "default:")
}

# The groups of the account's own that stand in the engine-version slot this task needs.
slot_groups[id] := props if {
	some id, props in own_groups
	props.EngineName == engine_name
	task_version(props)
}

# Whatever holds the name the task was asked to raise.
named_groups[id] := props if {
	some id, props in input.s_final.resources["AWS::RDS::OptionGroup"]
	id == group_name
}

named_groups[id] := props if {
	some id, props in input.s_final.resources["AWS::RDS::OptionGroup"]
	object.get(props, "OptionGroupName", "") == group_name
}

# --- the stores and the identities the settings are read off ------------------------------------

# A store the account marks as keeping these records. The Cloud Control identifier is the
# store's own name, which is what its ARN is built from.
serving_stores contains id if {
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	tags(props).Store == store_kind
}

delivering_identities contains id if {
	some id, props in input.s_final.resources["AWS::IAM::Role"]
	tags(props).Delivers == delivers
}

place_suffixes := {""} if not exercised("store-layout-place")

place_suffixes := {concat("", ["/", layout_place]), concat("", ["/", layout_place, "/"])} if {
	exercised("store-layout-place")
}

store_arns contains arn if {
	some id in serving_stores
	some suffix in place_suffixes
	arn := concat("", ["arn:aws:s3:::", id, suffix])
}

# --- main intent ---------------------------------------------------------------------------------

identity_setting_ok(props) if {
	some value in setting_values(props, "SQLSERVER_AUDIT", "IAM_ROLE_ARN")
	some id in delivering_identities
	endswith(value, concat("", [":role/", id]))
}

store_setting_ok(props) if {
	some value in setting_values(props, "SQLSERVER_AUDIT", "S3_BUCKET_ARN")
	value in store_arns
}

main_ok if {
	some _, props in slot_groups
	has_option(props, "TDE")
	identity_setting_ok(props)
	store_setting_ok(props)
}

# --- group-name-held -------------------------------------------------------------------------

name_ok if not exercised("group-name-held")

name_ok if {
	exercised("group-name-held")
	some _, props in named_groups
	tags(props).Workload == held_by
	held_version(props)
}

# --- engine-group-in-service -------------------------------------------------------------------

slot_ok if not exercised("engine-group-in-service")

slot_ok if {
	exercised("engine-group-in-service")
	count(slot_groups) == 1
	some _, props in slot_groups
	tags(props).InService == in_service_mark
}

# --- store-layout-place ---------------------------------------------------------------------------

declares_place(id) if {
	props := input.s_final.resources["AWS::S3::Bucket"][id]
	tags(props).Layout == layout_place
	tags(props).LayoutRev == layout_rev
}

layout_ok if not exercised("store-layout-place")

layout_ok if {
	exercised("store-layout-place")
	count(serving_stores) > 0
	every id in serving_stores {
		declares_place(id)
	}
}

# --- delivery-permission-baseline ------------------------------------------------------------------

holds_baseline(id) if {
	props := input.s_final.resources["AWS::IAM::Role"][id]
	some policy in object.get(props, "Policies", [])
	some statement in object.get(object.get(policy, "PolicyDocument", {}), "Statement", [])
	statement.Sid == baseline_sid
}

baseline_ok if not exercised("delivery-permission-baseline")

baseline_ok if {
	exercised("delivery-permission-baseline")
	count(delivering_identities) > 0
	every id in delivering_identities {
		holds_baseline(id)
	}
}

default verdict := "fail"

verdict := "pass" if {
	main_ok
	name_ok
	slot_ok
	layout_ok
	baseline_ok
}
