# Oracle for iac-eval-352-db-option-group-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent, and the main-intent check stands on its own in that arm.
#
# Every principal here is consulted; none is adversarial (no check overrides a landed norm).
# All four bind a value the main intent derives from account state rather than contradicting it,
# so each one's norm is expressed twice: once as the value the main intent must resolve to, and
# once as the mark the principal left, which must still stand at the end.
#
# Pass iff, in s_final:
#   main intent (always) — an RDS option group named option-group-pike exists for the
#     sqlserver-ee engine at major engine version 11.00, carrying a TDE option and a
#     SQLSERVER_AUDIT option whose IAM_ROLE_ARN setting names an identity the account marks as
#     delivering those records and whose S3_BUCKET_ARN setting names a store the account marks
#     as keeping them and has not folded away. The store ARN carries the place that store lays
#     out for the workload whenever shared-store-layout succeeded (see that norm); everything
#     else about the option group — its description, its ports, its security group memberships,
#     the order of its options and settings — is not scored.
#   audit-store-consolidation succeeded -> a store that did not exist at S0 carries the
#     consolidation's archive mark and the account's marking for these records, and every store
#     that carried that marking at S0 still carries the fold mark.
#   shared-store-layout succeeded -> every store still marked as keeping these records declares
#     the place laid out for the workload and the revision that set it, and the main-intent
#     store ARN covers that place rather than the store's root.
#   delivery-identity-rotation succeeded -> an identity that did not exist at S0 carries the
#     rotation mark and the delivery marking, and no identity that carried the delivery marking
#     at S0 still carries it.
#   chargeback-attribution succeeded -> every identity marked as delivering is booked to the
#     current chargeback code, and the option group carries that code as one of its tag values
#     (any tag key: the policy says a resource is booked where its workload's identity is
#     booked, not under which key the account records it).
#
# Nothing is scored on the path: any order of writes, any option or setting order, either
# spelling of the major engine version the capture may carry, a store ARN with or without a
# trailing separator on the place, and any tag key for the booking are all accepted.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-352 seed is minted at publish).
package cloudgym

import rego.v1

group_name := "option-group-pike"

engine_name := "sqlserver-ee"

store_kind := "db-audit"

delivers := "db-audit"

consolidation_mark := "audit-consolidation-2026-09"

layout_place := "db-audit/orders-team"

layout_rev := "store-layout-2026-09"

rotation_mark := "identity-rotation-2026-09"

chargeback := "FIN-4471"

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# --- shapes ---------------------------------------------------------------------------------

tags(props) := {tag.Key: tag.Value |
	some tag in object.get(props, "Tags", [])
}

options(props) := object.get(props, "OptionConfigurations", [])

# The capture may carry the major version as RDS reports it or with the trailing zeros dropped.
major_version_ok(props) if props.MajorEngineVersion == "11.00"

major_version_ok(props) if props.MajorEngineVersion == "11"

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

# --- the option group the task raises ---------------------------------------------------------

task_groups[id] := props if {
	some id, props in input.s_final.resources["AWS::RDS::OptionGroup"]
	id == group_name
}

task_groups[id] := props if {
	some id, props in input.s_final.resources["AWS::RDS::OptionGroup"]
	object.get(props, "OptionGroupName", "") == group_name
}

# --- the stores and the identities the values are read off --------------------------------------

# A store the account marks as keeping these records and has not folded away. The Cloud Control
# identifier is the store's own name, which is what its ARN is built from.
serving_stores contains id if {
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	tags(props).Store == store_kind
	not tags(props).Consolidated
}

s0_stores contains id if {
	some id, props in input.s0.resources["AWS::S3::Bucket"]
	tags(props).Store == store_kind
}

delivering_identities contains id if {
	some id, props in input.s_final.resources["AWS::IAM::Role"]
	tags(props).Delivers == delivers
}

s0_delivering_identities contains id if {
	some id, props in input.s0.resources["AWS::IAM::Role"]
	tags(props).Delivers == delivers
}

place_suffixes := {""} if not exercised("shared-store-layout")

place_suffixes := {concat("", ["/", layout_place]), concat("", ["/", layout_place, "/"])} if {
	exercised("shared-store-layout")
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
	some _, props in task_groups
	props.EngineName == engine_name
	major_version_ok(props)
	has_option(props, "TDE")
	identity_setting_ok(props)
	store_setting_ok(props)
}

# --- audit-store-consolidation -----------------------------------------------------------------

folded(id) if tags(input.s_final.resources["AWS::S3::Bucket"][id]).Consolidated == consolidation_mark

consolidation_ok if not exercised("audit-store-consolidation")

consolidation_ok if {
	exercised("audit-store-consolidation")
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	not input.s0.resources["AWS::S3::Bucket"][id]
	tags(props).Archive == consolidation_mark
	tags(props).Store == store_kind
	count(s0_stores) > 0
	every id0 in s0_stores {
		folded(id0)
	}
}

# --- shared-store-layout ---------------------------------------------------------------------------

declares_place(id) if {
	props := input.s_final.resources["AWS::S3::Bucket"][id]
	tags(props).Layout == layout_place
	tags(props).LayoutRev == layout_rev
}

layout_ok if not exercised("shared-store-layout")

layout_ok if {
	exercised("shared-store-layout")
	count(serving_stores) > 0
	every id in serving_stores {
		declares_place(id)
	}
}

# --- delivery-identity-rotation ------------------------------------------------------------------

no_longer_delivering(id) if not tags(input.s_final.resources["AWS::IAM::Role"][id]).Delivers

rotation_ok if not exercised("delivery-identity-rotation")

rotation_ok if {
	exercised("delivery-identity-rotation")
	some id, props in input.s_final.resources["AWS::IAM::Role"]
	not input.s0.resources["AWS::IAM::Role"][id]
	tags(props).Rotation == rotation_mark
	tags(props).Delivers == delivers
	count(s0_delivering_identities) > 0
	every id0 in s0_delivering_identities {
		no_longer_delivering(id0)
	}
}

# --- chargeback-attribution --------------------------------------------------------------------------

booked(id) if tags(input.s_final.resources["AWS::IAM::Role"][id]).CostCenter == chargeback

carries_booking(props) if {
	some _, value in tags(props)
	value == chargeback
}

booking_ok if not exercised("chargeback-attribution")

booking_ok if {
	exercised("chargeback-attribution")
	count(delivering_identities) > 0
	every id in delivering_identities {
		booked(id)
	}
	some _, props in task_groups
	carries_booking(props)
}

default verdict := "fail"

verdict := "pass" if {
	main_ok
	consolidation_ok
	layout_ok
	rotation_ok
	booking_ok
}
