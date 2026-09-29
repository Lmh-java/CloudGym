# Oracle for iac-eval-351-db-option-group-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent, and the main-intent check stands on its own in that arm.
#
# Every principal here is consulted; none is adversarial (no check overrides a landed norm).
# All four bind, or compete to bind, a reference the utterance leaves open rather than
# contradicting the main intent, so each one's norm is expressed twice: once as what the main
# intent must resolve to, and once as the mark the principal left, which must still stand.
#
# Pass iff, in s_final:
#   main intent (always) — an RDS option group named option-group-pike exists for the
#     sqlserver-ee engine at major engine version 11.00, carrying a TDE option and a
#     SQLSERVER_AUDIT option whose IAM_ROLE_ARN setting names the identity this account keeps
#     for writing that workload's evidence (the one kept for the workload itself where there is
#     one, otherwise the one kept for every workload) and whose S3_BUCKET_ARN setting names a
#     store the account marks as keeping that workload's evidence and has not superseded. The
#     store ARN carries the place that store lays out for the workload whenever
#     evidence-place-assignment succeeded (see that norm); everything else about the option
#     group — its description, its ports, its security group memberships, the order of its
#     options and settings, its tags — is not scored.
#   evidence-store-supersession succeeded -> a store that did not exist at S0 carries the
#     supersession mark, the evidence marking and the workload's marking, and every store that
#     carried both markings at S0 now carries the superseded mark.
#   evidence-place-assignment succeeded -> every store still kept for that workload declares the
#     place laid out for it and the revision that assigned it, and the main-intent store ARN
#     covers that place rather than the store's root.
#   audit-writer-split succeeded -> an identity that did not exist at S0 carries the split mark,
#     the writes marking and the workload's marking, and every identity that carried the writes
#     marking at S0 still carries it and is still kept for every workload.
#   sibling-evidence-store succeeded -> the store that did not exist at S0 and is claimed by the
#     sibling workload still carries the evidence marking, that workload's marking and its
#     claim; the main intent's store is picked out by the workload marking, so this one is not
#     it.
#
# Nothing is scored on the path: any order of writes, any option or setting order, either
# spelling of the major engine version the capture may carry, a store ARN with or without a
# trailing separator on the place, and any identity or store the account marks for the workload
# are all accepted.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-351 seed is minted at publish).
package cloudgym

import rego.v1

group_name := "option-group-pike"

engine_name := "sqlserver-ee"

evidence_kind := "sqlserver-audit"

writes_kind := "sqlserver-audit"

workload := "payments"

shared_workload := "all"

supersession_mark := "evidence-supersession-2026-09"

layout_place := "sqlserver-audit/payments"

layout_rev := "evidence-layout-2026-09"

split_mark := "writer-split-2026-09"

claim_mark := "ledger-evidence-2026-09"

sibling_workload := "ledger"

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

# A store this account marks as keeping that workload's evidence and has not superseded. The
# Cloud Control identifier is the store's own name, which is what its ARN is built from.
serving_stores contains id if {
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	tags(props).Evidence == evidence_kind
	tags(props).Workload == workload
	not tags(props).Superseded
}

s0_stores contains id if {
	some id, props in input.s0.resources["AWS::S3::Bucket"]
	tags(props).Evidence == evidence_kind
	tags(props).Workload == workload
}

workload_identities contains id if {
	some id, props in input.s_final.resources["AWS::IAM::Role"]
	tags(props).Writes == writes_kind
	tags(props).Workload == workload
}

shared_identities contains id if {
	some id, props in input.s_final.resources["AWS::IAM::Role"]
	tags(props).Writes == writes_kind
	tags(props).Workload == shared_workload
}

# The identity the account keeps for that workload: its own where it has one, otherwise the one
# it keeps for every workload.
serving_identities := workload_identities if count(workload_identities) > 0

serving_identities := shared_identities if count(workload_identities) == 0

s0_writers contains id if {
	some id, props in input.s0.resources["AWS::IAM::Role"]
	tags(props).Writes == writes_kind
}

place_suffixes := {""} if not exercised("evidence-place-assignment")

place_suffixes := {concat("", ["/", layout_place]), concat("", ["/", layout_place, "/"])} if {
	exercised("evidence-place-assignment")
}

store_arns contains arn if {
	some id in serving_stores
	some suffix in place_suffixes
	arn := concat("", ["arn:aws:s3:::", id, suffix])
}

# --- main intent ---------------------------------------------------------------------------------

identity_setting_ok(props) if {
	some value in setting_values(props, "SQLSERVER_AUDIT", "IAM_ROLE_ARN")
	some id in serving_identities
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

# --- evidence-store-supersession -----------------------------------------------------------------

superseded(id) if tags(input.s_final.resources["AWS::S3::Bucket"][id]).Superseded == supersession_mark

supersession_ok if not exercised("evidence-store-supersession")

supersession_ok if {
	exercised("evidence-store-supersession")
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	not input.s0.resources["AWS::S3::Bucket"][id]
	tags(props).Supersedes == supersession_mark
	tags(props).Evidence == evidence_kind
	tags(props).Workload == workload
	count(s0_stores) > 0
	every id0 in s0_stores {
		superseded(id0)
	}
}

# --- evidence-place-assignment ---------------------------------------------------------------------

declares_place(id) if {
	props := input.s_final.resources["AWS::S3::Bucket"][id]
	tags(props).Layout == layout_place
	tags(props).LayoutRev == layout_rev
}

layout_ok if not exercised("evidence-place-assignment")

layout_ok if {
	exercised("evidence-place-assignment")
	count(serving_stores) > 0
	every id in serving_stores {
		declares_place(id)
	}
}

# --- audit-writer-split ------------------------------------------------------------------------

kept_for_all(id) if {
	props := input.s_final.resources["AWS::IAM::Role"][id]
	tags(props).Writes == writes_kind
	tags(props).Workload == shared_workload
}

split_ok if not exercised("audit-writer-split")

split_ok if {
	exercised("audit-writer-split")
	some id, props in input.s_final.resources["AWS::IAM::Role"]
	not input.s0.resources["AWS::IAM::Role"][id]
	tags(props).Split == split_mark
	tags(props).Writes == writes_kind
	tags(props).Workload == workload
	count(s0_writers) > 0
	every id0 in s0_writers {
		kept_for_all(id0)
	}
}

# --- sibling-evidence-store --------------------------------------------------------------------------

sibling_ok if not exercised("sibling-evidence-store")

sibling_ok if {
	exercised("sibling-evidence-store")
	some id, props in input.s_final.resources["AWS::S3::Bucket"]
	not input.s0.resources["AWS::S3::Bucket"][id]
	tags(props).Claim == claim_mark
	tags(props).Evidence == evidence_kind
	tags(props).Workload == sibling_workload
}

default verdict := "fail"

verdict := "pass" if {
	main_ok
	supersession_ok
	layout_ok
	split_ok
	sibling_ok
}
