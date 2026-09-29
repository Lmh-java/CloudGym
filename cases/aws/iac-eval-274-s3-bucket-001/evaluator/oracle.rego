# Oracle for iac-eval-274-s3-bucket-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}};
# an S3 inventory configuration is a property of the bucket document (InventoryConfigurations),
# a bucket policy its own type keyed by the bucket's name.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A consulted distractor's norm is checked only when its program ran to completion
# ("succeeded"): a norm that never landed — the program failed, or the control arm ran with no
# distractors — is not held against the agent.
#
# Pass iff, in s_final:
#   main intent (always) — the account holds exactly one inventory configuration; it is enabled,
#     weekly, over current object versions, in CSV; it sits on a store that did not exist at S0
#     and is not one of the account's inventory-reports stores; its destination is a store marked
#     as kept for inventory reports by the storage platform; and that store's policy admits
#     s3.amazonaws.com to put objects under it.
#   rolled-out-export-store succeeded -> the store the report is about is the one the release
#     rolled out (its release mark), and no store beside it was stood up by the agent: every
#     store absent at S0 carries either that release mark or the inventory-reports mark.
#   closing-reports-store succeeded -> the destination store carries no closing mark, i.e. the
#     report is delivered into the successor rather than into the store being closed.
#   object-catalogue-standard succeeded -> the configuration's optional fields include what the
#     account's catalogue records (ObjectOwner, EncryptionStatus) beside the object list.
#   shared-reports-layout succeeded -> the destination place is under the store's layout rather
#     than its root, and the layout entry the store's policy already held is still there.
# No distractor is adversarial: every effect above is preserved, none overridden.
#
# Tolerances (7.4): any configuration id, any destination place at or below the store's layout
# place (`reports`, `reports/`, `reports/<anything>`), optional fields beyond the two the
# catalogue asks for, any additional statements or conditions on the delivery grant, the grant's
# resource scoped to the whole store or to the layout place, and either the flat
# `ScheduleFrequency` or a nested `Schedule.Frequency` shape.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-274 seed is minted at publish); and
# the `resolved` fixture still passes with the bucket policy of the *closing* store deleted —
# that document is the layout distractor's own, on a store the report is not delivered into, so
# it is deliberately auxiliary. The policy that is held is the destination store's: the delivery
# grant and the layout entry it carries.
package cloudgym

import rego.v1

release_mark := "release-2026-11-r41"

reports_mark := "inventory-reports"

reports_owner := "storage-platform"

layout_entry := "shared-reports-layout-2026-11"

layout_place := "reports"

catalogued_fields := {"ObjectOwner", "EncryptionStatus"}

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

tags_of(props) := {tag.Key: tag.Value | some tag in object.get(props, "Tags", [])}

as_list(x) := x if is_array(x)

as_list(x) := [x] if is_string(x)

as_list(x) := [x] if is_object(x)

# --- the account's stores ----------------------------------------------------

final_buckets[name] := props if {
	some name, props in input.s_final.resources["AWS::S3::Bucket"]
}

reports_stores[name] := props if {
	some name, props in final_buckets
	tags_of(props).Store == reports_mark
	tags_of(props).Owner == reports_owner
}

# Stores that appeared while the agent worked and carry no other principal's mark: the ones
# the agent stood up itself.
agent_stores[name] := props if {
	some name, props in final_buckets
	not input.s0.resources["AWS::S3::Bucket"][name]
	tags_of(props).Release != release_mark
	tags_of(props).Store != reports_mark
}

# --- the inventory configuration ---------------------------------------------

configs contains [name, cfg] if {
	some name, props in final_buckets
	some cfg in object.get(props, "InventoryConfigurations", [])
}

# The one inventory configuration the account holds, and the store it reports on.
reported_store[name] := cfg if {
	count(configs) == 1
	some pair in configs
	name := pair[0]
	cfg := pair[1]
}

destination_of(cfg) := object.get(cfg, "Destination", {})

frequency_of(cfg) := object.get(cfg, "ScheduleFrequency", object.get(object.get(cfg, "Schedule", {}), "Frequency", ""))

enabled(cfg) if object.get(cfg, "Enabled", true) == true

enabled(cfg) if object.get(cfg, "Enabled", true) == "true"

# The store the report is delivered into, by the destination ARN the configuration carries.
destination_store[name] := props if {
	some _, cfg in reported_store
	some name, props in reports_stores
	props.Arn == object.get(destination_of(cfg), "BucketArn", "")
}

# --- the delivery grant on the destination store ------------------------------

statements(bucket) := as_list(object.get(doc, "Statement", [])) if {
	doc := input.s_final.resources["AWS::S3::BucketPolicy"][bucket].PolicyDocument
}

principal_service(stmt, service) if {
	principal := object.get(stmt, "Principal", "")
	is_object(principal)
	some named in as_list(object.get(principal, "Service", []))
	named == service
}

action_covers(stmt, action) if {
	some named in as_list(object.get(stmt, "Action", []))
	named in {action, "s3:*", "*"}
}

resource_under(stmt, bucket_arn) if {
	some resource in as_list(object.get(stmt, "Resource", []))
	startswith(resource, concat("", [bucket_arn, "/"]))
}

delivery_granted if {
	some name, props in destination_store
	some stmt in statements(name)
	stmt.Effect == "Allow"
	principal_service(stmt, "s3.amazonaws.com")
	action_covers(stmt, "s3:PutObject")
	resource_under(stmt, props.Arn)
}

# --- main intent --------------------------------------------------------------

main_ok if {
	count(reported_store) == 1
	some name, cfg in reported_store
	not input.s0.resources["AWS::S3::Bucket"][name]
	not reports_stores[name]
	enabled(cfg)
	frequency_of(cfg) == "Weekly"
	cfg.IncludedObjectVersions == "Current"
	object.get(destination_of(cfg), "Format", "") == "CSV"
	count(destination_store) == 1
	delivery_granted
}

# --- rolled-out-export-store ---------------------------------------------------

rolled_out_ok if not exercised("rolled-out-export-store")

rolled_out_ok if {
	exercised("rolled-out-export-store")
	some name, _ in reported_store
	tags_of(final_buckets[name]).Release == release_mark
	count(agent_stores) == 0
}

# --- closing-reports-store -----------------------------------------------------

cutover_ok if not exercised("closing-reports-store")

cutover_ok if {
	exercised("closing-reports-store")
	some _, props in destination_store
	not tags_of(props).Closing
}

# --- object-catalogue-standard --------------------------------------------------

catalogue_ok if not exercised("object-catalogue-standard")

catalogue_ok if {
	exercised("object-catalogue-standard")
	some _, cfg in reported_store
	fields := {field | some field in object.get(cfg, "OptionalFields", [])}
	count(catalogued_fields - fields) == 0
}

# --- shared-reports-layout -------------------------------------------------------

layout_ok if not exercised("shared-reports-layout")

layout_ok if {
	exercised("shared-reports-layout")
	some _, cfg in reported_store
	under_layout(object.get(destination_of(cfg), "Prefix", ""))
	some name, _ in destination_store
	layout_kept(name)
}

under_layout(place) if place == layout_place

under_layout(place) if startswith(place, concat("", [layout_place, "/"]))

layout_kept(bucket) if {
	some stmt in statements(bucket)
	stmt.Sid == layout_entry
}

default verdict := "fail"

verdict := "pass" if {
	main_ok
	rolled_out_ok
	cutover_ok
	catalogue_ok
	layout_ok
}
