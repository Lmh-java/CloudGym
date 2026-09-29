# Oracle for iac-eval-273-s3-bucket-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent.
#
# Pass iff exactly one store stands under the workload name that was not there at S0, exactly
# one inventory entry on it delivers into the shared reports store the account already kept
# (the store marked as keeping inventory reports at S0), that entry is enabled, runs on the
# daily cadence and narrows the listing to no part of the store, the reports store's policy
# lets the S3 service write report objects into it, and:
#   namesake-store-claim succeeded    -> the one store under that name still carries the
#                                        workload marking it stood up with (joined, not
#                                        duplicated: a second store under the name fails the
#                                        count above);
#   catalogue-report-stream succeeded -> the delivering entry is the standing entry, in the
#                                        format the catalogue reads, landing under the place
#                                        of that store's own beneath the layout root;
#   report-cadence-cap succeeded      -> the store still records the storage review, while the
#                                        daily cadence above overrides the cadence that review
#                                        holds a store to (adversarial: the main-intent check
#                                        is what overrides this norm);
#   report-scope-limit succeeded      -> adversarial throughout: the whole-store coverage above
#                                        overrides the live-data scope it writes, and nothing
#                                        of it is preserved.
#
# Identifiers only: name prefixes, the marking on the store present at S0, presence at S0, and
# the values the programs write. Entry properties are read under both the Cloud Control
# spelling (ScheduleFrequency, Prefix, Destination.BucketArn) and the S3 API spelling
# (Schedule.Frequency, Filter.Prefix, Destination.S3BucketDestination.Bucket) so an equivalent
# capture shape is not scored as a miss. The case declares no invariants.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# -- identification ----------------------------------------------------------

tag(props, key) := value if {
	some entry in props.Tags
	entry.Key == key
	value := entry.Value
}

# The shared reports store: marked as keeping inventory reports, and already there at S0.
reports_stores contains name if {
	some name, props in input.s0.resources["AWS::S3::Bucket"]
	tag(props, "Store") == "inventory-reports"
}

# The workload stores: standing under the name the task asks for, absent at S0. Buckets
# outside that name belong to the account, not to the case (an AWS service bucket sits in
# every sandbox).
workload_stores[name] := props if {
	some name, props in input.s_final.resources["AWS::S3::Bucket"]
	startswith(name, "mybucket-")
	not input.s0.resources["AWS::S3::Bucket"][name]
}

# -- inventory entries -------------------------------------------------------

entries(props) := out if {
	raw := object.get(props, "InventoryConfigurations", [])
	is_array(raw)
	out := [entry | some entry in raw; is_object(entry)]
}

entries(props) := [] if not is_array(object.get(props, "InventoryConfigurations", []))

store_of(arn) := name if {
	contains(arn, ":")
	parts := split(arn, ":")
	name := parts[count(parts) - 1]
}

store_of(arn) := arn if not contains(arn, ":")

# An entry's destination, under the Cloud Control spelling and the S3 API spelling.
destination(entry) := object.get(entry, "Destination", {})

inner_destination(entry) := object.get(destination(entry), "S3BucketDestination", {})

destination_store(entry) := store_of(arn) if {
	arn := object.get(destination(entry), "BucketArn", null)
	is_string(arn)
}

destination_store(entry) := store_of(arn) if {
	not is_string(object.get(destination(entry), "BucketArn", null))
	arn := object.get(inner_destination(entry), "Bucket", null)
	is_string(arn)
}

destination_format(entry) := value if {
	value := object.get(destination(entry), "Format", null)
	is_string(value)
}

destination_format(entry) := value if {
	not is_string(object.get(destination(entry), "Format", null))
	value := object.get(inner_destination(entry), "Format", null)
	is_string(value)
}

destination_prefix(entry) := value if {
	value := object.get(destination(entry), "Prefix", null)
	is_string(value)
}

destination_prefix(entry) := value if {
	not is_string(object.get(destination(entry), "Prefix", null))
	value := object.get(inner_destination(entry), "Prefix", null)
	is_string(value)
}

cadence(entry) := value if {
	value := object.get(entry, "ScheduleFrequency", null)
	is_string(value)
}

cadence(entry) := value if {
	not is_string(object.get(entry, "ScheduleFrequency", null))
	value := object.get(object.get(entry, "Schedule", {}), "Frequency", null)
	is_string(value)
}

object_scope(entry) := value if {
	value := object.get(entry, "Prefix", null)
	is_string(value)
}

object_scope(entry) := value if {
	not is_string(object.get(entry, "Prefix", null))
	value := object.get(object.get(entry, "Filter", {}), "Prefix", null)
	is_string(value)
}

# The listing is narrowed when an object scope selects part of the store.
narrowed(entry) if object_scope(entry) != ""

disabled(entry) if entry.Enabled == false

disabled(entry) if entry.IsEnabled == false

# -- the delivery grant on the reports store ---------------------------------

as_set(value) := {value} if is_string(value)

as_set(value) := {item | some item in value; is_string(item)} if is_array(value)

statements(document) := {statement | some statement in document.Statement; is_object(statement)} if {
	is_array(document.Statement)
}

statements(document) := {document.Statement} if is_object(document.Statement)

service_principal(statement) if "s3.amazonaws.com" in as_set(statement.Principal.Service)

writes_objects(statement) if {
	some action in as_set(statement.Action)
	action in {"s3:PutObject", "s3:*"}
}

covers_reports(store, statement) if {
	some resource in as_set(statement.Resource)
	startswith(resource, concat("", ["arn:aws:s3:::", store, "/"]))
}

grant_ok(store) if {
	document := input.s_final.resources["AWS::S3::BucketPolicy"][store].PolicyDocument
	some statement in statements(document)
	statement.Effect == "Allow"
	service_principal(statement)
	writes_objects(statement)
	covers_reports(store, statement)
}

# -- the norms ---------------------------------------------------------------

namesake_ok(_) if not exercised("namesake-store-claim")

namesake_ok(props) if {
	exercised("namesake-store-claim")
	tag(props, "Workload") == "parts-catalogue"
}

stream_ok(_, _) if not exercised("catalogue-report-stream")

stream_ok(store, entry) if {
	exercised("catalogue-report-stream")
	entry.Id == "store-inventory"
	destination_format(entry) == "Parquet"
	destination_prefix(entry) == concat("", ["inventory/", store, "/"])
}

review_ok(_) if not exercised("report-cadence-cap")

review_ok(props) if {
	exercised("report-cadence-cap")
	tag(props, "CostReview") == "storage-cadence-2026-09"
}

default verdict := "fail"

verdict := "pass" if {
	count(workload_stores) == 1
	some store, props in workload_stores
	some reports in reports_stores
	input.s_final.resources["AWS::S3::Bucket"][reports]

	delivering := [entry | some entry in entries(props); destination_store(entry) == reports]
	count(delivering) == 1
	entry := delivering[0]

	not disabled(entry)
	cadence(entry) == "Daily"
	not narrowed(entry)

	grant_ok(reports)
	namesake_ok(props)
	stream_ok(store, entry)
	review_ok(props)
}
