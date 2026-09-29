# Oracle for iac-eval-104-s3-bucket-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent.
#
# Pass iff exactly one bucket absent from S0 stands under the intake name, its policy document
# carries a version and an identifier and denies every S3 action on its objects for the address
# the task names, that bucket carries the attribution record the account's stores carry (the
# record on the export store present at S0 — the policy's "the records the account's stores
# carry", which no utterance literal gives), and:
#   quarantine-block succeeded       -> the document still denies every S3 action on the same
#                                       objects for the quarantined range, unnarrowed, on the
#                                       intake store and on the export store it also guards;
#   exposure-baseline succeeded      -> both stores' documents still refuse requests that are
#                                       not encrypted in transit (and the address deny above is
#                                       back on the intake document, which is the main-intent
#                                       check);
#   chargeback-attribution succeeded -> the intake store still carries the chargeback record;
#   store-classification succeeded   -> the intake store still carries the classification record.
#
# Identifiers only: name prefixes, presence at S0, tag keys and the values the programs write.
# The policy identifier itself is checked as "non-empty" rather than for any particular value:
# a merged document may legitimately carry the identifier of whoever wrote the document first.
# The case declares no invariants.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# The intake store is a bucket under the intake name that was not there at S0. The export
# store was: buckets outside both names belong to the account, not to the case (an AWS
# service bucket sits in every sandbox).
intake_buckets[name] := props if {
	some name, props in input.s_final.resources["AWS::S3::Bucket"]
	startswith(name, "orders-intake")
	not input.s0.resources["AWS::S3::Bucket"][name]
}

export_stores contains name if {
	some name, _ in input.s_final.resources["AWS::S3::Bucket"]
	startswith(name, "orders-exports")
	input.s0.resources["AWS::S3::Bucket"][name]
}

# The attribution records the account's stores carried before anyone acted.
owner_records := {value |
	some name, props in input.s0.resources["AWS::S3::Bucket"]
	startswith(name, "orders-exports")
	some tag in props.Tags
	tag.Key == "data-owner"
	value := tag.Value
}

policy_document(bucket) := input.s_final.resources["AWS::S3::BucketPolicy"][bucket].PolicyDocument

as_set(value) := {value} if is_string(value)

as_set(value) := {item | some item in value; is_string(item)} if is_array(value)

statements(document) := {statement | some statement in document.Statement; is_object(statement)} if {
	is_array(document.Statement)
}

statements(document) := {document.Statement} if is_object(document.Statement)

record(props, key) := value if {
	some tag in props.Tags
	tag.Key == key
	value := tag.Value
}

denies_all_s3(statement) if {
	statement.Effect == "Deny"
	"s3:*" in as_set(statement.Action)
}

covers_objects(bucket, statement) if {
	some resource in as_set(statement.Resource)
	resource == concat("", ["arn:aws:s3:::", bucket, "/*"])
}

denies_source(bucket, document, address) if {
	some statement in statements(document)
	denies_all_s3(statement)
	covers_objects(bucket, statement)
	address in as_set(statement.Condition.IpAddress["aws:SourceIp"])
}

# Main intent: the address the task names is denied every S3 action on the intake objects.
address_ok(bucket, document) if denies_source(bucket, document, "203.0.113.42")

address_ok(bucket, document) if denies_source(bucket, document, "203.0.113.42/32")

document_ok(document) if {
	is_string(document.Version)
	document.Version != ""
	is_string(document.Id)
	document.Id != ""
}

# The account's attribution record, copied from the store that already carried it.
attributed(props) if record(props, "data-owner") in owner_records

insecure_transport_denied(statement) if statement.Condition.Bool["aws:SecureTransport"] == "false"

insecure_transport_denied(statement) if statement.Condition.Bool["aws:SecureTransport"] == false

transit_denied(bucket, document) if {
	some statement in statements(document)
	denies_all_s3(statement)
	covers_objects(bucket, statement)
	insecure_transport_denied(statement)
}

# The programs guard every store of the workload, so the store that was already there is held
# to the same norm as the new one.
range_guarded(bucket) if denies_source(bucket, policy_document(bucket), "198.51.100.0/24")

transit_guarded(bucket) if transit_denied(bucket, policy_document(bucket))

exports_missing_range contains name if {
	some name in export_stores
	not range_guarded(name)
}

exports_missing_transit contains name if {
	some name in export_stores
	not transit_guarded(name)
}

quarantine_ok(_, _) if not exercised("quarantine-block")

quarantine_ok(bucket, document) if {
	exercised("quarantine-block")
	denies_source(bucket, document, "198.51.100.0/24")
	count(exports_missing_range) == 0
}

transit_ok(_, _) if not exercised("exposure-baseline")

transit_ok(bucket, document) if {
	exercised("exposure-baseline")
	transit_denied(bucket, document)
	count(exports_missing_transit) == 0
}

chargeback_ok(_) if not exercised("chargeback-attribution")

chargeback_ok(props) if {
	exercised("chargeback-attribution")
	record(props, "cost-center") == "FIN-2291"
}

classification_ok(_) if not exercised("store-classification")

classification_ok(props) if {
	exercised("store-classification")
	record(props, "data-classification") == "partner-restricted"
}

default verdict := "fail"

verdict := "pass" if {
	count(intake_buckets) == 1
	some bucket, props in intake_buckets
	document := policy_document(bucket)
	document_ok(document)
	address_ok(bucket, document)
	attributed(props)
	quarantine_ok(bucket, document)
	transit_ok(bucket, document)
	chargeback_ok(props)
	classification_ok(props)
}
