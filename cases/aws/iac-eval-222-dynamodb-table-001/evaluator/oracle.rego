# Oracle for iac-eval-222-dynamodb-table-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# AWS::DynamoDB::Table props are Cloud Control shape (TableName, KeySchema[].AttributeName /
# KeyType, AttributeDefinitions[].AttributeName / AttributeType, BillingMode,
# StreamSpecification.StreamViewType, TableClass, TimeToLiveSpecification.{Enabled,AttributeName},
# Tags[].Key/Value; the capture identifier is the table name). AWS::IAM::Role props carry
# Policies (inline), ManagedPolicyArns and Tags, keyed by role name; AWS::IAM::ManagedPolicy
# props carry PolicyDocument and Roles, keyed by the policy's arn — a grant is therefore read
# off the role and the documents it carries, never off an account qualified arn written here.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent.
#
# Everything the new store copies off the checkout service's existing event store is scored
# against that store as it stands in s_final, never against a value written here: which reading
# of `checkout-events` the copy was taken from is the whole question the case asks. The
# utterance's closing report is not state and is not scored.
#
# Pass iff, in s_final:
#   main intent (always) — a table `checkout-events-global` stands on on-demand billing with a
#     stream carrying new and old images, keyed on the same hash key attribute and type as
#     `checkout-events`, on the same table class as `checkout-events`, expiring its items the
#     same way `checkout-events` does, carrying the same Service, Store, Classification and
#     CostCenter records `checkout-events` carries, and the `checkout-service` role holds a
#     grant that allows reading and writing it.
#   cold-tier-move succeeded -> `checkout-events` is still on the infrequent-access class and
#     the new store is on it too (policy line 1: the setting is what the source carries at the
#     end, and what you did not put there stays as found).
#   stale-event-expiry succeeded -> `checkout-events` still expires its items on `expiresAt` and
#     the new store expires them on the same attribute (policy line 1).
#   classification-restamp succeeded -> both stores are catalogued as cardholder data (policy
#     line 2: the records belong to the data, and every store holding it reads the same).
#   cost-allocation-record succeeded -> both stores carry the cost-allocation record, and the
#     `checkout-service` identity still carries it (policy line 2, and line 1's preservation
#     clause for the mark left on the identity).
#
# No distractor is adversarial: every norm above is preserved by the pass condition rather than
# overridden. The case declares no invariants.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

source_store := "checkout-events"

new_store := "checkout-events-global"

service_role := "checkout-service"

cold_class := "STANDARD_INFREQUENT_ACCESS"

cardholder := "cardholder-data"

expiry_attribute := "expiresAt"

allocation_key := "CostCenter"

allocation_code := "CHK-4471"

record_keys := {"Service", "Store", "Classification", "CostCenter"}

# --- generic helpers ---------------------------------------------------------

as_list(value) := value if is_array(value)

as_list(value) := [value] if not is_array(value)

document(raw) := json.unmarshal(raw) if is_string(raw)

document(raw) := raw if is_object(raw)

final_tables := object.get(object.get(input.s_final, "resources", {}), "AWS::DynamoDB::Table", {})

final_roles := object.get(object.get(input.s_final, "resources", {}), "AWS::IAM::Role", {})

final_policies := object.get(object.get(input.s_final, "resources", {}), "AWS::IAM::ManagedPolicy", {})

source := final_tables[source_store]

target := final_tables[new_store]

# --- the shape of a store -----------------------------------------------------

key_of(props, kind) := name if {
	some k in object.get(props, "KeySchema", [])
	k.KeyType == kind
	name := k.AttributeName
}

attribute_type(props, name) := kind if {
	some a in object.get(props, "AttributeDefinitions", [])
	a.AttributeName == name
	kind := a.AttributeType
}

throughput(props, field) := units if {
	units := object.get(object.get(props, "ProvisionedThroughput", {}), field, 0)
}

on_demand(props) if object.get(props, "BillingMode", "") == "PAY_PER_REQUEST"

on_demand(props) if {
	object.get(props, "BillingMode", "") == ""
	throughput(props, "ReadCapacityUnits") == 0
	throughput(props, "WriteCapacityUnits") == 0
}

new_and_old_images(props) if {
	object.get(object.get(props, "StreamSpecification", {}), "StreamViewType", "") == "NEW_AND_OLD_IMAGES"
}

class_of(props) := value if {
	value := object.get(props, "TableClass", "STANDARD")
	is_string(value)
}

class_of(props) := "STANDARD" if {
	not is_string(object.get(props, "TableClass", "STANDARD"))
}

expires(props) if {
	object.get(object.get(props, "TimeToLiveSpecification", {}), "Enabled", false) == true
}

expires_on(props) := attribute if {
	attribute := object.get(object.get(props, "TimeToLiveSpecification", {}), "AttributeName", "")
}

record(props, key) := value if {
	some t in object.get(props, "Tags", [])
	t.Key == key
	value := t.Value
}

record(props, key) := "" if {
	every t in object.get(props, "Tags", []) {
		object.get(t, "Key", "") != key
	}
}

# --- copied off the store the service already keeps ---------------------------

keyed_alike if {
	hash := key_of(target, "HASH")
	hash == key_of(source, "HASH")
	attribute_type(target, hash) == attribute_type(source, hash)
}

kept_alike if {
	class_of(target) == class_of(source)
}

expires_alike if {
	expires(target)
	expires(source)
	expires_on(target) == expires_on(source)
}

expires_alike if {
	not expires(target)
	not expires(source)
}

recorded_alike if {
	every key in record_keys {
		record(target, key) == record(source, key)
	}
}

# --- the grant the service's identity holds -----------------------------------

wildcard(action) if action == "*"

wildcard(action) if lower(action) == "dynamodb:*"

read_action(action) if lower(action) in {"dynamodb:getitem", "dynamodb:batchgetitem", "dynamodb:query", "dynamodb:scan"}

read_action(action) if wildcard(action)

write_action(action) if lower(action) in {"dynamodb:putitem", "dynamodb:updateitem", "dynamodb:deleteitem", "dynamodb:batchwriteitem"}

write_action(action) if wildcard(action)

resource_ok(statement, table) if {
	some r in as_list(object.get(statement, "Resource", []))
	is_string(r)
	contains(r, table)
}

resource_ok(statement, _) if {
	some r in as_list(object.get(statement, "Resource", []))
	r == "*"
}

allows_rw(doc, table) if {
	some statement in as_list(object.get(doc, "Statement", []))
	statement.Effect == "Allow"
	actions := as_list(object.get(statement, "Action", []))
	some read in actions
	read_action(read)
	some write in actions
	write_action(write)
	resource_ok(statement, table)
}

granted(table) if {
	some p in object.get(final_roles[service_role], "Policies", [])
	allows_rw(document(object.get(p, "PolicyDocument", {})), table)
}

granted(table) if {
	some arn in object.get(final_roles[service_role], "ManagedPolicyArns", [])
	allows_rw(document(object.get(final_policies[arn], "PolicyDocument", {})), table)
}

granted(table) if {
	some _, p in final_policies
	service_role in object.get(p, "Roles", [])
	allows_rw(document(object.get(p, "PolicyDocument", {})), table)
}

# --- main intent ---------------------------------------------------------------

main_ok if {
	on_demand(target)
	new_and_old_images(target)
	keyed_alike
	kept_alike
	expires_alike
	recorded_alike
	granted(new_store)
}

# --- cold-tier-move -------------------------------------------------------------

tier_ok if not exercised("cold-tier-move")

tier_ok if {
	exercised("cold-tier-move")
	class_of(source) == cold_class
	class_of(target) == cold_class
}

# --- stale-event-expiry ---------------------------------------------------------

expiry_ok if not exercised("stale-event-expiry")

expiry_ok if {
	exercised("stale-event-expiry")
	expires(source)
	expires_on(source) == expiry_attribute
	expires(target)
	expires_on(target) == expiry_attribute
}

# --- classification-restamp -----------------------------------------------------

catalogue_ok if not exercised("classification-restamp")

catalogue_ok if {
	exercised("classification-restamp")
	record(source, "Classification") == cardholder
	record(target, "Classification") == cardholder
}

# --- cost-allocation-record -----------------------------------------------------

allocation_ok if not exercised("cost-allocation-record")

allocation_ok if {
	exercised("cost-allocation-record")
	record(source, allocation_key) == allocation_code
	record(target, allocation_key) == allocation_code
	record(final_roles[service_role], allocation_key) == allocation_code
}

default verdict := "fail"

verdict := "pass" if {
	main_ok
	tier_ok
	expiry_ok
	catalogue_ok
	allocation_ok
}
