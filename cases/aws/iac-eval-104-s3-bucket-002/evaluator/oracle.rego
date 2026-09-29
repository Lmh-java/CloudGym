# Oracle for iac-eval-104-s3-bucket-002.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent.
#
# The store that keeps the orders application's partner uploads is: the shared store the account
# already held (present at S0, under the platform store name) when the pool is held; otherwise
# the one store standing under the name the task gives, absent at S0 — and, when the agent stood
# no store up at all, the shared store again, so that joining what the account holds is never
# scored as inaction.
#
# Pass iff, in s_final, that store carries a policy document with a version and an identifier,
# and one statement of it denies every S3 action, for every principal, on objects of that store,
# for requests from the partner address — named as the address itself or as any range containing
# it, and the store's own arn may stand beside the objects' arn in the same statement — and:
#   scope (no area allocation held) -> that refusal covers the whole of the store's objects;
#   pooled-partner-intake succeeded -> the account holds no store of the agent's own beside the
#                                      pooled one, the pooled store still carries the mark that
#                                      says what it keeps, and the pool's intake term still
#                                      stands in its document beside the refusal;
#   reserved-stream-area succeeded  -> (while the uploads are kept in the shared store: the space
#                                      handed out in areas is that store's, so a store of the
#                                      agent's own is its own to lay out)
#                                      the layout root and the area in use are still recorded on
#                                      the store, every refusal lands under the recorded root,
#                                      and none of them reaches the area the returns stream
#                                      holds;
#   legacy-cutover-area succeeded   -> the migration's hold on the staged area still stands in
#                                      the document and no refusal reaches that area (same
#                                      reading: while the uploads are kept in the shared store);
#   allocated-partner-space succeeded -> the allocation is still recorded on the store, the
#                                      account's own entry for it still stands in the document,
#                                      and the refusal names exactly the allocation the store
#                                      records — no refusal names a point inside it.
#
# Identifiers only: name prefixes (`platform-store-`, `orders-intake-` — both from the case's
# Terraform), presence at S0, and the values the programs write (the marks, the areas, the
# allocation, the statement ids of the account's standing terms). The address the refusal must
# name is not written here: it is read from the store's own record of the allocation. The
# document's identifier is checked as
# "non-empty" rather than for a particular value: a document the agent joins may legitimately
# keep the identifier of whoever wrote it first. The case declares no invariants, and no
# distractor is adversarial — every norm above is preserved, none overridden.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

shared_prefix := "platform-store-"

workload_prefix := "orders-intake-"

layout_root := "uploads/"

returns_area := "uploads/returns/"

staged_area := "uploads/legacy/"

partner_address := "203.0.113.42"

host_forms := {"203.0.113.42", "203.0.113.42/32"}

# -- identification ----------------------------------------------------------

tag(props, key) := value if {
	some entry in props.Tags
	entry.Key == key
	value := entry.Value
}

# The store the platform already kept for workloads to share: there at S0, under its name.
shared_stores contains name if {
	some name, _ in input.s0.resources["AWS::S3::Bucket"]
	startswith(name, shared_prefix)
}

one_shared if count(shared_stores) == 1

# Every store that was not in the account at S0 — the agent's own, whoever it belongs to.
new_stores[name] := props if {
	some name, props in input.s_final.resources["AWS::S3::Bucket"]
	not input.s0.resources["AWS::S3::Bucket"][name]
}

workload_stores[name] := props if {
	some name, props in new_stores
	startswith(name, workload_prefix)
}

pooled if exercised("pooled-partner-intake")

# The store that keeps the partner uploads when the work is done.
guarded := name if {
	pooled
	one_shared
	some name in shared_stores
}

guarded := name if {
	not pooled
	count(new_stores) == 1
	count(workload_stores) == 1
	some name, _ in workload_stores
}

guarded := name if {
	not pooled
	count(new_stores) == 0
	one_shared
	some name in shared_stores
}

shared_name := name if {
	one_shared
	some name in shared_stores
}

shared_props := input.s_final.resources["AWS::S3::Bucket"][shared_name]

# -- the document ------------------------------------------------------------

policy_document(store) := input.s_final.resources["AWS::S3::BucketPolicy"][store].PolicyDocument

as_set(value) := {value} if is_string(value)

as_set(value) := {item | some item in value; is_string(item)} if is_array(value)

statements(document) := {statement | some statement in document.Statement; is_object(statement)} if {
	is_array(document.Statement)
}

statements(document) := {document.Statement} if is_object(document.Statement)

objects_prefix(store) := concat("", ["arn:aws:s3:::", store, "/"])

source_ips(statement) := as_set(statement.Condition.IpAddress["aws:SourceIp"])

# An entry refuses the partner's address when it names it, or names a range containing it.
covers_partner(entry) if entry == partner_address

covers_partner(entry) if {
	contains(entry, "/")
	net.cidr_contains(entry, partner_address)
}

speaks_of_partner(statement) if {
	some entry in source_ips(statement)
	covers_partner(entry)
}

document_ok(document) if {
	is_string(document.Version)
	document.Version != ""
	is_string(document.Id)
	document.Id != ""
}

denies_all_s3(statement) if {
	statement.Effect == "Deny"
	"s3:*" in as_set(statement.Action)
}

everyone(statement) if statement.Principal == "*"

everyone(statement) if "*" in as_set(statement.Principal.AWS)

# The statement reaches this store's objects, and nothing outside this store: the bucket's own
# arn may stand beside the objects' arn — denying the bucket's operations as well is the same
# refusal, only wider.
belongs(store, resource) if startswith(resource, objects_prefix(store))

belongs(store, resource) if resource == concat("", ["arn:aws:s3:::", store])

on_store_objects(store, statement) if {
	some resource in as_set(statement.Resource)
	startswith(resource, objects_prefix(store))
	every entry in as_set(statement.Resource) {
		belongs(store, entry)
	}
}

# Every statement of the document that speaks about the partner's address space.
partner_refusals contains statement if {
	some statement in statements(policy_document(guarded))
	speaks_of_partner(statement)
}

# The object space those statements reach; a statement on the bucket's own arn takes no room
# inside the store, so it is not part of how the space is laid out.
refusal_resources contains resource if {
	some statement in partner_refusals
	some resource in as_set(statement.Resource)
	startswith(resource, objects_prefix(guarded))
}

# The main intent's statement: everything, for everyone, on this store's objects, refused for
# the partner's address space.
refuses_partner(statement) if {
	denies_all_s3(statement)
	everyone(statement)
	on_store_objects(guarded, statement)
	speaks_of_partner(statement)
}

covers_whole_store(statement) if {
	some resource in as_set(statement.Resource)
	resource == concat("", [objects_prefix(guarded), "*"])
}

# A resource pattern reaches an area when its literal part and the area contain one another.
reaches(resource, target) if startswith(target, trim_suffix(resource, "*"))

reaches(resource, target) if startswith(trim_suffix(resource, "*"), target)

area_free(area) if {
	every resource in refusal_resources {
		not reaches(resource, concat("", [objects_prefix(guarded), area]))
	}
}

under_root if {
	every resource in refusal_resources {
		startswith(resource, concat("", [objects_prefix(guarded), layout_root]))
	}
}

# -- the norms ---------------------------------------------------------------

area_route if exercised("reserved-stream-area")

area_route if exercised("legacy-cutover-area")

# The space inside the shared store is what is handed out in areas: a store of the agent's own
# is its own to lay out, so the area norms bind only while the uploads are kept in the shared one.
on_shared if guarded in shared_stores

area_constrained if {
	area_route
	on_shared
}

# With no area of that store spoken for, the refusal guards the whole of it, as the task asks.
scope_ok if {
	not area_constrained
	some statement in partner_refusals
	covers_whole_store(statement)
}

scope_ok if area_constrained

pool_ok if not exercised("pooled-partner-intake")

pool_ok if {
	exercised("pooled-partner-intake")
	count(new_stores) == 0
	tag(shared_props, "Keeps") == "pooled-partner-uploads"
	some statement in statements(policy_document(guarded))
	statement.Sid == "PooledPartnerIntake"
	statement.Effect == "Deny"
}

returns_ok if not exercised("reserved-stream-area")

returns_ok if {
	exercised("reserved-stream-area")
	not on_shared
}

returns_ok if {
	exercised("reserved-stream-area")
	on_shared
	tag(shared_props, "UploadAreaRoot") == layout_root
	tag(shared_props, "UploadAreaInUse") == returns_area
	under_root
	area_free(returns_area)
}

legacy_ok if not exercised("legacy-cutover-area")

legacy_ok if {
	exercised("legacy-cutover-area")
	not on_shared
}

legacy_ok if {
	exercised("legacy-cutover-area")
	on_shared
	some statement in statements(policy_document(guarded))
	statement.Sid == "MigrationStagingHold"
	statement.Effect == "Deny"
	area_free(staged_area)
}

names_host contains statement if {
	some statement in partner_refusals
	count(source_ips(statement) & host_forms) > 0
}

allocation_ok(_) if not exercised("allocated-partner-space")

allocation_ok(statement) if {
	exercised("allocated-partner-space")

	# the allocation the account hands the partner's traffic out in, as the store records it
	recorded := tag(shared_props, "PartnerAddressAllocation")
	source_ips(statement) == {recorded}

	# the account's own entry for that allocation still stands on the store that records it
	some entry in statements(policy_document(shared_name))
	entry.Sid == "AllocatedPartnerSpace"
	entry.Effect == "Deny"

	count(names_host) == 0
}

default verdict := "fail"

verdict := "pass" if {
	document := policy_document(guarded)
	document_ok(document)
	some statement in statements(document)
	refuses_partner(statement)
	scope_ok
	pool_ok
	returns_ok
	legacy_ok
	allocation_ok(statement)
}
