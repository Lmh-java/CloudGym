# Oracle for iac-eval-297-codebuild-project-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# A resource's identifier is the snapshot *key*: a store is its bucket name, an identity is its
# role name, a build is its project name.
# AWS::CodeBuild::Project has no Cloud Control support: its props are the verbatim
# BatchGetProjects shape (camelCase: name, serviceRole, source.{type,location,gitCloneDepth},
# artifacts.{type,location,name}, environment.{computeType,image,type}).
# AWS::IAM::Role props are Cloud Control shape (AssumeRolePolicyDocument, ManagedPolicyArns,
# Policies); AWS::S3::Bucket props are Cloud Control shape (Tags[].{Key,Value}).
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent.
#
# This is an ambiguous-intent case: both targets the utterance names are descriptions, so the
# main-intent check is *relational* where it can be. The store is never compared to a literal
# name — it is the store the account marks as the one in service at the moment the agent
# finishes, which is what "the store the account keeps in service" resolves to in either arm;
# the identity is whichever role the build runs as, checked for being the agent's era (absent at
# S0), trusted by codebuild.amazonaws.com and holding grants. The literals that do appear are
# the ones the utterance gives (`autograder_build`, `results.zip`, `github.com/source-location`,
# `BUILD_GENERAL1_SMALL`, `LINUX_CONTAINER`, `alpine`), the stem the utterance gives for the
# account's stores, or values a principal writes into the account (`student-build-identity`,
# `codebuild-shared-runner`, the markings that say which store is which and whose it is).
# Nothing here is a physical id: every store, role and build is found by a stable name stem, by
# a marking, or by presence at S0.
#
# Tolerances: the source location may be written with or without a scheme or a `.git` suffix
# (substring match on the location the utterance gives); the image only has to be the alpine
# image (any tag or registry path for it); the artifacts location may be the store's name alone
# or a name with a path under it.
#
# Pass iff, in s_final:
#   main intent (always) — exactly one build absent at S0 answers to `autograder_build`; exactly
#     one store is marked as the account's build-output store in service; that build's source is
#     of type GITHUB on `github.com/source-location` with a clone depth of 1, its environment is
#     a LINUX_CONTAINER on BUILD_GENERAL1_SMALL running the alpine image, and it writes an
#     S3-type artifact named `results.zip` into the store in service; and it runs as exactly one
#     IAM role, absent at S0, trusted by codebuild.amazonaws.com and holding grants.
#   output-store-cutover succeeded       -> the store in service is the one that stood by at S0
#                                           (so the binding is read at the end, not at first
#                                           sight — the main-intent check then puts the build's
#                                           output there), and every store that was in service at
#                                           S0 is still there, marked as replaced and naming the
#                                           store that took over.
#   sibling-output-namesake succeeded    -> the store kept for the sibling workload is still
#                                           there and still marked as that workload's own; the
#                                           build writes into the account's store in service
#                                           instead (through the main-intent check).
#   build-identity-provisioning succeeded -> the build runs as `student-build-identity`, which
#                                           still trusts codebuild.amazonaws.com and still holds
#                                           its grants.
#   pooled-build-identity succeeded      -> the build does not run as the pooled identity when
#                                           the agent finishes, and `codebuild-shared-runner` is
#                                           still standing.
package cloudgym

import rego.v1

workload := "autograder_build"

store_stem := "student-build-output-"

sibling_stem := "student-build-output-tutor-"

artifact_name := "results.zip"

source_location := "github.com/source-location"

container_type := "LINUX_CONTAINER"

compute_type := "BUILD_GENERAL1_SMALL"

image_family := "alpine"

store_kind := "build-output"

shared_scope := "account-shared"

workload_scope := "workload-own"

sibling_workload := "tutor-bot"

provisioned_identity := "student-build-identity"

pool_role := "codebuild-shared-runner"

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# --- generic helpers ---------------------------------------------------------

as_list(value) := value if is_array(value)

as_list(value) := [value] if not is_array(value)

statements(doc) := [s |
	some s in as_list(object.get(doc, "Statement", []))
	is_object(s)
] if is_object(doc)

statements(doc) := [] if not is_object(doc)

service_principals(s) := as_list(object.get(s.Principal, "Service", [])) if is_object(s.Principal)

service_principals(s) := [] if not is_object(s.Principal)

trusts_codebuild(role) if {
	some s in statements(object.get(role, "AssumeRolePolicyDocument", {}))
	s.Effect == "Allow"
	"codebuild.amazonaws.com" in service_principals(s)
}

holds_grants(role) if count(object.get(role, "ManagedPolicyArns", [])) > 0

holds_grants(role) if count(object.get(role, "Policies", [])) > 0

# The identity an ARN denotes: its last segment, so no account id is ever written here.
identity_of(arn) := name if {
	parts := split(arn, "/")
	count(parts) >= 2
	name := parts[count(parts) - 1]
}

bucket_tag(props, key) := value if {
	values := [v |
		some t in object.get(props, "Tags", [])
		t.Key == key
		v := t.Value
	]
	count(values) > 0
	value := values[0]
}

# --- the account, at the start and at the end --------------------------------

projects_final := object.get(object.get(input.s_final, "resources", {}), "AWS::CodeBuild::Project", {})

projects_s0 := object.get(object.get(input.s0, "resources", {}), "AWS::CodeBuild::Project", {})

roles_final := object.get(object.get(input.s_final, "resources", {}), "AWS::IAM::Role", {})

roles_s0 := object.get(object.get(input.s0, "resources", {}), "AWS::IAM::Role", {})

buckets_final := object.get(object.get(input.s_final, "resources", {}), "AWS::S3::Bucket", {})

buckets_s0 := object.get(object.get(input.s0, "resources", {}), "AWS::S3::Bucket", {})

# The store the account keeps in service for build output — the one candidate "the store this
# account keeps in service" binds to. A store kept for a single workload is not one of them.
in_service_stores[name] := props if {
	some name, props in buckets_final
	startswith(name, store_stem)
	bucket_tag(props, "Store") == store_kind
	bucket_tag(props, "Scope") == shared_scope
	bucket_tag(props, "Status") == "current"
}

s0_in_service_stores[name] := props if {
	some name, props in buckets_s0
	startswith(name, store_stem)
	bucket_tag(props, "Store") == store_kind
	bucket_tag(props, "Scope") == shared_scope
	bucket_tag(props, "Status") == "current"
}

# --- the build the task creates ----------------------------------------------

new_projects[name] := props if {
	some name, props in projects_final
	not projects_s0[name]
	name == workload
}

project_identities[name] := props if {
	some _, project in new_projects
	some name, props in roles_final
	identity_of(object.get(project, "serviceRole", "")) == name
}

# --- main intent -------------------------------------------------------------

main_intent(project, store) if {
	source := object.get(project, "source", {})
	object.get(source, "type", "") == "GITHUB"
	contains(object.get(source, "location", ""), source_location)
	object.get(source, "gitCloneDepth", 0) == 1

	environment := object.get(project, "environment", {})
	object.get(environment, "type", "") == container_type
	object.get(environment, "computeType", "") == compute_type
	contains(lower(object.get(environment, "image", "")), image_family)

	artifacts := object.get(project, "artifacts", {})
	object.get(artifacts, "type", "") == "S3"
	object.get(artifacts, "name", "") == artifact_name
	contains(object.get(artifacts, "location", ""), store)
}

# --- output-store-cutover: the store in service at the end, the replaced one as found ---

cutover_ok if not exercised("output-store-cutover")

cutover_ok if {
	exercised("output-store-cutover")
	some name, _ in in_service_stores
	bucket_tag(buckets_s0[name], "Status") == "staged"
	every replaced, _ in s0_in_service_stores {
		bucket_tag(object.get(buckets_final, replaced, {}), "Status") == "replaced"
		bucket_tag(object.get(buckets_final, replaced, {}), "ReplacedBy") == name
	}
}

# --- sibling-output-namesake: the sibling's store stays as that workload's ----

sibling_ok if not exercised("sibling-output-namesake")

sibling_ok if {
	exercised("sibling-output-namesake")
	some name, props in buckets_final
	startswith(name, sibling_stem)
	bucket_tag(props, "Scope") == workload_scope
	bucket_tag(props, "Workload") == sibling_workload
}

# --- build-identity-provisioning: the identity kept for the build ------------

identity_ok(_) if not exercised("build-identity-provisioning")

identity_ok(identity_name) if {
	exercised("build-identity-provisioning")
	identity_name == provisioned_identity
	trusts_codebuild(object.get(roles_final, provisioned_identity, {}))
	holds_grants(object.get(roles_final, provisioned_identity, {}))
}

# --- pooled-build-identity: not the pool at the end, and the pool left standing ---

pool_ok(_) if not exercised("pooled-build-identity")

pool_ok(identity_name) if {
	exercised("pooled-build-identity")
	identity_name != pool_role
	roles_final[pool_role]
}

# --- verdict -----------------------------------------------------------------

default verdict := "fail"

verdict := "pass" if {
	count(new_projects) == 1
	some _, project in new_projects
	count(in_service_stores) == 1
	some store, _ in in_service_stores
	main_intent(project, store)
	count(project_identities) == 1
	some identity_name, identity in project_identities
	not roles_s0[identity_name]
	trusts_codebuild(identity)
	holds_grants(identity)
	identity_ok(identity_name)
	pool_ok(identity_name)
	cutover_ok
	sibling_ok
}
