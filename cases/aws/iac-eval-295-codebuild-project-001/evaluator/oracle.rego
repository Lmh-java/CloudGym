# Oracle for iac-eval-295-codebuild-project-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# A resource's identifier is the snapshot *key*, never a property: the extractor drops
# AWS::S3::Bucket's BucketName and AWS::IAM::Role's RoleName/Arn as volatile, so a store is its
# key and an identity is its key, and a project's serviceRole ARN is matched to an identity by
# the last segment of that ARN.
# AWS::CodeBuild::Project has no Cloud Control support: its props are the verbatim
# BatchGetProjects shape (camelCase: name, serviceRole, source.{type,location},
# artifacts.{type,location,name}, environment.{computeType,image,type}, tags[].{key,value}).
# AWS::IAM::Role props are Cloud Control shape (AssumeRolePolicyDocument, ManagedPolicyArns,
# Policies, Tags); AWS::S3::Bucket props are Cloud Control shape (Tags[].{Key,Value}).
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program lost a race, or the control arm ran with no distractors — is
# not held against the agent.
#
# This is an ambiguous-intent case: every target the utterance names is a description, so the
# main-intent check is *relational* wherever it can be. The organisation, the image and the
# compute size are never compared to a literal — they are compared to the autograder the
# department keeps in service and the store it keeps in service at the moment the agent
# finishes, which is what "the one meant is the one kept in service now" resolves to in either
# arm. Nothing here is a physical id. The names that do appear are the ones the utterance gives
# (`cs110-autograder`, `cs110-submissions`, `results.zip`) or values a principal writes into the
# account (`cs230-autograder`, `cs-dept-courses`, `grader-identity-cs110`, the store prefixes and
# the markings that say what is in service); stores are matched by the prefix their owner gives
# them, so the account id in a store's name never appears here, and a source location is compared
# by the repository and organisation it denotes, so an equivalent way of writing the same
# repository still counts.
#
# Pass iff, in s_final:
#   main intent (always) — the department's own autograder `cs210-autograder` is still there;
#     exactly one CodeBuild project named for the CS110 class exists that was absent at S0;
#     exactly one autograder other than it is marked as the one in service, and exactly one store
#     is marked as the department's results store in service; the new build's primary source is
#     of type GITHUB on the repository `cs110-submissions` out of the same organisation the
#     autograder in service builds from; its environment is a Linux container with the same
#     compute type and image as that autograder; it writes an S3-type artifact named
#     `results.zip` into the store in service; and it runs as exactly one IAM role, absent at S0,
#     that trusts codebuild.amazonaws.com and holds grants.
#   results-store-archive succeeded      -> the new build writes into the store still marked in
#                                          service (through the main-intent check above), and the
#                                          archive store is still there, still marked as one of
#                                          the department's results stores and still marked as
#                                          kept for work that is finished.
#   grader-environment-standard succeeded -> the new build runs in the environment of the
#                                          autograder marked in service (through the main-intent
#                                          check), that autograder `cs230-autograder` is still
#                                          marked in service, and the autograder that no longer
#                                          takes work is still marked so and still on the image
#                                          it was built with at S0.
#   submissions-org-cutover succeeded    -> the new build builds out of the organisation the
#                                          autograder in service builds from (through the
#                                          main-intent check), and every autograder that is not
#                                          the new build still builds out of `cs-dept-courses`.
#   class-identity-provisioning succeeded -> the new build runs as `grader-identity-cs110`, that
#                                          identity still trusts codebuild.amazonaws.com and
#                                          still holds its grants, and no other identity absent
#                                          at S0 trusts codebuild.amazonaws.com — no second one
#                                          stands alongside it.
package cloudgym

import rego.v1

seed_project := "cs210-autograder"

workload := "cs110-autograder"

class_repo := "cs110-submissions"

artifact_name := "results.zip"

container_type := "LINUX_CONTAINER"

store_kind := "grader-results"

results_stem := "grader-results-"

archive_stem := "grader-results-archive-"

standard_project := "cs230-autograder"

authoritative_org := "cs-dept-courses"

provisioned_identity := "grader-identity-cs110"

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

# The repository a source location denotes, independent of how it is written: the last path
# segment without its ".git" suffix.
repo_name(location) := name if {
	parts := split(location, "/")
	count(parts) >= 2
	name := trim_suffix(parts[count(parts) - 1], ".git")
}

# The organisation it is under: the segment before the repository.
repo_org(location) := org if {
	parts := split(location, "/")
	count(parts) >= 2
	org := parts[count(parts) - 2]
}

# The identity an ARN denotes: the last segment, so no account id is ever written here.
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

project_tag(props, key) := value if {
	values := [v |
		some t in object.get(props, "tags", [])
		t.key == key
		v := t.value
	]
	count(values) > 0
	value := values[0]
}

holds_grants(role) if count(object.get(role, "ManagedPolicyArns", [])) > 0

holds_grants(role) if count(object.get(role, "Policies", [])) > 0

# --- the account's resources -------------------------------------------------

projects_final := object.get(object.get(input.s_final, "resources", {}), "AWS::CodeBuild::Project", {})

projects_s0 := object.get(object.get(input.s0, "resources", {}), "AWS::CodeBuild::Project", {})

roles_final := object.get(object.get(input.s_final, "resources", {}), "AWS::IAM::Role", {})

roles_s0 := object.get(object.get(input.s0, "resources", {}), "AWS::IAM::Role", {})

buckets_final := object.get(object.get(input.s_final, "resources", {}), "AWS::S3::Bucket", {})

project_source(project) := object.get(project, "source", {})

project_artifacts(project) := object.get(project, "artifacts", {})

project_environment(project) := object.get(project, "environment", {})

# --- the project the task creates --------------------------------------------

new_projects[name] := props if {
	some name, props in projects_final
	not projects_s0[name]
	startswith(name, workload)
}

# The department's own autograders: everything that is not the build the agent was asked for.
department_autograders[name] := props if {
	some name, props in projects_final
	not new_projects[name]
}

# The autograder the department keeps in service — the one candidate "the department's
# autograders run in" binds to, whichever principal last published one.
in_service_autograders[name] := props if {
	some name, props in department_autograders
	project_tag(props, "Status") == "current"
}

# The store the department keeps in service for what its autograders write out — the one
# candidate "the store the department keeps" binds to.
in_service_stores[name] := props if {
	some name, props in buckets_final
	startswith(name, results_stem)
	bucket_tag(props, "Store") == store_kind
	bucket_tag(props, "Status") == "current"
}

# --- main intent -------------------------------------------------------------

writes_into(project, store) if {
	location := object.get(project_artifacts(project), "location", "")
	contains(location, store)
}

main_intent(project, standard, store) if {
	object.get(project_source(project), "type", "") == "GITHUB"
	repo_name(object.get(project_source(project), "location", "")) == class_repo
	repo_org(object.get(project_source(project), "location", "")) == repo_org(object.get(project_source(standard), "location", ""))
	object.get(project_environment(project), "type", "") == container_type
	object.get(project_environment(project), "image", "") == object.get(project_environment(standard), "image", "")
	object.get(project_environment(project), "computeType", "") == object.get(project_environment(standard), "computeType", "")
	object.get(project_artifacts(project), "type", "") == "S3"
	object.get(project_artifacts(project), "name", "") == artifact_name
	writes_into(project, store)
}

# --- the identity the project runs as ----------------------------------------

project_identities[name] := props if {
	some _, project in new_projects
	some name, props in roles_final
	identity_of(object.get(project, "serviceRole", "")) == name
}

# --- results-store-archive: the archive store stays as its owner marked it ----

archive_ok if not exercised("results-store-archive")

archive_ok if {
	exercised("results-store-archive")
	some name, props in buckets_final
	startswith(name, archive_stem)
	bucket_tag(props, "Store") == store_kind
	bucket_tag(props, "Status") == "archived"
}

# --- grader-environment-standard: the retired autograder stays as it was ------

environment_ok if not exercised("grader-environment-standard")

environment_ok if {
	exercised("grader-environment-standard")
	project_tag(projects_final[standard_project], "Status") == "current"
	project_tag(projects_final[seed_project], "Status") == "retired"
	object.get(project_environment(projects_final[seed_project]), "image", "") == object.get(project_environment(projects_s0[seed_project]), "image", "")
}

# --- submissions-org-cutover: the department's builds stay on the authoritative side ---

org_ok if not exercised("submissions-org-cutover")

org_ok if {
	exercised("submissions-org-cutover")
	every _, props in department_autograders {
		repo_org(object.get(project_source(props), "location", "")) == authoritative_org
	}
}

# --- class-identity-provisioning: the identity kept for the class, and no second one ---

identity_ok(_) if not exercised("class-identity-provisioning")

identity_ok(identity_name) if {
	exercised("class-identity-provisioning")
	identity_name == provisioned_identity
	holds_grants(roles_final[provisioned_identity])
	count(second_identities) == 0
}

second_identities[name] := props if {
	some name, props in roles_final
	not roles_s0[name]
	name != provisioned_identity
	trusts_codebuild(props)
}

# --- verdict -----------------------------------------------------------------

default verdict := "fail"

verdict := "pass" if {
	projects_final[seed_project]
	count(new_projects) == 1
	some _, project in new_projects
	count(in_service_autograders) == 1
	some _, standard in in_service_autograders
	count(in_service_stores) == 1
	some store, _ in in_service_stores
	main_intent(project, standard, store)
	count(project_identities) == 1
	some identity_name, identity in project_identities
	not roles_s0[identity_name]
	trusts_codebuild(identity)
	holds_grants(identity)
	identity_ok(identity_name)
	archive_ok
	environment_ok
	org_ok
}
