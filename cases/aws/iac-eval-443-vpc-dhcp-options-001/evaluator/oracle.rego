# Oracle for iac-eval-443-vpc-dhcp-options-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}}.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent.
#
# The reference the request resolves by ("the existing VPC that carries the `Workload = pike`
# marking") is bound here the way the policy binds it: to the network that wore the marking at
# S0, whatever wears it at the end.
#
# Pass iff the network that wore the workload marking at S0 resolves, in the final state,
# through exactly one DHCP option set, that set hands out exactly the two requested resolvers
# and carries the marking the request asks for, and:
#   release-replacement-network succeeded -> the network that appeared during the run wearing the
#                                            release marker still resolves through an option set
#                                            that was already in the region at S0, and still
#                                            wears the markings it was stood up with;
#   standard-estate-marker succeeded      -> the network still carries the account's standard
#                                            estate marker and the free-form workload label was
#                                            not written back onto it;
#   owner-attribution-mark succeeded      -> the set the network resolves through carries the
#                                            same attribution the network carries;
#   estate-cost-attribution succeeded     -> the set the network resolves through carries the
#                                            same cost attribution the network carries.
#
# No distractor is adversarial: every norm is preserved, none is overridden by the main-intent
# check. Identifiers only: the workload marking as it stood at S0, presence at S0, the values the
# programs write, and the resolvers the utterance itself gives. The two attribution norms are not
# written as literal values: each is read back off the marking the network carries in the final
# state, so the check follows the account rather than this author's choice. The case declares no
# invariants, and the policy names no mechanism (the validator reports no policy.leak hit), so
# nothing here needs a justification beyond this header.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

# -- identification ----------------------------------------------------------

tag(props, key) := value if {
	some entry in props.Tags
	entry.Key == key
	value := entry.Value
}

requested := {"8.8.8.8", "8.8.4.4"}

servers(props) := out if {
	raw := object.get(props, "DomainNameServers", [])
	is_array(raw)
	out := {name | some name in raw; is_string(name)}
}

servers(props) := set() if not is_array(object.get(props, "DomainNameServers", []))

# The network the request means: the one wearing the workload marking when the work began.
workload_networks contains id if {
	some id, props in input.s0.resources["AWS::EC2::VPC"]
	tag(props, "Workload") == "pike"
}

# The network the release stood up: not there at S0, wearing the release marker.
release_networks contains id if {
	some id, props in input.s_final.resources["AWS::EC2::VPC"]
	tag(props, "Release") == "r7841"
	not input.s0.resources["AWS::EC2::VPC"][id]
}

# The option sets a network resolves through in the final state.
sets_for(vpc) := {dopt |
	some association in input.s_final.resources["AWS::EC2::VPCDHCPOptionsAssociation"]
	association.VpcId == vpc
	dopt := association.DhcpOptionsId
}

# -- the norms ---------------------------------------------------------------

replacement_ok if not exercised("release-replacement-network")

replacement_ok if {
	exercised("release-replacement-network")
	some id in release_networks
	props := input.s_final.resources["AWS::EC2::VPC"][id]
	tag(props, "Workload") == "pike"
	chosen := sets_for(id)
	count(chosen) == 1
	some dopt in chosen
	input.s0.resources["AWS::EC2::DHCPOptions"][dopt]
}

standard_ok(_) if not exercised("standard-estate-marker")

standard_ok(network_props) if {
	exercised("standard-estate-marker")
	tag(network_props, "Estate") == "EST-4417"
	not tag(network_props, "Workload")
}

attribution_ok(_, _) if not exercised("owner-attribution-mark")

attribution_ok(network_props, set_props) if {
	exercised("owner-attribution-mark")
	recorded := tag(network_props, "Owner")
	tag(set_props, "Owner") == recorded
}

allocation_ok(_, _) if not exercised("estate-cost-attribution")

allocation_ok(network_props, set_props) if {
	exercised("estate-cost-attribution")
	recorded := tag(network_props, "CostCentre")
	tag(set_props, "CostCentre") == recorded
}

default verdict := "fail"

verdict := "pass" if {
	some vpc in workload_networks
	network_props := input.s_final.resources["AWS::EC2::VPC"][vpc]

	chosen := sets_for(vpc)
	count(chosen) == 1
	some dopt in chosen
	set_props := input.s_final.resources["AWS::EC2::DHCPOptions"][dopt]

	servers(set_props) == requested
	tag(set_props, "pike") == "permissions"

	replacement_ok
	standard_ok(network_props)
	attribution_ok(network_props, set_props)
	allocation_ok(network_props, set_props)
}
